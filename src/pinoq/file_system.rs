use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{prelude::*, Cursor, SeekFrom};
use std::time::Duration;

use crate::pinoq::{config::Config, Aspect, Block, Dir, EncryptedAspect, INode, SuperBlock};

use anyhow::Result;
use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{Filesystem, ReplyAttr, ReplyCreate, ReplyDirectory, ReplyEntry, Request};
use memmap::MmapMut;

const TTL: Duration = Duration::from_secs(1);

pub struct PinoqFs {
    config: Config,
    mmap: MmapMut,
    sblock: SuperBlock,
    aspect: Option<Aspect>,
    // should be constructed only after decrypting all the aspects
    block_map: BitVec<u8, Lsb0>,
}

impl PinoqFs {
    pub fn new(config: Config) -> Result<Self> {
        let disk = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.disk)?;
        let mmap = unsafe { MmapMut::map_mut(&disk)? };
        let mut cursor = Cursor::new(&mmap);

        let sblock = SuperBlock::deserialize_from(&mut cursor)?;
        let mut fs = PinoqFs {
            config,
            mmap,
            sblock,
            aspect: None,
            block_map: BitVec::new(),
        };
        fs.aspect = Some(fs.get_aspect(fs.config.current.aspect)?);
        fs.construct_block_map()?;
        fs.init_root()?;

        Ok(fs)
    }

    pub fn inspect(path: &str) -> Result<SuperBlock> {
        let mut disk = OpenOptions::new().read(true).open(path)?;
        SuperBlock::deserialize_from(&mut disk)
    }

    fn construct_block_map(&mut self) -> Result<()> {
        log::debug!("Constructing Block Map for {} Aspects", self.sblock.aspects);
        self.block_map = BitVec::repeat(false, self.sblock.blocks as _);
        for i in 0..self.sblock.aspects {
            let aspect = self.get_aspect(i)?;
            self.block_map |= aspect.block_map;
        }
        Ok(())
    }

    fn get_current_aspect(&self) -> Aspect {
        self.aspect.as_ref().unwrap().clone()
    }

    fn get_current_aspect_mut(&mut self) -> &mut Aspect {
        self.aspect.as_mut().unwrap()
    }

    fn get_aspect(&self, n: u32) -> Result<Aspect> {
        let offset = self.aspect_offset(n);

        let mut cursor = Cursor::new(&self.mmap);
        cursor.seek(SeekFrom::Start(offset as _))?;

        let encrypted = EncryptedAspect::deserialize_from(cursor)?;
        Aspect::from_encrypted_aspect(encrypted, "password")
    }

    fn allocate_block(&mut self) -> Result<usize> {
        let index = self
            .find_free_block()
            .ok_or_else(|| anyhow::anyhow!("No space left"))?;
        self.block_map.set(index, true);
        Ok(index)
    }

    fn find_free_block(&self) -> Option<usize> {
        self.block_map.iter().position(|x| !*x)
    }

    // TODO: move to mkfs
    fn init_root(&mut self) -> Result<()> {
        log::debug!("Initializing Root Directory");

        let aspect = self.get_current_aspect();
        if aspect.has_root_block() {
            log::debug!("Already have a root");
            return Ok(());
        }

        // TODO: allocate random blocks
        let root_block_index = self.allocate_block()?;
        let data_block_index = self.allocate_block()?;

        self.get_current_aspect_mut().root_block = root_block_index as _;
        self.get_current_aspect_mut()
            .block_map
            .set(root_block_index as _, true);
        self.get_current_aspect_mut()
            .block_map
            .set(data_block_index as _, true);

        let root_node = INode {
            mode: libc::S_IFDIR,
            block_size: crate::pinoq::BLOCK_SIZE as _,
            data_block: data_block_index as _,
            uid: self.sblock.uid,
            gid: self.sblock.gid,
            ..Default::default()
        };
        let directory = Dir::default();
        self.save_inode(root_node, root_block_index as _)?;
        self.save_dir(&directory, data_block_index as _)?;
        self.save_aspect(&self.get_current_aspect(), self.config.current.aspect)
    }

    fn save_dir(&mut self, dir: &Dir, n: u32) -> Result<()> {
        let offset = self.block_offset(n);

        let mut cursor = Cursor::new(self.mmap.as_mut());
        cursor.seek(SeekFrom::Start(offset as _))?;

        dir.serialize_into(&mut cursor)
    }

    fn save_inode(&mut self, inode: INode, n: u32) -> Result<()> {
        let offset = self.block_offset(n);

        let mut cursor = Cursor::new(self.mmap.as_mut());
        cursor.seek(SeekFrom::Start(offset as _))?;

        inode.serialize_into(&mut cursor)
    }

    fn save_aspect(&mut self, aspect: &Aspect, n: u32) -> Result<()> {
        let offset = self.aspect_offset(n);

        let mut cursor = Cursor::new(self.mmap.as_mut());
        cursor.seek(SeekFrom::Start(offset as _))?;

        let encrypted = aspect.to_encrypted_aspect(&self.config.current.password)?;
        encrypted.serialize_into(&mut cursor)
    }

    fn get_inode_from_block(&self, n: u32) -> Result<INode> {
        log::debug!("Getting Inode From Block {}", n);

        let mut cursor = Cursor::new(&self.mmap);
        cursor.seek(SeekFrom::Start(self.block_offset(n) as _))?;

        INode::deserialize_from(cursor)
    }

    fn get_dir_from_inode(&self, n: u32) -> Result<Dir> {
        log::debug!("Getting Directory From Inode {}", n);

        let node = self.get_inode_from_block(n)?;
        if !node.is_dir() {
            return Err(anyhow::anyhow!("No such directory"));
        }

        let mut cursor = Cursor::new(&self.mmap);
        cursor.seek(SeekFrom::Start(self.block_offset(node.data_block) as _))?;

        Dir::deserialize_from(cursor)
    }

    /// fuse returns `1` for root inode
    /// we need to convert that to the aspect's specific root inode
    fn convert_inode_index(&self, n: u64) -> u64 {
        if n == 1 {
            self.get_current_aspect().root_block as _
        } else {
            n - 1 // indices start from 1 in fuse
        }
    }

    fn block_offset(&self, n: u32) -> usize {
        std::mem::size_of::<SuperBlock>()
            + EncryptedAspect::size_of(self.sblock.blocks) * (self.sblock.aspects as usize)
            + std::mem::size_of::<Block>() * (n as usize)
    }

    fn aspect_offset(&self, n: u32) -> usize {
        std::mem::size_of::<SuperBlock>()
            + EncryptedAspect::size_of(self.sblock.blocks) as usize * n as usize
    }
}

impl Filesystem for PinoqFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent = self.convert_inode_index(parent);
        match self.get_dir_from_inode(parent as _) {
            Ok(dir) => match dir.entries.get(name.to_str().unwrap()) {
                Some(&n) => match self.get_inode_from_block(n) {
                    Ok(node) => {
                        reply.entry(&TTL, &node.as_attr(n), 0);
                    }
                    Err(_) => reply.error(libc::ENOENT),
                },
                None => reply.error(libc::ENOENT),
            },
            Err(_) => reply.error(libc::ENOTDIR),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let ino = self.convert_inode_index(ino);
        match self.get_dir_from_inode(ino as _) {
            Ok(dir) => {
                let mut entries = vec![
                    (ino, fuser::FileType::Directory, ".".to_string()),
                    (1, fuser::FileType::Directory, "..".to_string()),
                ];

                for (name, ino) in dir.entries {
                    if let Ok(node) = self.get_inode_from_block(ino) {
                        let kind = match node.is_dir() {
                            true => fuser::FileType::Directory,
                            false => fuser::FileType::RegularFile,
                        };
                        entries.push((ino as _, kind, name));
                    }
                }

                for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                        break;
                    }
                }

                reply.ok();
            }
            Err(_) => reply.error(libc::ENOTDIR),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let ino = self.convert_inode_index(ino);
        match self.get_inode_from_block(ino as u32) {
            Ok(node) => reply.attr(&TTL, &node.as_attr(ino as _)),
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent = self.convert_inode_index(parent);

        let node = INode {
            mode: libc::S_IFREG,
            block_size: crate::pinoq::BLOCK_SIZE as _,
            data_block: 0xFFFFFFFF,
            uid: self.sblock.uid,
            gid: self.sblock.gid,
            ..Default::default()
        };
        let node_block_index = match self.allocate_block() {
            Ok(b) => b,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        match self.get_dir_from_inode(parent as _) {
            Ok(mut dir) => {
                let name = name.to_str().unwrap();
                dir.entries.insert(name.to_owned(), node_block_index as _);

                if let Err(_) = self.save_inode(node, node_block_index as _) {
                    reply.error(libc::ENOENT);
                    return;
                }

                let inode = match self.get_inode_from_block(parent as _) {
                    Ok(n) => n,
                    Err(_) => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };
                if let Err(_) = self.save_dir(&dir, inode.data_block) {
                    reply.error(libc::ENOENT);
                    return;
                }

                self.get_current_aspect_mut()
                    .block_map
                    .set(node_block_index, true);
                if let Err(_) =
                    self.save_aspect(&self.get_current_aspect(), self.config.current.aspect)
                {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }
}
