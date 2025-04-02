use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{prelude::*, Cursor, SeekFrom};
use std::time::Duration;

use crate::pinoq::{
    config::Config,
    error::{PinoqError, Result},
    filefmt::{
        from_encrypted_block, to_encrypted_block, Aspect, Dir, EncryptedBlock, INode,
        PinoqSerialize, SuperBlock, BLOCK_SIZE,
    },
};

use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{FileAttr, Filesystem, ReplyAttr, ReplyCreate, ReplyDirectory, ReplyEntry, Request};
use memmap::MmapMut;

const TTL: Duration = Duration::from_secs(1);

pub struct PinoqFs {
    config: Config,
    mmap: MmapMut,
    sblock: SuperBlock,
    aspect: Aspect,
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
        let offset = crate::pinoq::get_aspect_offset(sblock.blocks, config.current.aspect);
        let aspect = crate::pinoq::decrypt_aspect(&mut cursor, offset, &config.current.password)?;

        let mut fs = PinoqFs {
            config,
            mmap,
            sblock,
            aspect,
            block_map: BitVec::new(),
        };
        fs.construct_block_map()?;
        fs.init_root()?;

        Ok(fs)
    }

    pub fn inspect(path: &str) -> Result<SuperBlock> {
        let mut disk = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| PinoqError::IO(e))?;
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

    fn allocate_block(&mut self) -> Result<usize> {
        let index = self
            .find_free_block()
            .ok_or_else(|| PinoqError::NoEnoughSpace)?;
        self.block_map.set(index, true);
        Ok(index)
    }

    fn find_free_block(&self) -> Option<usize> {
        self.block_map.iter().position(|x| !*x)
    }

    // TODO: move to mkfs
    fn init_root(&mut self) -> Result<()> {
        log::debug!("Initializing Root Directory");

        if self.aspect.has_root_block() {
            log::debug!("Already have a root");
            return Ok(());
        }

        // TODO: allocate random blocks
        let root_block_index = self.allocate_block()?;
        let data_block_index = self.allocate_block()?;

        self.aspect.root_block = root_block_index as _;
        self.aspect.block_map.set(root_block_index as _, true);
        self.aspect.block_map.set(data_block_index as _, true);

        let mut root_node = INode::new(libc::S_IFDIR, self.sblock.uid, self.sblock.gid);
        root_node.block_size = BLOCK_SIZE as _;
        root_node.data_block = data_block_index as _;

        let directory = Dir::default();
        self.store_to_block(&root_node, root_block_index as _)?;
        self.store_to_block(&directory, data_block_index as _)?;
        self.store_aspect(self.aspect.clone(), self.config.current.aspect)
    }

    fn get_directory_content(&self, inode: u64) -> Result<BTreeMap<String, u32>> {
        Ok(self.get_from_block::<Dir>(inode as _)?.entries)
    }

    fn lookup_name(&self, inode: u64, name: &OsStr) -> Result<FileAttr> {
        let inode = self.get_from_block::<INode>(inode as _)?;
        if !inode.is_dir() {
            return Err(PinoqError::NoDirectory);
        }

        let entries = self.get_directory_content(inode.data_block as _)?;
        match entries.get(name.to_str().unwrap()) {
            Some(&n) => {
                let inode = self.get_from_block::<INode>(n)?;
                Ok(inode.as_attr(n))
            }
            None => Err(PinoqError::NoEntry),
        }
    }

    fn create_entry(&mut self, inode: u64, name: &OsStr) -> Result<FileAttr> {
        let mut node = INode::new(libc::S_IFREG, self.sblock.uid, self.sblock.gid);
        node.block_size = BLOCK_SIZE as _;
        node.data_block = 0xFFFFFFFF;

        let node_block_index = self.allocate_block()?;

        let parent = self.get_from_block::<INode>(inode as _)?;
        let mut dir = self.get_from_block::<Dir>(parent.data_block)?;

        let name = name.to_str().unwrap();
        dir.entries.insert(name.to_owned(), node_block_index as _);
        self.store_to_block(&parent, inode as _)?;
        self.store_to_block(&dir, parent.data_block as _)?;

        self.aspect.block_map.set(node_block_index, true);
        self.store_aspect(self.aspect.clone(), self.config.current.aspect)?;

        self.store_to_block(&node, node_block_index as _)?;
        Ok(node.as_attr(node_block_index as _))
    }

    fn list_entries(&self, inode: u64) -> Result<Vec<(u64, fuser::FileType, String)>> {
        let parent = self.get_from_block::<INode>(inode as _)?;
        let dir_entries = self.get_directory_content(parent.data_block as _)?;

        let mut entries = vec![
            (inode, fuser::FileType::Directory, ".".to_string()),
            (1, fuser::FileType::Directory, "..".to_string()),
        ];

        for (name, i) in dir_entries {
            if let Ok(node) = self.get_from_block::<INode>(i) {
                let kind = match node.is_dir() {
                    true => fuser::FileType::Directory,
                    false => fuser::FileType::RegularFile,
                };
                entries.push((i as _, kind, name));
            }
        }

        Ok(entries)
    }

    fn store_to_block<T>(&mut self, t: &T, n: u32) -> Result<()>
    where
        T: PinoqSerialize,
    {
        let offset = self.get_block_offset(n);

        let mut cursor = Cursor::new(self.mmap.as_mut());
        cursor
            .seek(SeekFrom::Start(offset as _))
            .map_err(|e| PinoqError::IO(e))?;

        let eb = to_encrypted_block(t, &self.aspect.key, n)?;
        eb.serialize_into(&mut cursor)
    }

    fn get_from_block<T>(&self, n: u32) -> Result<T>
    where
        T: PinoqSerialize,
    {
        let mut cursor = Cursor::new(&self.mmap);
        cursor
            .seek(SeekFrom::Start(self.get_block_offset(n) as _))
            .map_err(|e| PinoqError::IO(e))?;

        let eb = EncryptedBlock::deserialize_from(cursor)?;
        from_encrypted_block::<T>(&eb, &self.aspect.key, n)
    }

    /// fuse returns `1` for root inode
    /// we need to convert that to the aspect's specific root inode
    fn convert_inode_index(&self, n: u64) -> u64 {
        if n == 1 {
            self.aspect.root_block as _
        } else {
            n - 1 // indices start from 1 in fuse
        }
    }

    fn get_aspect(&self, n: u32) -> Result<Aspect> {
        let offset = self.get_aspect_offset(n);
        let cursor = Cursor::new(&self.mmap);
        // TODO: provide a way to ask for each aspect's password
        crate::pinoq::decrypt_aspect(cursor, offset, &self.config.current.password)
    }

    fn store_aspect(&mut self, aspect: Aspect, n: u32) -> Result<()> {
        let offset = self.get_aspect_offset(n);
        let cursor = Cursor::new(self.mmap.as_mut());
        // TODO: provide a way to ask for each aspect's password
        crate::pinoq::encrypt_aspect(cursor, offset, aspect, &self.config.current.password)
    }

    #[inline]
    fn get_block_offset(&self, n: u32) -> usize {
        crate::pinoq::get_block_offset(self.sblock.aspects, self.sblock.blocks, n)
    }

    #[inline]
    fn get_aspect_offset(&self, n: u32) -> usize {
        crate::pinoq::get_aspect_offset(self.sblock.blocks, n)
    }
}

impl Filesystem for PinoqFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent = self.convert_inode_index(parent);
        match self.lookup_name(parent, name) {
            Ok(attrs) => reply.entry(&TTL, &attrs, 0),
            Err(e) => reply.error(e.to_code()),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        inode: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let inode = self.convert_inode_index(inode);
        let entries = match self.list_entries(inode) {
            Ok(e) => e,
            Err(e) => {
                reply.error(e.to_code());
                return;
            }
        };

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }

        reply.ok();
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let ino = self.convert_inode_index(ino);
        match self.get_from_block::<INode>(ino as u32) {
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
        match self.create_entry(parent, name) {
            Ok(attrs) => reply.created(&TTL, &attrs, 0, 0, 0),
            Err(e) => reply.error(e.to_code()),
        }
    }
}
