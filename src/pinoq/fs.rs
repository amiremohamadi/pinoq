use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{prelude::*, Cursor, SeekFrom};
use std::time::{Duration, SystemTime};

use crate::pinoq::{
    config::Config,
    error::{PinoqError, Result},
    filefmt::{
        from_encrypted_block, to_encrypted_block, Aspect, Block, Dir, EncryptedBlock, INode,
        PinoqSerialize, SuperBlock, BLOCK_SIZE,
    },
};

use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{
    FileAttr, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen,
    ReplyWrite, Request, TimeOrNow,
};
use memmap::MmapMut;

const TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct FDManager {
    file_decs: HashMap<u64, FileDescriptor>,
}

impl FDManager {
    pub fn get(&self, fd: u64) -> Option<&FileDescriptor> {
        self.file_decs.get(&fd)
    }

    pub fn insert(&mut self, fd: u64, val: FileDescriptor) {
        self.file_decs.insert(fd, val);
    }
}

#[derive(Debug, Default)]
struct FileDescriptor {
    next_block: Option<u32>,
}

pub struct PinoqFs {
    config: Config,
    mmap: MmapMut,
    sblock: SuperBlock,
    aspect: Aspect,
    // should be constructed only after decrypting all the aspects
    block_map: BitVec<u8, Lsb0>,
    fd_manager: FDManager,
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
            fd_manager: FDManager::default(),
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

    /// make sure to store the current aspect after calling this function
    /// as it only modifies the aspect's block_map in-memory
    fn allocate_block(&mut self) -> Result<usize> {
        let index = self
            .find_free_block()
            .ok_or_else(|| PinoqError::NoEnoughSpace)?;
        self.block_map.set(index, true);
        self.aspect.block_map.set(index, true);
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

    fn write(&mut self, ino: u64, fh: u64, data: &[u8]) -> Result<usize> {
        const RAW_BLK_SIZE: usize = BLOCK_SIZE - 32;

        let mut next_block = self.allocate_block()?;

        let fd = match self.fd_manager.get(fh) {
            Some(n) => n,
            None => {
                self.fd_manager
                    .insert(fh, FileDescriptor { next_block: None });
                &FileDescriptor { next_block: None }
            }
        };
        match fd.next_block {
            Some(n) => {
                let mut b = self.get_from_block::<Block>(n as _)?;
                b.next_block = next_block as _;
                self.store_to_block(&b, n)?;
            }
            None => {
                let mut inode = self.get_from_block::<INode>(ino as _)?;
                inode.data_block = next_block as _;
                self.store_to_block(&inode, ino as _)?;
            }
        }

        let mut chunks = data.chunks(RAW_BLK_SIZE).peekable();
        while let Some(chunk) = chunks.next() {
            let current_block = next_block;
            next_block = match chunks.peek() {
                None => {
                    self.fd_manager.insert(
                        fh,
                        FileDescriptor {
                            next_block: Some(next_block as _),
                        },
                    );
                    0xFFFFFFFF
                }
                Some(_) => self.allocate_block()?,
            };

            let blk = Block {
                data: chunk.to_vec(),
                next_block: next_block as _,
            };
            self.store_to_block(&blk, current_block as _)?;
        }

        self.store_aspect(self.aspect.clone(), self.config.current.aspect)?;
        Ok(data.len())
    }

    fn read(&mut self, ino: u64, fh: u64, _offset: u64) -> Result<Vec<u8>> {
        let fd = self.fd_manager.get(fh).unwrap();
        let next_block = match fd.next_block {
            Some(n) => n,
            None => {
                let inode = self.get_from_block::<INode>(ino as _)?;
                inode.data_block
            }
        };

        if next_block == 0xFFFFFFFF {
            return Ok(vec![]);
        }

        let blk = self.get_from_block::<Block>(next_block)?;
        self.fd_manager.insert(
            fh,
            FileDescriptor {
                next_block: Some(blk.next_block as _),
            },
        );

        Ok(blk.data)
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
            // n - 1 // indices start from 1 in fuse
            n
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

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // TODO: not implemented
        // just return the attrs for now to supress the warnings
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

    fn write(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        _offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let inode = self.convert_inode_index(inode);
        // TODO: consider offset
        match self.write(inode, fh, data) {
            Ok(n) => reply.written(n as _),
            Err(e) => reply.error(e.to_code()),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let inode = self.convert_inode_index(inode);
        match self.read(inode, fh, offset as _) {
            Ok(d) => {
                reply.data(&d);
            }
            Err(e) => {
                reply.error(e.to_code());
            }
        }
    }

    fn open(&mut self, _req: &Request, inode: u64, _flags: i32, reply: ReplyOpen) {
        let inode = self.convert_inode_index(inode);
        self.fd_manager
            .insert(inode, FileDescriptor { next_block: None });
        reply.opened(inode, fuser::consts::FOPEN_DIRECT_IO);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pinoq::config::*;
    use crate::pinoq::*;
    use tempfile::tempdir;

    #[test]
    fn test_write_data_blocks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("my-volume.pnoq");
        let path = path.to_str().unwrap();
        let password = "testpass".to_string();

        mkfs(2, 1024, path, "password").unwrap();

        let config = Config {
            disk: path.to_string(),
            mount: "".to_string(),
            current: Current {
                aspect: 1,
                password: password.clone(),
            },
        };

        let data = vec![69; BLOCK_SIZE];
        let mut fs = PinoqFs::new(config).unwrap();
        fs.init_root().unwrap();

        fs.create_entry(0, OsStr::new("file.txt")).unwrap();

        fs.fd_manager.insert(0, FileDescriptor { next_block: None });
        fs.write(2, 0, &data).unwrap();

        let b1 = fs.get_from_block::<Block>(3).unwrap();
        let b2 = fs.get_from_block::<Block>(4).unwrap();
        assert!(b1.data.iter().all(|&x| x == 69));
        assert!(b2.data.iter().all(|&x| x == 69));
        assert_eq!(b1.data.len() + b2.data.len(), data.len());
        assert_eq!(b1.next_block, 4);
    }
}
