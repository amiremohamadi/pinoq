use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{prelude::*, Cursor, Read, SeekFrom};
use std::time::UNIX_EPOCH;

use crate::pinoq::{Aspect, Block, Dir, INode, SuperBlock};

use anyhow::Result;
use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{FileAttr, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request};
use memmap::MmapMut;

pub struct Config {
    pub disk: String,
    pub current_aspect: u32,
}

pub struct PinoqFs {
    config: Config,
    mmap: MmapMut,
    sblock: SuperBlock,
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
            block_map: BitVec::new(),
        };
        fs.construct_block_map()?;
        fs.init_root()?;

        Ok(fs)
    }

    fn construct_block_map(&mut self) -> Result<()> {
        log::debug!("Constructing Block Map for {} Aspects", self.sblock.aspects);
        for i in 0..self.sblock.aspects {
            let aspect = self.get_aspect(i)?;
            self.block_map &= aspect.block_map;
        }
        Ok(())
    }

    fn get_aspect(&self, n: u32) -> Result<Aspect> {
        let offset =
            std::mem::size_of::<SuperBlock>() + (Aspect::size_of(self.sblock.blocks) * n as usize);

        let mut cursor = Cursor::new(&self.mmap);
        cursor.seek(SeekFrom::Start(offset as _))?;

        Aspect::deserialize_from(cursor, self.sblock.blocks)
    }

    // TODO: move to mkfs
    fn init_root(&mut self) -> Result<()> {
        let aspect = self.get_aspect(self.config.current_aspect)?;
        Ok(())
    }

    fn get_inode_from_block(&self, n: u32) -> Result<INode> {
        log::debug!("Getting Inode From Block {}", n);

        let mut cursor = Cursor::new(&self.mmap);
        cursor.seek(SeekFrom::Start(self.block_offset(n) as _))?;

        INode::deserialize_from(cursor)
    }

    fn get_dir_from_block(&self, n: u32) -> Result<Dir> {
        log::debug!("Getting Directory From Block");

        let offset = 0;

        Ok(Dir::default())
    }

    fn block_offset(&self, n: u32) -> usize {
        std::mem::size_of::<SuperBlock>()
            + Aspect::size_of(self.sblock.blocks) * (self.sblock.aspects as usize)
            + std::mem::size_of::<Block>() * (n as usize)
    }
}

impl Filesystem for PinoqFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {}

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        // match self.get_block(ino) {
        //     Ok(b) => {
        //         let node = INode::deserialize_from()
        //     }
        //     Err(_) => reply.error(libc::ENOENT),
        // }

        if ino != 1 {
            reply.error(libc::ENOENT);
            return;
        }

        let entries = vec![
            (1, fuser::FileType::Directory, "."),
            (1, fuser::FileType::Directory, ".."),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        reply.error(64);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        // match ino {
        //     1 => reply.attr(&std::time::Duration::from_secs(1), &HELLO_DIR_ATTR),
        //     2 => reply.attr(&std::time::Duration::from_secs(1), &HELLO_TXT_ATTR),
        //     _ => reply.error(64),
        // }
    }
}
