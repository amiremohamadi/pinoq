use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::io::Read;
use std::time::UNIX_EPOCH;

use crate::pinoq::{Aspect, SuperBlock};

use anyhow::Result;
use fuser::{FileAttr, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request};
use memmap::MmapMut;

pub struct Config {
    pub disk: String,
    pub aspects: u32,
    pub block_size: u32,
}

pub struct PinoqFs {
    config: Config,
    mmap: MmapMut,
    current_aspect: usize,
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
        println!("superblock {:?}", sblock);

        Ok(PinoqFs {
            config,
            mmap,
            current_aspect: 0,
        })
    }
}

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: fuser::FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: fuser::FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

impl Filesystem for PinoqFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // if name.to_str() == Some("test.txt") {
        //     reply.entry(&std::time::Duration::from_secs(1), &HELLO_TXT_ATTR, 0);
        // } else {
        //     reply.error(64);
        // }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(64);
            return;
        }

        let entries = vec![
            (1, fuser::FileType::Directory, "."),
            (1, fuser::FileType::Directory, ".."),
            (2, fuser::FileType::RegularFile, "test.txt"),
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
        match ino {
            1 => reply.attr(&std::time::Duration::from_secs(1), &HELLO_DIR_ATTR),
            2 => reply.attr(&std::time::Duration::from_secs(1), &HELLO_TXT_ATTR),
            _ => reply.error(64),
        }
    }
}
