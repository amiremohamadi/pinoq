use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;

use anyhow::Result;
use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{FileAttr, FileType};
use serde::{Deserialize, Serialize};

const MAGIC: u32 = 0x504E4F51u32;
pub const BLOCK_SIZE: usize = 1 << 10;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SuperBlock {
    pub magic: u32,
    pub aspects: u32,
    pub blocks: u32,
    pub uid: u32,
    pub gid: u32,
}

impl SuperBlock {
    pub fn new(aspects: u32, blocks: u32, uid: u32, gid: u32) -> Self {
        Self {
            magic: MAGIC,
            aspects,
            blocks,
            uid,
            gid,
        }
    }

    pub fn serialize_into<W>(&mut self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    pub fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[derive(Debug, Default)]
pub struct Aspect {
    pub block_map: BitVec<u8, Lsb0>,
    // TODO: encrypt the fields using a RSA key
    // pub key: [u8; 32],
    // pub gen: [u8; 32],
}

impl Aspect {
    pub fn new(blocks: u32) -> Self {
        Self {
            block_map: BitVec::repeat(false, blocks as _),
        }
    }

    pub fn serialize_into<W>(&mut self, mut w: W) -> Result<()>
    where
        W: Write,
    {
        Ok(w.write_all(self.block_map.as_raw_slice())?)
    }

    pub fn deserialize_from<R>(mut r: R, n: u32) -> Result<Self>
    where
        R: Read,
    {
        let mut buf = vec![0u8; n as usize];
        r.read_exact(&mut buf)?;
        Ok(Self {
            block_map: BitVec::<u8, Lsb0>::from_slice(&buf),
        })
    }

    pub fn size_of(blocks: u32) -> usize {
        blocks as usize
        // (blocks / 8) as usize
    }
}

#[allow(dead_code)]
pub struct Block([u8; BLOCK_SIZE]);

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct INode {
    pub mode: libc::mode_t,
    pub size: usize,
    pub block_size: u32,
    pub uid: u32,
    pub gid: u32,
    pub data_block: u32,
}

impl INode {
    pub fn serialize_into<W>(&mut self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    pub fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }

    pub fn as_attr(&self, n: u32) -> FileAttr {
        let kind = if self.mode & libc::S_IFDIR != 0 {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino: n as _,
            size: self.size as _,
            blocks: 1, // TODO:
            // TODO: should we present the real datetime in deniable encryptions?
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm: 0o755, // TODO:
            nlink: 1,    // TODO:
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: self.block_size,
            flags: 0,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Dir {
    pub entries: BTreeMap<String, u32>,
}

impl Dir {
    pub fn serialize_into<W>(&mut self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    pub fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}
