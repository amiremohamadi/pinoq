use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::time::UNIX_EPOCH;

use crate::pinoq::encryption::*;
use crate::pinoq::error::Result;

use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{FileAttr, FileType};
use serde::{Deserialize, Serialize};

pub(crate) const BLOCK_SIZE: usize = 1 << 10;
const MAGIC: u32 = 0x504E4F51u32;

pub trait PinoqSerialize: Sized {
    fn serialize_into<W: Write>(&self, w: W) -> Result<()>;
    fn deserialize_from<R: Read>(r: R) -> Result<Self>;
}

pub fn to_encrypted_block<T>(t: &T, key: &Key, n: u32) -> Result<EncryptedBlock>
where
    T: PinoqSerialize,
{
    let mut buf = Cursor::new(Vec::new());
    t.serialize_into(&mut buf)?;

    let iv = IV::from_bytes(&n.to_be_bytes());
    let enc_buf = encrypt(&buf.into_inner(), key, &iv);

    Ok(EncryptedBlock(enc_buf))
}

pub fn from_encrypted_block<T>(eb: &EncryptedBlock, key: &Key, n: u32) -> Result<T>
where
    T: PinoqSerialize,
{
    let iv = IV::from_bytes(&n.to_be_bytes());
    let buf = decrypt(&eb.0, key, &iv);
    let buf = Cursor::new(buf);
    T::deserialize_from(buf)
}

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
}

impl PinoqSerialize for SuperBlock {
    fn serialize_into<W>(&self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedAspect {
    // to encrypt/decrypt the aspect
    pub key: Key,
    pub encrypted_data: Vec<u8>,
}

impl EncryptedAspect {
    pub fn size_of(n: u32) -> usize {
        // FIXME: calculate the length instead of using hardcoded numbers
        ((n as usize) / 8) + 88
    }
}

impl PinoqSerialize for EncryptedAspect {
    fn serialize_into<W>(&self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Aspect {
    // to encrypt/decrypt the blocks
    pub key: Key,
    pub root_block: u32,
    pub block_map: BitVec<u8, Lsb0>,
}

impl Aspect {
    pub fn new(blocks: u32) -> Self {
        Self {
            key: random_key(),
            root_block: 0xFFFFFFFF, // we consider 0xFFFFFFFF as uninitialized
            block_map: BitVec::repeat(false, blocks as _),
        }
    }

    pub fn has_root_block(&self) -> bool {
        self.root_block != 0xFFFFFFFF
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.key.0);
        buf.extend_from_slice(&self.root_block.to_be_bytes());
        buf.extend_from_slice(&self.block_map.as_raw_slice());

        buf
    }

    pub fn from_encrypted_aspect(ea: EncryptedAspect, password: &str) -> Result<Self> {
        let iv = IV::from_bytes(password.as_bytes());
        let decrypted = decrypt(&ea.encrypted_data, &ea.key, &iv);

        let mut kbuf = [0u8; KEY_LEN];
        kbuf.copy_from_slice(&decrypted[..KEY_LEN]);

        const BUF_LEN: usize = 4;
        let mut bbuf = [0u8; BUF_LEN];
        bbuf.copy_from_slice(&decrypted[KEY_LEN..KEY_LEN + BUF_LEN]);

        Ok(Self {
            key: Key(kbuf), // FIXME
            root_block: u32::from_be_bytes(bbuf),
            block_map: BitVec::<u8, Lsb0>::from_slice(&decrypted[KEY_LEN + BUF_LEN..]),
        })
    }

    pub fn to_encrypted_aspect(&self, password: &str) -> EncryptedAspect {
        let key = random_key();
        // TODO: currently we're using password as IV (init vector)
        // should use PBKDF in the future and fill the IV with random data
        let encoded = self.serialize();
        let iv = IV::from_bytes(password.as_bytes());
        let encrypted_data = encrypt(encoded.as_slice(), &key, &iv);

        EncryptedAspect {
            key,
            encrypted_data,
        }
    }
}

// TODO: must raise an error in case the inner data length is larger than BLOCK_SIZE
// otherwise we'll have overlapping blocks which leads to data corruption
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedBlock(pub Vec<u8>);

impl PinoqSerialize for EncryptedBlock {
    fn serialize_into<W>(&self, w: W) -> Result<()>
    where
        W: Write,
    {
        // bincode: 4 bytes for len + data
        assert!(
            self.0.len() <= BLOCK_SIZE - std::mem::size_of::<usize>(),
            "block overflow"
        );
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct Block {
    // 0xFFFFFFFF, in case this is the last block
    pub next_block: u32,
    pub data: Vec<u8>,
}

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
    pub fn new(mode: libc::mode_t, uid: u32, gid: u32) -> Self {
        Self {
            mode,
            uid,
            gid,
            ..Default::default()
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFDIR != 0
    }

    pub fn as_attr(&self, n: u32) -> FileAttr {
        let kind = match self.mode & libc::S_IFDIR {
            0 => FileType::RegularFile,
            _ => FileType::Directory,
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

impl PinoqSerialize for INode {
    fn serialize_into<W>(&self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Dir {
    pub entries: BTreeMap<String, u32>,
}

impl PinoqSerialize for Dir {
    fn serialize_into<W>(&self, w: W) -> Result<()>
    where
        W: Write,
    {
        bincode::serialize_into(w, self).map_err(|e| e.into())
    }

    fn deserialize_from<R>(r: R) -> Result<Self>
    where
        R: Read,
    {
        bincode::deserialize_from(r).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_block() {
        let mut dir = Dir::default();
        dir.entries.insert("name".to_string(), 123);

        let key = Key([1; KEY_LEN]);
        let enc_block = to_encrypted_block(&dir, &key, 69).unwrap();

        let dir = from_encrypted_block::<Dir>(&enc_block, &key, 69).unwrap();
        assert_eq!(dir.entries.get("name"), Some(&123));

        // invalid block number
        let result = from_encrypted_block::<Dir>(&enc_block, &key, 88);
        assert!(result.is_err());
    }
}
