use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::UNIX_EPOCH;

use anyhow::Result;
use bitvec::{order::Lsb0, vec::BitVec};
use fuser::{FileAttr, FileType};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};

const IV_LEN: usize = 16;
const KEY_LEN: usize = 32;
const MAGIC: u32 = 0x504E4F51u32;
pub const BLOCK_SIZE: usize = 1 << 10;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Key([u8; KEY_LEN]);

fn random_key() -> Key {
    let mut k = [0; KEY_LEN];
    rand::fill(&mut k[..]);
    Key(k)
}

fn decrypt(encrypted_data: &[u8], key: &Key, password: &str) -> Result<Vec<u8>> {
    let mut iv = password.as_bytes().to_vec();
    iv.resize(IV_LEN, 0);

    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key.0, Some(&iv)).unwrap();

    let block_size = cipher.block_size();
    let mut decrypted_data = vec![0; encrypted_data.len() + block_size];
    let count = decrypter
        .update(encrypted_data, &mut decrypted_data)
        .unwrap();
    let rest = decrypter.finalize(&mut decrypted_data[count..]).unwrap();
    decrypted_data.truncate(count + rest);

    Ok(decrypted_data)
}

fn encrypt(data: &[u8], key: &Vec<u8>, password: &Vec<u8>) -> Result<Vec<u8>> {
    let mut iv = password.clone();
    iv.resize(IV_LEN, 0);

    let cipher = Cipher::aes_256_cbc();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv)).unwrap();

    let block_size = cipher.block_size();
    let mut encrypted_data = vec![0; data.len() + block_size];
    let count = encrypter.update(data, &mut encrypted_data).unwrap();
    let rest = encrypter.finalize(&mut encrypted_data[count..]).unwrap();
    encrypted_data.truncate(count + rest);

    Ok(encrypted_data)
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

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedAspect {
    // to encrypt/decrypt the aspect
    pub key: Key,
    pub encrypted_data: Vec<u8>,
}

impl EncryptedAspect {
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

    pub fn size_of(n: u32) -> usize {
        // FIXME: calculate the length instead of using hardcoded numbers
        ((n as usize) / 8) + 88
    }
}

#[derive(Debug, Default)]
pub struct Aspect {
    // to encrypt/decrypt the blocks
    pub key: Key,
    pub block_map: BitVec<u8, Lsb0>,
}

impl Aspect {
    pub fn new(blocks: u32) -> Self {
        Self {
            key: random_key(),
            block_map: BitVec::repeat(false, blocks as _),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];

        buf.extend_from_slice(&self.key.0);
        buf.extend_from_slice(&self.block_map.as_raw_slice());

        Ok(buf)
    }

    pub fn serialize_into<W>(&mut self, mut w: W) -> Result<()>
    where
        W: Write,
    {
        Ok(w.write_all(self.block_map.as_raw_slice())?)
    }

    pub fn from_encrypted_aspect(ea: EncryptedAspect, password: &str) -> Result<Self> {
        let raw_data = decrypt(&ea.encrypted_data, &ea.key, password)?;

        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&raw_data[..KEY_LEN]);

        Ok(Self {
            key: Key(k), // FIXME
            block_map: BitVec::<u8, Lsb0>::from_slice(&raw_data[KEY_LEN..]),
        })
    }

    pub fn to_encrypted_aspect(&self, password: &str) -> Result<EncryptedAspect> {
        let key = random_key();
        // TODO: currently we're using password as IV (init vector)
        // should use PBKDF in the future and fill the IV with random data
        let encoded = self.serialize()?;
        // make sure password contains at most IV_LEN bytes
        let encrypted_data = encrypt(
            encoded.as_slice(),
            &key.0.to_vec(),
            &password.as_bytes().to_vec(),
        )?;

        Ok(EncryptedAspect {
            key,
            encrypted_data,
        })
    }
}

// TODO: probably better to keep track of blocks using
// a block bitmap in the aspect header?
#[derive(Debug)]
pub struct Block {
    // 0xFFFFFFFF, in case this is the last block
    pub next_block: u32,
    pub data: [u8; BLOCK_SIZE],
}

impl Block {
    pub fn serialize_into<W>(&mut self, mut w: W) -> Result<()>
    where
        W: Write,
    {
        w.write_all(&self.next_block.to_be_bytes())?;
        Ok(w.write_all(&self.data)?)
    }

    pub fn deserialize_from<R>(mut r: R) -> Result<Self>
    where
        R: Read,
    {
        let mut next_block = [0u8; 4];
        let mut data = [0u8; BLOCK_SIZE];

        r.read_exact(&mut next_block)?;
        r.read_exact(&mut data)?;

        Ok(Self {
            next_block: u32::from_be_bytes(next_block),
            data,
        })
    }
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
    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFDIR != 0
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
