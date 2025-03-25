use std::io::{self, Read, Write};
use std::str::FromStr;

use anyhow::Result;
use serde::{Deserialize, Serialize};

const MAGIC: u32 = 0x504E4F51u32;

#[derive(Debug, Serialize, Deserialize)]
pub struct SuperBlock {
    pub magic: u32,
    pub aspects: u32,
    pub blocks: u32,
}

impl SuperBlock {
    pub fn new(aspects: u32, blocks: u32) -> Self {
        Self {
            magic: MAGIC,
            aspects,
            blocks,
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

pub struct Aspect {
    pub b_offset: u32,
    // TODO: encrypt the fields using a RSA key
    // pub key: [u8; 32],
    // pub gen: [u8; 32],
}

pub struct Block([u8; 1024]);
