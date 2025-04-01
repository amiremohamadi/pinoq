pub mod config;
mod encryption;
mod error;
mod filefmt;
mod fs;

pub use fs::PinoqFs;

use config::Config;
use error::{PinoqError, Result};
use filefmt::{Aspect, Block, EncryptedAspect, PinoqSerialize, SuperBlock};

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

#[inline]
fn get_block_offset(aspects: u32, blocks: u32, n: u32) -> usize {
    std::mem::size_of::<SuperBlock>()
        + EncryptedAspect::size_of(blocks) * (aspects as usize)
        + std::mem::size_of::<Block>() * (n as usize)
}

#[inline]
fn get_aspect_offset(blocks: u32, n: u32) -> usize {
    std::mem::size_of::<SuperBlock>() + EncryptedAspect::size_of(blocks) * (n as usize)
}

fn decrypt_aspect<R>(mut reader: R, offset: usize, password: &str) -> Result<Aspect>
where
    R: Read,
    R: Seek,
{
    reader
        .seek(SeekFrom::Start(offset as _))
        .map_err(|e| PinoqError::IO(e))?;
    let encrypted = EncryptedAspect::deserialize_from(reader)?;
    Aspect::from_encrypted_aspect(encrypted, password)
}

fn encrypt_aspect<W>(mut writer: W, offset: usize, aspect: Aspect, password: &str) -> Result<()>
where
    W: Write,
    W: Seek,
{
    writer
        .seek(SeekFrom::Start(offset as _))
        .map_err(|e| PinoqError::IO(e))?;
    let encrypted = aspect.to_encrypted_aspect(password);
    encrypted.serialize_into(&mut writer)
}

pub fn mount(config: Config) {
    let mountpoint = config.mount.clone();
    let fs = PinoqFs::new(config).unwrap();
    let _ = fuser::mount2(
        fs,
        mountpoint,
        &[
            fuser::MountOption::AutoUnmount,
            fuser::MountOption::AllowOther,
        ],
    );
}

pub fn mkfs(aspects: u32, blocks: u32, path: &str, pass: &str) -> anyhow::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

    let length = get_block_offset(aspects, blocks, blocks);
    file.set_len(length as _)?;

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let sblock = SuperBlock::new(aspects, blocks, uid, gid);
    sblock.serialize_into(&mut file)?;

    for _ in 0..aspects {
        let aspect = Aspect::new(blocks);
        let encrypted = aspect.to_encrypted_aspect(pass);
        encrypted.serialize_into(&mut file)?;
    }

    Ok(())
}

pub fn inspect(path: &str) -> anyhow::Result<()> {
    let sblock = PinoqFs::inspect(path)?;
    println!(
        r#"{{"path": "{}", "magic": "{:#X}", "aspects": {}, "blocks": {}}}"#,
        path, sblock.magic, sblock.aspects, sblock.blocks
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_volume() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("my-volume.pnoq");
        let path = path.to_str().unwrap();

        mkfs(2, 512, path, "password").unwrap();
        let sblock = PinoqFs::inspect(path).unwrap();
        assert_eq!(sblock.magic, 0x504E4F51u32);
        assert_eq!(sblock.aspects, 2);
        assert_eq!(sblock.blocks, 512);

        dir.close().unwrap();
    }

    #[test]
    fn test_offsets() {
        let aspects = 2;
        let blocks = 256;

        let sblock_len = std::mem::size_of::<SuperBlock>();
        let block_len = std::mem::size_of::<Block>();
        let aspect_len = EncryptedAspect::size_of(blocks);

        let offset = get_aspect_offset(blocks, 0);
        assert_eq!(offset, sblock_len);
        let offset = get_aspect_offset(blocks, 1);
        assert_eq!(offset, sblock_len + aspect_len);

        let offset = get_block_offset(aspects, blocks, 0);
        assert_eq!(offset, sblock_len + aspect_len * (aspects as usize));
        let offset = get_block_offset(aspects, blocks, 1);
        assert_eq!(
            offset,
            sblock_len + aspect_len * (aspects as usize) + block_len
        );
    }
}
