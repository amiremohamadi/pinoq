mod file_format;
mod file_system;

pub mod config;

use anyhow::Result;
use std::fs::OpenOptions;

use config::Config;
pub use file_format::{Aspect, Block, Dir, EncryptedAspect, INode, SuperBlock, BLOCK_SIZE};
pub use file_system::PinoqFs;

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

pub fn mkfs(aspects: u32, blocks: u32, path: &str, pass: &str) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

    let length = std::mem::size_of::<SuperBlock>()
        + EncryptedAspect::size_of(blocks) * (aspects as usize)
        + std::mem::size_of::<Block>() * (blocks as usize);
    file.set_len(length as _)?;

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let sblock = SuperBlock::new(aspects, blocks, uid, gid);
    sblock.serialize_into(&mut file)?;

    for _ in 0..aspects {
        let aspect = Aspect::new(blocks);
        let encrypted = aspect.to_encrypted_aspect(pass)?;
        encrypted.serialize_into(&mut file)?;
    }

    Ok(())
}

pub fn inspect(path: &str) -> Result<()> {
    let sblock = PinoqFs::inspect(path)?;
    println!(
        r#"{{"path": "{}", "magic": "{:#X}", "aspects": {}, "blocks": {}}}"#,
        path, sblock.magic, sblock.aspects, sblock.blocks
    );
    Ok(())
}
