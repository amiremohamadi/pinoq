mod file_format;
mod file_system;

use anyhow::Result;
use std::fs::OpenOptions;

pub use file_format::{Aspect, Block, Dir, INode, SuperBlock, BLOCK_SIZE};
pub use file_system::{Config, PinoqFs};

pub fn mount(config: Config, mountpoint: &str) {
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

pub fn mkfs(aspects: u32, blocks: u32, path: &str) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

    let length = std::mem::size_of::<SuperBlock>()
        + Aspect::size_of(blocks) * (aspects as usize)
        + std::mem::size_of::<Block>() * (blocks as usize);
    file.set_len(length as _)?;

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mut sblock = SuperBlock::new(aspects, blocks, uid, gid);
    sblock.serialize_into(&mut file)?;

    for _ in 0..aspects {
        let mut aspect = Aspect::new(blocks);
        aspect.serialize_into(&mut file)?;
    }

    Ok(())
}
