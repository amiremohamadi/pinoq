mod file_format;
mod file_system;

use std::fs::OpenOptions;
use std::io::Write;
use std::mem;

use anyhow::Result;

pub use file_format::{Aspect, Block, SuperBlock};
pub use file_system::{Config, PinoqFs};

pub fn mount(config: Config, mountpoint: &str) {
    let mut fs = PinoqFs::new(config).unwrap();
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

    let length = mem::size_of::<SuperBlock>()
        + mem::size_of::<Aspect>() * (aspects as usize)
        + mem::size_of::<Block>() * (blocks as usize);
    file.set_len(length as _);

    let mut sblock = SuperBlock::new(aspects, blocks);
    sblock.serialize_into(&mut file)?;

    Ok(())
}
