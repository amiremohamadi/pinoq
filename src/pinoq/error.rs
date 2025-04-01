use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, PinoqError>;

#[derive(Error, Debug)]
pub(crate) enum PinoqError {
    #[error("No such file")]
    NoEntry,
    #[error("Not a directory")]
    NoDirectory,
    #[error("Not enoguh space available")]
    NoEnoughSpace,
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Serialization error")]
    Serialization(#[from] bincode::Error),
    #[error("Invalid Config")]
    InvalidConfig,
}

impl PinoqError {
    pub(crate) fn to_code(&self) -> i32 {
        match self {
            Self::NoEntry => libc::ENOENT,
            Self::NoDirectory => libc::ENOTDIR,
            Self::NoEnoughSpace => libc::ENOSPC,
            Self::IO(_) => libc::EIO,
            _ => -1,
        }
    }
}
