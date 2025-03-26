# Hacking on Pinoq

## Prerequisites
Before you start, make sure you have the following installed on your system:

1. [Rust](https://www.rust-lang.org/tools/install) (including `cargo`)
2. [FUSE](https://github.com/libfuse/libfuse)

## Development Environment

Start by pulling the source code:
```sh
$ git clone https://github.com/amiremohamadi/pinoq.git && cd pinoq
```

Install the dependencies:
```sh
$ rustup update
$ sudo apt-get install -y libfuse-dev
```

Build the project:
```sh
$ cargo build
```

Create a pinoq volume:
```sh
$ cargo run -- --mkfs 2 1024 volume.pnoq
```

Modify the [configuration file](./config.toml) and mount the volume:
```sh
$ cargo run -- --mount ./config.toml
```

Execute the integration tests at the end to verify that your changes have not introduced any issues:
```sh
$ python ./tests/integration.py
```
