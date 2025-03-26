mod pinoq;

use clap::Parser;
use pinoq::config::Config;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    /// Mount a volume based on specified config
    #[clap(long("mount"))]
    config_path: Option<String>,
    /// Create a pinoq volume with the specified size
    #[clap(
        long("mkfs"),
        num_args = 2,
        value_names = ["ASPECTS", "BLOCKS"],
        requires = "path"
    )]
    file_system_size: Option<Vec<u32>>,
    path: Option<String>,
}

fn main() -> anyhow::Result<()> {
    pretty_env_logger::formatted_builder()
        .parse_filters("DEBUG")
        .init();

    let args = Args::parse();
    if let Some(path) = args.config_path {
        let config = match std::fs::read_to_string(path) {
            Ok(c) => Config::new(&c),
            _ => panic!("Couldn't find the file"),
        }?;
        pinoq::mount(config);
    } else if let (Some(size), Some(path)) = (args.file_system_size, args.path) {
        let (aspects, blocks) = (size[0], size[1]);
        pinoq::mkfs(aspects, blocks, &path)?;
    }

    Ok(())
}
