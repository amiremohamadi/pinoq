mod pinoq;

use clap::Parser;
use pinoq::config::Config;

#[derive(Debug, Parser)]
#[command(version, arg_required_else_help = true)]
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
    /// Inspect information from a pinoq disk
    #[clap(long, requires = "path")]
    inspect: bool,
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
    } else if let Some(path) = args.path {
        if let Some(size) = args.file_system_size {
            let (aspects, blocks) = (size[0], size[1]);
            pinoq::mkfs(aspects, blocks, &path)?;
        }
        if args.inspect {
            pinoq::inspect(&path)?;
        }
    }

    Ok(())
}
