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
        num_args = 4,
        value_names = ["ASPECTS", "BLOCKS", "PATH", "PASSWORD"],
    )]
    mkfs: Vec<String>,
    /// Inspect information from a pinoq disk
    #[clap(long("inspect"), value_names = ["PATH"])]
    inspect_path: Option<String>,
}

fn parse_args() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(path) = args.config_path {
        let config = match std::fs::read_to_string(path) {
            Ok(c) => Config::new(&c),
            _ => panic!("Couldn't find the file"),
        }?;
        pinoq::mount(config);
    } else if args.mkfs.len() > 0 {
        let aspects = args.mkfs[0].parse::<u32>()?;
        let blocks = args.mkfs[1].parse::<u32>()?;
        pinoq::mkfs(aspects, blocks, &args.mkfs[2], &args.mkfs[3])?;
    } else if let Some(path) = args.inspect_path {
        pinoq::inspect(&path)?;
    }

    Ok(())
}

fn main() {
    pretty_env_logger::formatted_builder()
        .parse_filters("DEBUG")
        .init();

    if let Err(e) = parse_args() {
        eprintln!("pionq: {:?}", e);
        std::process::exit(1);
    }
}
