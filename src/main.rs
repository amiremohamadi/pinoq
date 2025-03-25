mod pinoq;
use clap::Parser;

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
        .parse_filters("INFO")
        .init();

    let args = Args::parse();
    if let Some(path) = args.config_path {
        pinoq::mount(
            pinoq::Config {
                disk: "./volume.pnoq".to_string(),
                aspects: 2,
                block_size: 1024,
            },
            "/tmp/pinoq",
        );
    } else if let (Some(size), Some(path)) = (args.file_system_size, args.path) {
        let (aspects, blocks) = (size[0], size[1]);
        pinoq::mkfs(aspects, blocks, &path)?;
    }

    Ok(())
}
