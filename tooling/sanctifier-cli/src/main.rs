use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

mod branding;
mod cache;
mod commands;

#[derive(Parser)]
#[command(name = "sanctifier")]
#[command(about = "Stellar Soroban Security & Formal Verification Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a Soroban contract for vulnerabilities
    Analyze(commands::analyze::AnalyzeArgs),
    /// Generate a security report
    Report {
        /// Output file path
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Initialize Sanctifier in a new project
    Init(commands::init::InitArgs),
    /// Check for and download the latest Sanctifier binary
    Update,
    /// Translate Soroban contract into a Kani-verifiable harness
    Kani {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze(args) => {
            if args.format != "json" {
                branding::print_logo();
            }
            commands::analyze::exec(args)?;
        }
        Commands::Report { output } => {
            if let Some(p) = output {
                println!("Report saved to {:?}", p);
            } else {
                println!("Report printed to stdout.");
            }
        }
        Commands::Init(args) => {
            commands::init::exec(args, None)?;
        }
        Commands::Update => {
            commands::update::exec()?;
        }
        Commands::Kani { path, output } => {
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                eprintln!(
                    "❌ Error: Kani bridge currently only supports single .rs files."
                );
                std::process::exit(1);
            }
            if let Ok(content) = fs::read_to_string(&path) {
                match sanctifier_core::kani_bridge::KaniBridge::translate_for_kani(&content) {
                    Ok(harness) => {
                        if let Some(ref out_path) = output {
                            if let Err(e) = std::fs::write(out_path, harness) {
                                eprintln!("❌ Failed to write Kani harness: {}", e);
                            } else {
                                println!(
                                    "✨ Generated Kani harness at {:?}",
                                    out_path
                                );
                            }
                        } else {
                            println!("{}", harness);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Error generating Kani harness: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("❌ Error reading file {:?}", path);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
