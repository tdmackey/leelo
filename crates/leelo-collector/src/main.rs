//! Collect local observations without access to evaluation or volume credentials.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod metrics;
mod reconcile;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SnapshotRole {
    Frontend,
    Worker,
}

#[cfg(target_os = "linux")]
impl SnapshotRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::Worker => "worker",
        }
    }
}

#[derive(Parser)]
#[command(version, about = "Collect bounded Leelo observations")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Receive local events. The directory must be private to the collector.
    Events {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, required = true)]
        source: Vec<String>,
    },
    /// Read one protected daemon metrics snapshot into a textfile.
    Snapshot {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        server_uid: u32,
        /// Trusted role of the configured server UID; every sample must match.
        #[arg(long, value_enum)]
        role: SnapshotRole,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reconcile expected boots with external observations and local journals.
    Reconcile {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        observations: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

fn run() -> Result<()> {
    match Args::parse().command {
        Command::Reconcile {
            inventory,
            observations,
            output,
        } => reconcile::run(&inventory, &observations, &output),
        command => {
            #[cfg(target_os = "linux")]
            match command {
                Command::Events {
                    socket,
                    state_dir,
                    source,
                } => linux::events(&socket, &state_dir, &source),
                Command::Snapshot {
                    socket,
                    server_uid,
                    role,
                    output,
                } => linux::snapshot(&socket, server_uid, role, &output),
                Command::Reconcile { .. } => unreachable!(),
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = command;
                Err("local collection requires Linux".into())
            }
        }
    }
}

fn main() {
    if run().is_err() {
        eprintln!(
            "leelo-collector: collection failed; check configuration, permissions, and service state"
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn snapshot_requires_a_known_explicit_role() {
        let mut args = vec![
            "leelo-collector",
            "snapshot",
            "--socket",
            "metrics.sock",
            "--server-uid",
            "100",
            "--output",
            "metrics.prom",
        ];
        assert!(Args::try_parse_from(&args).is_err());
        args.extend(["--role", "client"]);
        assert!(Args::try_parse_from(&args).is_err());
        *args.last_mut().unwrap() = "frontend";
        assert!(Args::try_parse_from(&args).is_ok());
        *args.last_mut().unwrap() = "worker";
        assert!(Args::try_parse_from(args).is_ok());
    }
}
