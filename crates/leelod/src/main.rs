#![forbid(unsafe_code)]
//! This executable supplies a TLS frontend and a separate key worker with minimum privileges.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(unix)]
mod private_file;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod worker;

#[derive(Parser)]
#[command(
    version,
    about = "Leelo network-bound key evaluator; run worker and TLS frontend as separate OS users"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an evaluation key file (48 secret bytes, mode 0600).
    Keygen {
        #[arg(long)]
        key: PathBuf,
    },
    /// Start a key worker on a private Unix socket. This command requires Linux.
    Worker {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        /// Set the numeric UID of the only frontend that can use this socket.
        #[arg(long)]
        allow_uid: u32,
    },
    /// Serve network-bound evaluations over TLS 1.3. This command never loads an evaluation key.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        worker_socket: PathBuf,
    },
}

#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = run(cli).await;
    if let Err(error) = result {
        eprintln!("leelod: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(unix)]
async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen { key } => worker::keygen(&key),
        Command::Worker {
            key,
            socket,
            allow_uid,
        } => worker::run(&key, &socket, allow_uid).await,
        Command::Serve {
            listen,
            cert,
            tls_key,
            worker_socket,
        } => server::run(listen, &cert, &tls_key, worker_socket).await,
    }
}

#[cfg(not(unix))]
async fn run(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    Err("leelod requires Linux/Unix socket credential and permission enforcement".into())
}
