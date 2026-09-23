#![forbid(unsafe_code)]
//! This executable supplies a TLS frontend and a separate key worker with minimum privileges.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(unix)]
mod metrics;
#[cfg(unix)]
mod private_file;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod service;
#[cfg(unix)]
mod snapshot;
#[cfg(unix)]
mod worker;

#[derive(clap::Args, Default)]
pub struct Monitoring {
    /// Protected snapshot socket in a separate service-owned collector directory.
    #[arg(long, requires = "metrics_uid")]
    pub metrics_socket: Option<PathBuf>,
    /// Only this kernel UID may read snapshots; must be a separate collector account.
    #[arg(long, requires = "metrics_socket")]
    pub metrics_uid: Option<u32>,
    /// Assign only the metrics directory and socket to this supplementary group.
    #[arg(long, requires = "metrics_socket")]
    pub metrics_gid: Option<u32>,
}

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
        #[command(flatten)]
        monitoring: Monitoring,
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
        #[command(flatten)]
        monitoring: Monitoring,
    },
}

#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = run(cli).await;
    if result.is_err() {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(unix)]
async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen { key } => {
            let result = worker::keygen(&key);
            leelo_telemetry::Emitter::from_env().emit(leelo_telemetry::Event::new(
                "leelod",
                "key_creation",
                "keygen",
                "key_file",
                if result.is_ok() { "success" } else { "failure" },
                if result.is_ok() {
                    "none"
                } else {
                    "key_creation_failed"
                },
            ));
            result
        }
        Command::Worker {
            key,
            socket,
            allow_uid,
            monitoring,
        } => {
            let metrics = metrics::Metrics::new(metrics::Role::Worker, 8);
            metrics.lifecycle("service_start", "startup", "started", "none");
            let result = service::until_shutdown(worker::run(
                &key,
                &socket,
                allow_uid,
                metrics.clone(),
                &monitoring,
            ))
            .await;
            metrics.lifecycle(
                "service_stop",
                "service",
                if result.is_ok() { "success" } else { "failure" },
                if result.is_ok() {
                    "none"
                } else {
                    "service_failed"
                },
            );
            result
        }
        Command::Serve {
            listen,
            cert,
            tls_key,
            worker_socket,
            monitoring,
        } => {
            let metrics = metrics::Metrics::new(metrics::Role::Frontend, 64);
            metrics.lifecycle("service_start", "startup", "started", "none");
            let result = service::until_shutdown(server::run(
                listen,
                &cert,
                &tls_key,
                worker_socket,
                metrics.clone(),
                &monitoring,
            ))
            .await;
            metrics.lifecycle(
                "service_stop",
                "service",
                if result.is_ok() { "success" } else { "failure" },
                if result.is_ok() {
                    "none"
                } else {
                    "service_failed"
                },
            );
            result
        }
    }
}

#[cfg(not(unix))]
async fn run(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    Err("leelod requires Linux/Unix socket credential and permission enforcement".into())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn metrics_group_requires_explicit_snapshot_configuration() {
        let base = [
            "leelod",
            "worker",
            "--key",
            "key",
            "--socket",
            "worker.sock",
            "--allow-uid",
            "100",
        ];
        let mut args = base.to_vec();
        args.extend(["--metrics-gid", "200"]);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend(["--metrics-socket", "metrics/metrics.sock"]);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend(["--metrics-uid", "201"]);
        assert!(Cli::try_parse_from(args).is_ok());
    }
}
