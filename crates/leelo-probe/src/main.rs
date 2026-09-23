#![forbid(unsafe_code)]
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "One bounded HTTPS + VOPRF evaluation; never recovers a disk credential"
)]
struct Args {
    /// Ordinary trusted Leelo providers JSON; relative CA files resolve beside this file.
    #[arg(long)]
    config: PathBuf,
    /// One-based provider index. Use a stable small mapping in the deployment configuration.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=27))]
    target: u8,
    /// Dedicated last-run Node Exporter textfile, atomically replaced even on probe failure.
    #[arg(long)]
    textfile: PathBuf,
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            eprintln!("leelo-probe: invalid arguments; use --help");
            return ExitCode::from(2);
        }
    };
    let mut report = leelo_probe::run(&args.config, args.target);
    if leelo_probe::write_textfile(&args.textfile, &report).is_err() {
        report.collection_success = false;
        eprintln!("leelo-probe: textfile collection failed");
    }
    match serde_json::to_string(&report) {
        Ok(json) => println!("{json}"),
        Err(_) => return ExitCode::from(2),
    }
    if !report.collection_success {
        ExitCode::from(2)
    } else if report.success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
