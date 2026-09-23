use crate::{Outcome, Report};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;

impl Report {
    /// Last-run gauges only. This file is not a cumulative history or latency histogram.
    pub fn prometheus(&self) -> String {
        let mut output = String::with_capacity(3000);
        let target = self.target;
        for (name, help, value) in [
            (
                "leelo_probe_success",
                "Last attempt completed a valid evaluation under the configured pin.",
                u64::from(self.success),
            ),
            (
                "leelo_probe_collection_success",
                "Last attempt produced a complete observation with a valid clock.",
                u64::from(self.collection_success),
            ),
            (
                "leelo_probe_clock_valid",
                "Wall-clock endpoint timestamps are available and nondecreasing.",
                u64::from(self.clock_valid),
            ),
            (
                "leelo_probe_started_timestamp_seconds",
                "Start of the latest attempt, Unix seconds.",
                self.started_timestamp_seconds,
            ),
            (
                "leelo_probe_last_attempt_timestamp_seconds",
                "Completion of the latest attempt including failed attempts, Unix seconds.",
                self.completed_timestamp_seconds,
            ),
            (
                "leelo_probe_certificate_observed",
                "A validated TLS peer leaf certificate expiry was observed during this attempt.",
                u64::from(self.certificate_not_after_timestamp_seconds.is_some()),
            ),
        ] {
            let _ = writeln!(
                output,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name}{{target=\"{target}\"}} {value}"
            );
        }
        let _ = writeln!(
            output,
            "# HELP leelo_probe_duration_seconds Elapsed monotonic duration of the latest attempt.\n# TYPE leelo_probe_duration_seconds gauge\nleelo_probe_duration_seconds{{target=\"{target}\"}} {:.6}",
            self.duration_seconds
        );
        let _ = writeln!(
            output,
            "# HELP leelo_probe_outcome One-hot result of the latest attempt.\n# TYPE leelo_probe_outcome gauge"
        );
        for outcome in Outcome::ALL {
            let _ = writeln!(
                output,
                "leelo_probe_outcome{{target=\"{target}\",outcome=\"{}\"}} {}",
                outcome.as_str(),
                u8::from(self.outcome == outcome)
            );
        }
        if let Some(expiry) = self.certificate_not_after_timestamp_seconds {
            let _ = writeln!(
                output,
                "# HELP leelo_tls_certificate_not_after_timestamp_seconds Expiry of the actually observed validated peer leaf certificate.\n# TYPE leelo_tls_certificate_not_after_timestamp_seconds gauge\nleelo_tls_certificate_not_after_timestamp_seconds{{target=\"{target}\"}} {expiry}"
            );
        }
        output
    }
}

/// Write in the destination directory, then atomically replace the last-run file.
/// No existing content is read, so a different target cannot supply stale success/expiry.
pub fn write_textfile(path: &Path, report: &Report) -> io::Result<()> {
    if path.extension().is_none_or(|extension| extension != "prom") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "textfile must use .prom extension",
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".leelo-probe-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    temporary.write_all(report.prometheus().as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}
