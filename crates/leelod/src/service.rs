//! These service operations handle readiness and temporary listener failures.
use crate::metrics::{Metrics, Outcome};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const FIRST_RETRY: Duration = Duration::from_millis(50);
const MAX_RETRY: Duration = Duration::from_secs(1);

/// Stop on the normal service-manager signal without a telemetry flush or dependency wait.
pub async fn until_shutdown<F>(operation: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = operation => result,
        _ = terminate.recv() => Ok(()),
        result = tokio::signal::ctrl_c() => { result?; Ok(()) },
    }
}

/// Notify the service manager only after all worker startup checks succeed.
/// Standalone processes do not need a notification socket.
pub fn ready() -> io::Result<()> {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(path) => notify_ready(&path),
        None => Ok(()),
    }
}

fn notify_ready(path: &OsStr) -> io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    let bytes = path.as_bytes();
    if bytes.first() == Some(&b'@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(&bytes[1..])?;
            socket.send_to_addr(b"READY=1", &address)?;
        }
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "abstract notification sockets require Linux",
        ));
    } else if Path::new(path).is_absolute() {
        socket.send_to(b"READY=1", path)?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "notification socket needs an absolute path or an abstract name",
        ));
    }
    Ok(())
}

fn temporary(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::WouldBlock
    ) {
        return true;
    }
    let Some(number) = error.raw_os_error() else {
        return false;
    };
    let errno = Errno::from_raw_os_error(number);
    // Linux can return a pending connection's network error from accept.
    matches!(
        errno,
        Errno::MFILE
            | Errno::NFILE
            | Errno::NOBUFS
            | Errno::NOMEM
            | Errno::NETDOWN
            | Errno::NETUNREACH
            | Errno::HOSTUNREACH
            | Errno::HOSTDOWN
            | Errno::PROTO
            | Errno::NOPROTOOPT
            | Errno::OPNOTSUPP
    )
}

/// Keep temporary connection failures inside the listener operation.
/// Delay retries to prevent a busy loop during resource pressure.
pub async fn accept_observed<T, F, Fut>(metrics: Arc<Metrics>, mut operation: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut delay = FIRST_RETRY;
    let mut retrying = None;
    loop {
        match operation().await {
            Ok(connection) => {
                if let Some(retry) = retrying.take() {
                    crate::metrics::Retry::finish(retry, Outcome::Success);
                    metrics.event("listener_recovered", "listener", "success", "none");
                }
                return Ok(connection);
            }
            Err(error) if temporary(&error) => {
                metrics.accept_error(&error);
                if retrying.is_none() {
                    metrics.event(
                        "listener_impaired",
                        "listener",
                        "failure",
                        "temporary_accept",
                    );
                    retrying = Some(metrics.retry());
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_RETRY);
            }
            Err(error) => {
                metrics.accept_error(&error);
                if let Some(retry) = retrying.take() {
                    retry.finish(Outcome::Io);
                }
                metrics.event("listener_failed", "listener", "failure", "fatal_accept");
                return Err(error);
            }
        }
    }
}

#[cfg(test)]
async fn accept<T, F, Fut>(_name: &'static str, operation: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    accept_observed(Metrics::new(crate::metrics::Role::Frontend, 64), operation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn notification_reaches_a_filesystem_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        notify_ready(path.as_os_str()).unwrap();
        let mut bytes = [0; 32];
        let count = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"READY=1");
        assert!(notify_ready(OsStr::new("relative.sock")).is_err());
        assert!(notify_ready(directory.path().join("missing.sock").as_os_str()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("leelo-notify-test-{}", std::process::id());
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&address).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        notify_ready(OsStr::new(&format!("@{name}"))).unwrap();
        let mut bytes = [0; 32];
        let count = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"READY=1");
    }

    #[tokio::test(start_paused = true)]
    async fn temporary_errors_retry_with_a_capped_delay() {
        let mut results: VecDeque<io::Result<u8>> = (0..7)
            .map(|_| Err(io::Error::from_raw_os_error(Errno::MFILE.raw_os_error())))
            .chain([Ok(42)])
            .collect();
        let start = tokio::time::Instant::now();
        let value = accept("test", || std::future::ready(results.pop_front().unwrap()))
            .await
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(start.elapsed(), Duration::from_millis(3550));
    }

    #[tokio::test(start_paused = true)]
    async fn aborted_connections_retry_but_bad_listeners_fail() {
        let mut attempts = 0;
        let error = accept::<(), _, _>("test", || {
            attempts += 1;
            std::future::ready(Err(if attempts == 1 {
                io::Error::from(io::ErrorKind::ConnectionAborted)
            } else {
                io::Error::from_raw_os_error(Errno::BADF.raw_os_error())
            }))
        })
        .await
        .unwrap_err();
        assert_eq!(attempts, 2);
        assert_eq!(error.raw_os_error(), Some(Errno::BADF.raw_os_error()));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_stops_temporary_error_retries() {
        let mut attempts = 0;
        let result = tokio::time::timeout(
            Duration::from_millis(25),
            accept::<(), _, _>("test", || {
                attempts += 1;
                std::future::ready(Err(io::Error::from_raw_os_error(
                    Errno::NOMEM.raw_os_error(),
                )))
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }
}
