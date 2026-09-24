//! Real loopback TLS tests. OpenSSL only creates temporary test certificates.
use leelo_crypto::SecretServer;
use leelo_net::wire;
use leelo_probe::{Outcome, Report};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
enum Behavior {
    Good,
    WrongProof,
    InvalidPoint,
    MalformedFrame,
    Refused,
    SlowBody,
}

struct Server {
    origin: String,
    public_key: [u8; 49],
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

fn certificate(directory: &Path, name: &str) -> (PathBuf, PathBuf) {
    certificate_days(directory, name, "2")
}

fn certificate_days(directory: &Path, name: &str, days: &str) -> (PathBuf, PathBuf) {
    let cert = directory.join(format!("{name}.crt"));
    let key = directory.join(format!("{name}.key"));
    let openssl_config = directory.join(format!("{name}.cnf"));
    std::fs::write(&openssl_config, "[req]\ndistinguished_name=dn\n[dn]\n").unwrap();
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            days,
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .arg("-config")
        .arg(openssl_config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("probe integration tests require openssl");
    assert!(status.success());
    (cert, key)
}

fn server(cert: &Path, key: &Path, behavior: Behavior) -> Server {
    let cert = std::fs::read(cert).unwrap();
    let key = std::fs::read(key).unwrap();
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let certificates = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(&key).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let secret = SecretServer::generate().unwrap();
    let public_key = *secret.public_key().as_bytes();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let exchange = async {
                let (stream, _) = listener.accept().await?;
                let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls)).accept(stream).await?;
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(tls.read_u8().await?);
                    assert!(headers.len() < 8192);
                }
                assert!(headers.starts_with(b"POST /v1/evaluate HTTP/1.1\r\n"));
                let mut request = [0; wire::REQUEST_BYTES];
                tls.read_exact(&mut request).await?;
                let request = wire::decode_request(&request).unwrap();
                let mut evaluation = secret.evaluate(&request.point).unwrap();
                match behavior {
                    Behavior::WrongProof => {
                        let (_, other) = leelo_crypto::blind(b"a different fresh blind").unwrap();
                        evaluation.proof = secret.evaluate(&other).unwrap().proof;
                    }
                    Behavior::InvalidPoint => evaluation.element = [0; 49],
                    _ => {}
                }
                let mut body = wire::encode_response(&evaluation).to_vec();
                if matches!(behavior, Behavior::MalformedFrame) {
                    body.push(0);
                }
                let status = if matches!(behavior, Behavior::Refused) { "503 Service Unavailable" } else { "200 OK" };
                let headers = format!("HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", wire::CONTENT_TYPE, body.len());
                tls.write_all(headers.as_bytes()).await?;
                if matches!(behavior, Behavior::SlowBody) {
                    tls.write_all(&body[..1]).await?;
                    tls.flush().await?;
                    tokio::time::sleep(Duration::from_secs(7)).await;
                    tls.write_all(&body[1..]).await?;
                } else {
                    tls.write_all(&body).await?;
                }
                tls.shutdown().await?;
                Ok::<(), io::Error>(())
            };
            tokio::select! {
                _ = stopped => {},
                _ = tokio::time::timeout(Duration::from_secs(10), exchange) => {},
            }
        });
    });
    Server {
        origin: format!("https://localhost:{port}"),
        public_key,
        stop: Some(stop),
        thread: Some(thread),
    }
}

fn config(directory: &Path, origin: &str, public_key: [u8; 49], cert: &Path) -> PathBuf {
    let path = directory.join("provider-private-configuration.json");
    let value = serde_json::json!({ "providers": [{
        "provider_id": hex::encode([7u8; 32]),
        "key_id": hex::encode(leelo_net::key_id(&public_key)),
        "public_key": hex::encode(public_key),
        "url": origin,
        "ca_file": cert.file_name().unwrap().to_str().unwrap(),
    }] });
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

fn assert_safe(report: &Report, configured: &Path, public_key: [u8; 49]) {
    let output = format!(
        "{}{}",
        serde_json::to_string(report).unwrap(),
        report.prometheus()
    );
    for disallowed in [
        "localhost".to_string(),
        configured.to_string_lossy().into_owned(),
        "provider-private-configuration".to_string(),
        hex::encode(public_key),
        hex::encode(leelo_net::key_id(&public_key)),
        hex::encode([7u8; 32]),
        "BEGIN CERTIFICATE".to_string(),
        "nonproduction".to_string(),
    ] {
        assert!(
            !output.contains(&disallowed),
            "telemetry contains forbidden configured material"
        );
    }
    assert!(output.len() < 6000);
    assert!(report.duration_seconds.is_finite());
}

#[test]
fn valid_evaluation_observes_served_certificate_and_reports_safe_fields() {
    let directory = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(directory.path(), "served");
    let (other, _) = certificate_days(directory.path(), "unused-trust-root", "30");
    // The first configured certificate has a different expiry from the peer.
    // Reporting configured-bundle expiry instead of served-leaf expiry fails this test.
    let bundle = directory.path().join("trust-bundle.crt");
    let mut trusted = std::fs::read(other).unwrap();
    trusted.extend_from_slice(&std::fs::read(&cert).unwrap());
    std::fs::write(&bundle, trusted).unwrap();
    let server = server(&cert, &key, Behavior::Good);
    let configured = config(directory.path(), &server.origin, server.public_key, &bundle);
    let report = leelo_probe::run(&configured, 1);
    assert_eq!(report.outcome, Outcome::Success);
    assert!(report.success && report.collection_success && report.clock_valid);
    let expiry = report.certificate_not_after_timestamp_seconds.unwrap();
    assert!(expiry > report.completed_timestamp_seconds + 24 * 60 * 60);
    assert!(expiry < report.completed_timestamp_seconds + 3 * 24 * 60 * 60);
    assert_safe(&report, &configured, server.public_key);
}

#[test]
fn wrong_pin_valid_but_wrong_proof_and_malformed_responses_fail() {
    let directory = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(directory.path(), "served");
    for (behavior, wrong_pin, expected) in [
        (Behavior::Good, true, Outcome::InvalidProof),
        (Behavior::WrongProof, false, Outcome::InvalidProof),
        (Behavior::InvalidPoint, false, Outcome::InvalidResponse),
        (Behavior::MalformedFrame, false, Outcome::InvalidResponse),
        (Behavior::Refused, false, Outcome::RemoteRejected),
    ] {
        let server = server(&cert, &key, behavior);
        let pin = if wrong_pin {
            *SecretServer::generate().unwrap().public_key().as_bytes()
        } else {
            server.public_key
        };
        let configured = config(directory.path(), &server.origin, pin, &cert);
        let report = leelo_probe::run(&configured, 1);
        assert_eq!(report.outcome, expected);
        assert!(!report.success);
        assert!(report.collection_success);
        assert!(report.certificate_not_after_timestamp_seconds.is_some());
        assert_safe(&report, &configured, pin);
    }
}

#[test]
fn wrong_host_and_wrong_ca_are_never_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(directory.path(), "served");
    let (unrelated, _) = certificate(directory.path(), "unrelated");
    for wrong_host in [true, false] {
        let server = server(&cert, &key, Behavior::Good);
        let origin = if wrong_host {
            server.origin.replace("localhost", "127.0.0.1")
        } else {
            server.origin.clone()
        };
        let configured = config(
            directory.path(),
            &origin,
            server.public_key,
            if wrong_host { &cert } else { &unrelated },
        );
        let report = leelo_probe::run(&configured, 1);
        assert_eq!(report.outcome, Outcome::Transport);
        assert!(report.certificate_not_after_timestamp_seconds.is_none());
        assert!(!report.success);
        assert_safe(&report, &configured, server.public_key);
    }
}

#[test]
fn complete_response_deadline_includes_slow_body() {
    let directory = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(directory.path(), "served");
    let server = server(&cert, &key, Behavior::SlowBody);
    let configured = config(directory.path(), &server.origin, server.public_key, &cert);
    let start = Instant::now();
    let report = leelo_probe::run(&configured, 1);
    assert_eq!(report.outcome, Outcome::Timeout);
    assert!(start.elapsed() < Duration::from_secs(6));
    assert!(report.certificate_not_after_timestamp_seconds.is_some());
}

#[test]
fn refused_network_connection_is_a_fresh_failure_without_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let (cert, _) = certificate(directory.path(), "configured-ca");
    // Reserve then release an ephemeral loopback port to exercise connection refusal.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    drop(listener);
    let public = *SecretServer::generate().unwrap().public_key().as_bytes();
    let configured = config(directory.path(), &origin, public, &cert);
    let report = leelo_probe::run(&configured, 1);
    assert_eq!(report.outcome, Outcome::Transport);
    assert!(!report.success && report.collection_success);
    assert!(report.completed_timestamp_seconds >= report.started_timestamp_seconds);
    assert!(report.certificate_not_after_timestamp_seconds.is_none());
    assert_safe(&report, &configured, public);
}

#[test]
fn failed_attempt_replaces_stale_success_and_cli_reports_write_failure() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("probe.prom");
    std::fs::write(&target, "leelo_probe_success{target=\"1\"} 1\n").unwrap();
    let missing_config = directory.path().join("missing.json");
    let output = Command::new(env!("CARGO_BIN_EXE_leelo-probe"))
        .arg("--config")
        .arg(&missing_config)
        .args(["--target", "1", "--textfile"])
        .arg(&target)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "configuration");
    assert_eq!(report["collection_success"], true);
    let metrics = std::fs::read_to_string(&target).unwrap();
    assert!(metrics.contains("leelo_probe_success{target=\"1\"} 0\n"));
    assert!(metrics.contains("leelo_probe_last_attempt_timestamp_seconds{target=\"1\"}"));
    assert!(!metrics.contains("leelo_tls_certificate_not_after_timestamp_seconds"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);

    let output = Command::new(env!("CARGO_BIN_EXE_leelo-probe"))
        .arg("--config")
        .arg(missing_config)
        .args(["--target", "1", "--textfile"])
        .arg(directory.path().join("missing-directory/probe.prom"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["collection_success"], false);
    assert_eq!(output.stderr, b"leelo-probe: textfile collection failed\n");
}

#[test]
fn oversized_unknown_and_inconsistent_configuration_is_rejected_without_network() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    for bytes in [
        vec![b' '; 32769],
        b"{\"providers\":[],\"secret\":\"do-not-print\"}".to_vec(),
    ] {
        std::fs::write(&path, bytes).unwrap();
        let report = leelo_probe::run(&path, 1);
        assert_eq!(report.outcome, Outcome::Configuration);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("do-not-print")
        );
    }
    let public = *SecretServer::generate().unwrap().public_key().as_bytes();
    let provider = serde_json::json!({
        "provider_id": hex::encode([7u8; 32]),
        "key_id": hex::encode([0u8; 32]),
        "public_key": hex::encode(public),
        "url": "https://localhost:1",
        "ca_file": "missing-ca.crt",
    });
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"providers": [provider]})).unwrap(),
    )
    .unwrap();
    assert_eq!(leelo_probe::run(&path, 1).outcome, Outcome::Configuration);

    let oversized_ca = directory.path().join("oversized-ca.crt");
    std::fs::write(&oversized_ca, vec![b' '; leelo_net::MAX_CA_BYTES + 1]).unwrap();
    let configured = config(
        directory.path(),
        "https://localhost:1",
        public,
        &oversized_ca,
    );
    assert_eq!(
        leelo_probe::run(&configured, 1).outcome,
        Outcome::Configuration
    );
}
