//! These tests start real worker and frontend child processes in a temporary directory.
//! All connections use loopback. The tests require the openssl executable to configure TLS.
#![cfg(unix)]
use leelo_crypto::ServerPublicKey;
use leelo_envelope::NetworkBinding;
use leelo_net::{Endpoint, HttpsNetworkProvider, wire};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn certificate(directory: &Path, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let certificate = directory.join(format!("{name}.crt"));
    let key = directory.join(format!("{name}.key"));
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
            "1",
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
        .arg(&certificate)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("integration test requires openssl");
    assert!(status.success());
    (certificate, key)
}

#[test]
fn actual_tls_and_worker_verify_proof_and_reject_wrong_trust_identity_mode_and_sizes() {
    run_tls_worker_test(false);
}

#[test]
fn snapshot_setup_failure_preserves_readiness_and_valid_evaluation() {
    run_tls_worker_test(true);
}

fn run_tls_worker_test(invalid_metrics_directory: bool) {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("evaluation.key");
    let socket = directory.path().join("worker.sock");
    let public = Command::new(env!("CARGO_BIN_EXE_leelod"))
        .arg("keygen")
        .arg("--key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(public.status.success());
    let public: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    let public_key: [u8; 49] = hex::decode(public["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key_id: [u8; 32] = hex::decode(public["key_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(key_id, leelo_net::key_id(&public_key));
    let notify_path = directory.path().join("notify.sock");
    let notification = UnixDatagram::bind(&notify_path).unwrap();
    notification
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let metrics_directory = directory.path().join("metrics");
    std::fs::create_dir(&metrics_directory).unwrap();
    std::fs::set_permissions(&metrics_directory, std::fs::Permissions::from_mode(0o770)).unwrap();
    let event_path = directory.path().join("events.sock");
    let events = UnixDatagram::bind(&event_path).unwrap();
    events.set_nonblocking(true).unwrap();
    let configure = |command: &mut Command, role: &str| {
        command
            .env("NOTIFY_SOCKET", &notify_path)
            .env("LEELO_EVENTS_SOCKET", &event_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if invalid_metrics_directory {
            command
                .arg("--metrics-socket")
                .arg(metrics_directory.join(format!("{role}.sock")))
                .arg("--metrics-uid")
                .arg(
                    rustix::process::geteuid()
                        .as_raw()
                        .wrapping_add(1)
                        .to_string(),
                )
                .arg("--metrics-gid")
                .arg(rustix::process::getegid().as_raw().to_string());
        }
    };
    let mut worker_command = Command::new(env!("CARGO_BIN_EXE_leelod"));
    worker_command
        .arg("worker")
        .arg("--key")
        .arg(&key)
        .arg("--socket")
        .arg(&socket)
        .arg("--allow-uid")
        .arg(rustix::process::geteuid().as_raw().to_string());
    configure(&mut worker_command, "worker");
    let mut worker = ChildGuard(worker_command.spawn().unwrap());
    let mut notification_bytes = [0; 32];
    let count = notification.recv(&mut notification_bytes).unwrap();
    assert_eq!(&notification_bytes[..count], b"READY=1");
    assert!(worker.0.try_wait().unwrap().is_none(), "worker exited");
    // Receipt of READY means that the worker has already bound its socket.
    assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
    let (cert_path, tls_key) = certificate(directory.path(), "server");
    let ca_pem = std::fs::read(&cert_path).unwrap();
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut server_command = Command::new(env!("CARGO_BIN_EXE_leelod"));
    server_command
        .arg("serve")
        .arg("--listen")
        .arg(address.to_string())
        .arg("--cert")
        .arg(&cert_path)
        .arg("--tls-key")
        .arg(&tls_key)
        .arg("--worker-socket")
        .arg(&socket);
    configure(&mut server_command, "frontend");
    let mut server = ChildGuard(server_command.spawn().unwrap());
    let count = notification.recv(&mut notification_bytes).unwrap();
    assert_eq!(&notification_bytes[..count], b"READY=1");
    assert!(server.0.try_wait().unwrap().is_none(), "frontend exited");
    assert!(TcpStream::connect(address).is_ok());
    let origin = format!("https://localhost:{}", address.port());
    let binding = NetworkBinding {
        node_id: 1,
        provider_id: [7; 32],
        key_id,
        public_key,
        input_seed: [8; 32],
    };
    let make_provider = |url: String, ca_pem: Vec<u8>| {
        HttpsNetworkProvider::new(vec![Endpoint {
            provider_id: binding.provider_id,
            url,
            ca_pem,
        }])
        .unwrap()
    };
    let provider = make_provider(origin.clone(), ca_pem.clone());
    let (state, point) = leelo_crypto::blind(b"real-process TLS test").unwrap();
    let response = provider.evaluate_binding(&binding, &point).unwrap();
    assert!(
        state
            .finalize(&response, &ServerPublicKey::from_bytes(public_key).unwrap())
            .is_ok()
    );

    if invalid_metrics_directory {
        assert!(
            std::fs::read_dir(&metrics_directory)
                .unwrap()
                .next()
                .is_none()
        );
        assert_eq!(
            std::fs::metadata(&metrics_directory).unwrap().mode() & 0o777,
            0o770
        );
        assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(&socket).unwrap().gid(),
            rustix::process::getegid().as_raw()
        );
        let mut records = Vec::new();
        let mut bytes = [0; leelo_telemetry::MAX_EVENT_BYTES];
        while let Ok(count) = events.recv(&mut bytes) {
            records.push(leelo_telemetry::Record::decode(&bytes[..count]).unwrap());
        }
        for component in ["worker", "frontend"] {
            let failures: Vec<_> = records
                .iter()
                .filter(|record| {
                    record.component == component && record.event == "telemetry_failed"
                })
                .collect();
            assert_eq!(failures.len(), 1);
            let failure = failures[0];
            assert_eq!(failure.stage, "snapshot");
            assert_eq!(failure.outcome, "failure");
            assert_eq!(failure.reason, "setup_failed");
            assert!(!records.iter().any(|record| record.component == component && record.event == "service_failed"));
        }
        return;
    }

    let wrong_host = make_provider(
        format!("https://127.0.0.1:{}", address.port()),
        ca_pem.clone(),
    );
    assert!(wrong_host.evaluate_binding(&binding, &point).is_err());
    let (unrelated_ca, _) = certificate(directory.path(), "unrelated");
    let wrong_ca = make_provider(origin.clone(), std::fs::read(unrelated_ca).unwrap());
    assert!(wrong_ca.evaluate_binding(&binding, &point).is_err());

    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let request = wire::encode_request(&key_id, &point);
    let url = format!("{origin}/v1/evaluate");
    for index in [4, 5, 6, 7] {
        let mut wrong_header = request.to_vec();
        wrong_header[index] ^= 3;
        let response = client
            .post(&url)
            .header("content-type", wire::CONTENT_TYPE)
            .body(wrong_header)
            .send()
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    for body in [
        request[..88].to_vec(),
        [request.as_slice(), &[0]].concat(),
        vec![0; 16384],
    ] {
        let response = client
            .post(&url)
            .header("content-type", wire::CONTENT_TYPE)
            .body(body)
            .send()
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let mut wrong_key = request;
    wrong_key[8] ^= 1;
    assert_eq!(
        client
            .post(&url)
            .header("content-type", wire::CONTENT_TYPE)
            .body(wrong_key.to_vec())
            .send()
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .post(format!("{origin}/v1/attested/evaluate"))
            .body(request.to_vec())
            .send()
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    let old_tls = reqwest::blocking::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert!(old_tls.post(&url).body(request.to_vec()).send().is_err());
}

#[test]
fn failed_worker_startup_cannot_report_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let notify_path = directory.path().join("notify.sock");
    let notification = UnixDatagram::bind(&notify_path).unwrap();
    notification.set_nonblocking(true).unwrap();
    let socket = directory.path().join("worker.sock");
    let valid_key = directory.path().join("evaluation.key");
    let output = Command::new(env!("CARGO_BIN_EXE_leelod"))
        .arg("keygen")
        .arg("--key")
        .arg(&valid_key)
        .output()
        .unwrap();
    assert!(output.status.success());
    std::fs::write(&socket, b"existing path").unwrap();
    for key in [directory.path().join("missing.key"), valid_key] {
        let output = Command::new(env!("CARGO_BIN_EXE_leelod"))
            .arg("worker")
            .arg("--key")
            .arg(key)
            .arg("--socket")
            .arg(&socket)
            .arg("--allow-uid")
            .arg(rustix::process::geteuid().as_raw().to_string())
            .env("NOTIFY_SOCKET", &notify_path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(&socket).unwrap(), b"existing path");
        let error = notification.recv(&mut [0; 32]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[tokio::test]
async fn slow_response_body_obeys_the_complete_request_deadline() {
    use leelo_engine::{NetworkFailure, NetworkProvider};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let directory = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = certificate(directory.path(), "slow-server");
    let ca_pem = std::fs::read(cert_path).unwrap();
    let key_pem = std::fs::read(key_path).unwrap();
    let certificates = CertificateDer::pem_slice_iter(&ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tls_key = PrivateKeyDer::from_pem_slice(&key_pem).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, tls_key)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let key = leelo_crypto::SecretServer::generate().unwrap();
    let public_key = *key.public_key().as_bytes();
    let (_, point) = leelo_crypto::blind(b"complete response deadline").unwrap();
    let response = wire::encode_response(&key.evaluate(&point).unwrap());
    let sent = Arc::new(AtomicUsize::new(0));
    let server_sent = sent.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await?;
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            let byte = tls.read_u8().await?;
            headers.push(byte);
            assert!(headers.len() <= 8192);
        }
        let mut request = [0; wire::REQUEST_BYTES];
        tls.read_exact(&mut request).await?;
        assert_eq!(wire::decode_request(&request).unwrap().point, point);
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            wire::CONTENT_TYPE,
            response.len()
        );
        tls.write_all(headers.as_bytes()).await?;
        tls.flush().await?;
        for byte in &response[..12] {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tls.write_all(&[*byte]).await.is_err() || tls.flush().await.is_err() {
                return Ok::<(), std::io::Error>(());
            }
            server_sent.fetch_add(1, Ordering::SeqCst);
        }
        // A client with no complete-response deadline could accept this valid frame.
        let _ = tls.write_all(&response[12..]).await;
        let _ = tls.shutdown().await;
        Ok(())
    });
    let provider = HttpsNetworkProvider::new(vec![Endpoint {
        provider_id: [7; 32],
        url: format!("https://localhost:{}", address.port()),
        ca_pem,
    }])
    .unwrap();
    let binding = NetworkBinding {
        node_id: 1,
        provider_id: [7; 32],
        key_id: leelo_net::key_id(&public_key),
        public_key,
        input_seed: [8; 32],
    };
    let start = Instant::now();
    let result = provider
        .evaluate(&binding, &point, start + Duration::from_millis(350))
        .await;
    let elapsed = start.elapsed();
    server.abort();
    let _ = server.await;
    assert!(matches!(result, Err(NetworkFailure::Timeout)));
    assert!(
        sent.load(Ordering::SeqCst) > 0,
        "response body did not start"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "deadline elapsed: {elapsed:?}"
    );
}
