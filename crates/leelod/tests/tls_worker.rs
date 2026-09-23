//! These tests start real worker and frontend child processes in a temporary directory.
//! All connections use loopback. The tests require the openssl executable to configure TLS.
#![cfg(unix)]
use leelo_crypto::ServerPublicKey;
use leelo_envelope::NetworkBinding;
use leelo_net::{Endpoint, HttpsNetworkProvider, wire};
use std::net::{TcpListener, TcpStream};
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
    let mut worker = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_leelod"))
            .arg("worker")
            .arg("--key")
            .arg(&key)
            .arg("--socket")
            .arg(&socket)
            .arg("--allow-uid")
            .arg(rustix::process::geteuid().as_raw().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(worker.0.try_wait().unwrap().is_none(), "worker exited");
        assert!(Instant::now() < deadline, "worker startup timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
    let (cert_path, tls_key) = certificate(directory.path(), "server");
    let ca_pem = std::fs::read(&cert_path).unwrap();
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_leelod"))
            .arg("serve")
            .arg("--listen")
            .arg(address.to_string())
            .arg("--cert")
            .arg(&cert_path)
            .arg("--tls-key")
            .arg(&tls_key)
            .arg("--worker-socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(address).is_err() {
        assert!(server.0.try_wait().unwrap().is_none(), "frontend exited");
        assert!(Instant::now() < deadline, "frontend startup timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
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
