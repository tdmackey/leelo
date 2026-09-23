//! This TLS frontend has resource limits and a configured Unix socket.
//! It has no evaluation key object or evaluation secret file path.
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use leelo_net::wire;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

const MAX_CONNECTIONS: usize = 64;
const MAX_PEM_BYTES: usize = 64 * 1024;
const CONNECTION_DEADLINE: Duration = Duration::from_secs(5);
const IPC_DEADLINE: Duration = Duration::from_secs(2);

pub async fn run(
    listen: SocketAddr,
    certificate: &Path,
    tls_key: &Path,
    worker_socket: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let acceptor = tls_config(certificate, tls_key)?;
    let listener = TcpListener::bind(listen).await?;
    serve(listener, acceptor, worker_socket).await
}

pub(crate) fn tls_config(
    certificate: &Path,
    key: &Path,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let mut pem = Vec::new();
    std::fs::File::open(certificate)?
        .take((MAX_PEM_BYTES + 1) as u64)
        .read_to_end(&mut pem)?;
    if pem.len() > MAX_PEM_BYTES {
        return Err("certificate file exceeds size limit".into());
    }
    let certificates = rustls_pemfile::certs(&mut pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
    let key_pem = super::private_file::read(key, MAX_PEM_BYTES)?;
    let key =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("missing TLS private key")?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // This frontend disables TLS 0-RTT. It supports only the network-bound protocol.
    config.max_early_data_size = 0;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(crate) async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    worker_socket: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/v1/evaluate", post(evaluate))
        .with_state(worker_socket);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        // This limit includes connections with incomplete TLS handshakes.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let connection = async {
                let tls =
                    match tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(tls)) => tls,
                        _ => return,
                    };
                let mut http = http1::Builder::new();
                http.keep_alive(false)
                    .max_headers(16)
                    .max_buf_size(8192)
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(2));
                let _ = http
                    .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                    .await;
            };
            let _ = tokio::time::timeout(CONNECTION_DEADLINE, connection).await;
        });
    }
}

async fn evaluate(State(socket): State<PathBuf>, request: Request) -> Response {
    if request.uri().path() != "/v1/evaluate"
        || request.uri().query().is_some()
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some(wire::CONTENT_TYPE)
        || request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
        || request.headers().contains_key(header::CONTENT_ENCODING)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let bytes = match to_bytes(request.into_body(), wire::REQUEST_BYTES).await {
        Ok(bytes) if wire::decode_request(&bytes).is_ok() => bytes,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    match tokio::time::timeout(IPC_DEADLINE, exchange(&socket, &bytes)).await {
        Ok(Ok(response)) => (
            [(header::CONTENT_TYPE, wire::CONTENT_TYPE)],
            Body::from(response),
        )
            .into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn exchange(socket: &Path, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(request).await?;
    stream.shutdown().await?; // Each connection has one request. Shutdown marks its exact end.
    let mut response = Vec::with_capacity(wire::RESPONSE_BYTES + 2);
    stream
        .take((wire::RESPONSE_BYTES + 2) as u64)
        .read_to_end(&mut response)
        .await?;
    if response.len() != wire::RESPONSE_BYTES + 1
        || response[0] != 0
        || wire::decode_response(&response[1..]).is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker refused evaluation",
        ));
    }
    Ok(response[1..].to_vec())
}
