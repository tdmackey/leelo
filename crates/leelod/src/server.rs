//! This TLS frontend has resource limits and a configured Unix socket.
//! It has no evaluation key object or evaluation secret file path.
use crate::metrics::{Admission, Metrics, Outcome, Stage};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use leelo_protocol::wire;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::io::Read;
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
    metrics: Arc<Metrics>,
    monitoring: &super::snapshot::Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let acceptor = tls_config(certificate, tls_key).inspect_err(|_| {
        metrics.lifecycle(
            "service_failed",
            "tls_config",
            "failure",
            "invalid_configuration",
        )
    })?;
    let listener = TcpListener::bind(listen).await.inspect_err(|_| {
        metrics.lifecycle("service_failed", "listener", "failure", "bind_failed")
    })?;
    let _exporter = super::snapshot::start_optional(monitoring, metrics.clone(), None);
    super::service::ready().inspect_err(|_| {
        metrics.lifecycle("service_failed", "readiness", "failure", "notify_failed")
    })?;
    metrics.lifecycle("service_ready", "startup", "success", "none");
    serve(listener, acceptor, worker_socket, metrics).await
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
    let certificates = CertificateDer::pem_slice_iter(&pem).collect::<Result<Vec<_>, _>>()?;
    let key_pem = super::private_file::read(key, MAX_PEM_BYTES)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)?;
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
    metrics: Arc<Metrics>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router(worker_socket, metrics.clone());
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) =
            super::service::accept_observed(metrics.clone(), || listener.accept()).await?;
        // This limit includes connections with incomplete TLS handshakes.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            metrics.admission(Admission::Capacity);
            metrics.event("capacity_rejected", "connection", "failure", "capacity");
            continue;
        };
        metrics.admission(Admission::Admitted);
        let inflight = metrics.enter();
        let metrics = metrics.clone();
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _inflight = inflight;
            let timer = metrics.stage(Stage::Connection);
            let connection = async {
                let tls_timer = metrics.stage(Stage::Tls);
                let tls =
                    match tokio::time::timeout(Duration::from_secs(2), acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(tls)) => {
                            tls_timer.finish(Outcome::Success);
                            tls
                        }
                        Ok(Err(_)) => {
                            tls_timer.finish(Outcome::Protocol);
                            return Outcome::Protocol;
                        }
                        Err(_) => {
                            tls_timer.finish(Outcome::Timeout);
                            return Outcome::Timeout;
                        }
                    };
                let mut http = http1::Builder::new();
                http.keep_alive(false)
                    .max_headers(16)
                    .max_buf_size(8192)
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(2));
                match http
                    .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                    .await
                {
                    Ok(()) => Outcome::Success,
                    Err(error) if error.is_timeout() => Outcome::Timeout,
                    Err(error) if error.is_parse() => Outcome::Protocol,
                    Err(error) if error.is_incomplete_message() => Outcome::Eof,
                    Err(_) => Outcome::Io,
                }
            };
            timer.finish(
                match tokio::time::timeout(CONNECTION_DEADLINE, connection).await {
                    Ok(outcome) => outcome,
                    Err(_) => Outcome::Timeout,
                },
            );
        });
    }
}

#[derive(Clone)]
struct AppState {
    socket: PathBuf,
    metrics: Arc<Metrics>,
}

fn router(socket: PathBuf, metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/v1/evaluate", post(evaluate))
        .with_state(AppState {
            socket,
            metrics: metrics.clone(),
        })
        .layer(middleware::from_fn_with_state(metrics, observe_http))
}

async fn observe_http(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let timer = metrics.stage(Stage::Http);
    let response = next.run(request).await;
    metrics.http_status(response.status().as_u16());
    timer.finish(match response.status() {
        StatusCode::OK => Outcome::Success,
        StatusCode::BAD_REQUEST => Outcome::Protocol,
        StatusCode::NOT_FOUND => Outcome::NotFound,
        StatusCode::METHOD_NOT_ALLOWED => Outcome::Method,
        StatusCode::SERVICE_UNAVAILABLE => Outcome::Unavailable,
        _ => Outcome::Other,
    });
    response
}

async fn evaluate(State(state): State<AppState>, request: Request) -> Response {
    let timer = state.metrics.stage(Stage::Validation);
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
        timer.finish(Outcome::Headers);
        return StatusCode::BAD_REQUEST.into_response();
    }
    let bytes = match to_bytes(request.into_body(), wire::REQUEST_BYTES).await {
        Ok(bytes) if wire::decode_request(&bytes).is_ok() => bytes,
        Ok(_) => {
            timer.finish(Outcome::Frame);
            return StatusCode::BAD_REQUEST.into_response();
        }
        Err(_) => {
            timer.finish(Outcome::Body);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    timer.finish(Outcome::Success);
    let timer = state.metrics.stage(Stage::Ipc);
    match tokio::time::timeout(IPC_DEADLINE, exchange(&state.socket, &bytes)).await {
        Ok(Ok(response)) => {
            timer.finish(Outcome::Success);
            (
                [(header::CONTENT_TYPE, wire::CONTENT_TYPE)],
                Body::from(response),
            )
                .into_response()
        }
        result => {
            let reason = match result {
                Ok(Err(reason)) => reason,
                _ => Outcome::Timeout,
            };
            if matches!(reason, Outcome::Frame | Outcome::Eof) {
                state
                    .metrics
                    .event("worker_reply_invalid", "ipc", "failure", "invalid_reply");
            }
            timer.finish(reason);
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn exchange(socket: &Path, request: &[u8]) -> Result<Vec<u8>, Outcome> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| Outcome::Connect)?;
    stream
        .write_all(request)
        .await
        .map_err(|_| Outcome::Write)?;
    stream.shutdown().await.map_err(|_| Outcome::Write)?; // Each connection has one request. Shutdown marks its exact end.
    let mut response = Vec::with_capacity(wire::RESPONSE_BYTES + 2);
    stream
        .take((wire::RESPONSE_BYTES + 2) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|_| Outcome::Read)?;
    if response == [1] {
        return Err(Outcome::Refused);
    }
    if response.is_empty() {
        return Err(Outcome::Eof);
    }
    if response.len() != wire::RESPONSE_BYTES + 1
        || response[0] != 0
        || wire::decode_response(&response[1..]).is_err()
    {
        return Err(Outcome::Frame);
    }
    Ok(response[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Role;
    use tokio::net::UnixListener;
    use tower::ServiceExt;

    #[tokio::test]
    async fn router_errors_and_validation_keep_public_statuses_and_safe_categories() {
        let metrics = Metrics::new(Role::Frontend, 64);
        let app = router(
            PathBuf::from("/missing-leelo-worker-test.sock"),
            metrics.clone(),
        );
        for (method, path, content_type, body, expected) in [
            ("GET", "/missing", None, Vec::new(), 404),
            ("GET", "/v1/evaluate", None, Vec::new(), 405),
            ("POST", "/v1/evaluate", None, Vec::new(), 400),
            (
                "POST",
                "/v1/evaluate",
                Some(wire::CONTENT_TYPE),
                vec![0; wire::REQUEST_BYTES],
                400,
            ),
            (
                "POST",
                "/v1/evaluate",
                Some(wire::CONTENT_TYPE),
                vec![0; wire::REQUEST_BYTES + 1],
                400,
            ),
            (
                "POST",
                "/v1/evaluate",
                Some(wire::CONTENT_TYPE),
                wire::encode_request(&[0; 32], &[0; 49]).to_vec(),
                503,
            ),
        ] {
            let mut request = Request::builder().method(method).uri(path);
            if let Some(content_type) = content_type {
                request = request.header(header::CONTENT_TYPE, content_type);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
        let text = metrics.snapshot();
        for status in [404, 405, 503] {
            assert!(text.contains(&format!(
                "leelo_http_responses_total{{role=\"frontend\",status=\"{status}\"}} 1"
            )));
        }
        for reason in ["invalid_headers", "invalid_frame", "invalid_body"] {
            assert!(text.contains(&format!("stage=\"validation\",outcome=\"{reason}\"}} 1")));
        }
        assert!(text.contains("stage=\"ipc\",outcome=\"connect_error\"} 1"));
    }

    #[tokio::test]
    async fn ipc_refusal_empty_frame_and_bad_frame_remain_distinct_locally() {
        let directory = tempfile::tempdir().unwrap();
        for (index, reply, expected) in [
            (0, vec![1], Outcome::Refused),
            (1, vec![], Outcome::Eof),
            (2, vec![0, 1], Outcome::Frame),
        ] {
            let socket = directory.path().join(format!("{index}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                stream.write_all(&reply).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            assert_eq!(
                exchange(&socket, &[0; wire::REQUEST_BYTES]).await,
                Err(expected)
            );
            task.await.unwrap();
        }
    }
}
