//! Only this server module can use the evaluation key.
//! This process uses a different OS account from the TLS frontend.
use leelo_crypto::SecretServer;
use leelo_net::{key_id, wire};
use std::fs::{OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_WORK: usize = 8;
const IPC_DEADLINE: Duration = Duration::from_secs(2);

pub fn keygen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let secret = SecretServer::generate()?;
    let bytes = secret.export_secret_bytes();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes.as_ref())?;
    file.sync_all()?;
    let public = secret.public_key();
    println!(
        "{{\"key_id\":\"{}\",\"public_key\":\"{}\"}}",
        hex::encode(key_id(public.as_bytes())),
        hex::encode(public.as_bytes())
    );
    Ok(())
}

fn load(path: &Path) -> Result<SecretServer, Box<dyn std::error::Error>> {
    let bytes = super::private_file::read(path, 48)?;
    let mut scalar = Zeroizing::new([0; 48]);
    if bytes.len() != scalar.len() {
        return Err("evaluation key must contain exactly 48 bytes".into());
    }
    scalar.copy_from_slice(&bytes);
    Ok(SecretServer::from_secret_bytes(&scalar)?)
}

pub async fn run(
    key: &Path,
    socket: &Path,
    allowed_uid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = Arc::new(load(key)?);
    let parent = socket.parent().ok_or("socket needs a parent directory")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "worker socket directory must be owned by worker UID and not writable by group/other"
                .into(),
        );
    }
    // The worker never removes an existing socket path automatically.
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, Permissions::from_mode(0o660))?;
    serve(listener, secret, allowed_uid).await
}

pub(crate) async fn serve(
    listener: UnixListener,
    secret: Arc<SecretServer>,
    allowed_uid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let permits = Arc::new(Semaphore::new(MAX_WORK));
    let id = key_id(secret.public_key().as_bytes());
    loop {
        let (stream, _) = listener.accept().await?;
        if !matches!(stream.peer_cred(), Ok(credentials) if credentials.uid() == allowed_uid) {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let secret = secret.clone();
        tokio::spawn(async move {
            // The permit also limits all pending reads and CPU evaluation jobs.
            let _permit = permit;
            let _ = tokio::time::timeout(IPC_DEADLINE, handle(stream, secret, id)).await;
        });
    }
}

async fn handle(mut stream: UnixStream, secret: Arc<SecretServer>, id: [u8; 32]) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(wire::REQUEST_BYTES + 1);
    (&mut stream)
        .take((wire::REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    let request = match wire::decode_request(&bytes) {
        Ok(request) if request.key_id == id => request,
        _ => {
            stream.write_all(&[1]).await?;
            return Ok(());
        }
    };
    // A P-384 evaluation does not perform I/O. An attacker cannot change its work size.
    let evaluation = secret.evaluate(&request.point);
    match evaluation {
        Ok(evaluation) => {
            stream.write_all(&[0]).await?;
            stream
                .write_all(&wire::encode_response(&evaluation))
                .await?;
        }
        Err(_) => stream.write_all(&[1]).await?,
    }
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn key_file_rejects_permissions_symlinks_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        keygen(&path).unwrap();
        assert!(load(&path).is_ok());
        assert!(keygen(&path).is_err());
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(load(&path).is_err());
    }

    #[tokio::test]
    async fn socket_refuses_a_different_kernel_uid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let secret = Arc::new(SecretServer::generate().unwrap());
        let forbidden_uid = rustix::process::geteuid().as_raw().wrapping_add(1);
        let task = tokio::spawn(async move {
            let _ = serve(listener, secret, forbidden_uid).await;
        });
        let mut client = UnixStream::connect(path).await.unwrap();
        let mut response = [0; 1];
        let received = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .unwrap();
        assert!(matches!(received, Ok(0) | Err(_)));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn socket_rejects_wrong_mode_key_size_and_point() {
        let secret = Arc::new(SecretServer::generate().unwrap());
        let id = key_id(secret.public_key().as_bytes());
        let (_, point) = leelo_crypto::blind(b"socket regression").unwrap();
        let valid = wire::encode_request(&id, &point);
        let mut wrong_mode = valid.to_vec();
        wrong_mode[6] = 2;
        let mut wrong_key = valid.to_vec();
        wrong_key[8] ^= 1;
        let mut oversized = valid.to_vec();
        oversized.push(0);
        let bad_point = wire::encode_request(&id, &[0; 49]).to_vec();
        for message in [
            wrong_mode,
            wrong_key,
            oversized,
            valid[..88].to_vec(),
            bad_point,
        ] {
            let (mut client, worker) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(worker, secret.clone(), id));
            client.write_all(&message).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, [1]);
            task.await.unwrap().unwrap();
        }
    }
}
