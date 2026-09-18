use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::cert;

pub async fn run(
    listen: SocketAddr,
    proxy_to: SocketAddr,
    cert_dir: &std::path::Path,
) -> Result<()> {
    let identity = cert::load_or_create(cert_dir)?;
    info!("certificate fingerprint: {}", identity.fingerprint_hex());

    let server_config = crate::tls::server_config(&identity)?;
    let endpoint = quinn::Endpoint::server(server_config, listen)
        .with_context(|| format!("failed to bind QUIC endpoint on {listen}"))?;
    info!("listening on {listen}, proxying to {proxy_to}");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    debug!("accepted connection from {}", conn.remote_address());
                    if let Err(err) = serve_connection(conn, proxy_to).await {
                        debug!("connection closed: {err:#}");
                    }
                }
                Err(err) => warn!("handshake failed: {err}"),
            }
        });
    }

    Ok(())
}

async fn serve_connection(conn: quinn::Connection, proxy_to: SocketAddr) -> Result<()> {
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Err(err) = proxy_stream(send, recv, proxy_to).await {
                debug!("stream closed: {err:#}");
            }
        });
    }
    Ok(())
}

async fn proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    proxy_to: SocketAddr,
) -> Result<()> {
    let tcp = TcpStream::connect(proxy_to)
        .await
        .with_context(|| format!("failed to connect to {proxy_to}"))?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let to_remote = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = recv
                .read(&mut buf)
                .await
                .context("quic recv failed")?
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            tcp_write
                .write_all(&buf[..n])
                .await
                .context("tcp write failed")?;
        }
        let _ = tcp_write.shutdown().await;
        Ok::<_, anyhow::Error>(())
    };

    let to_local = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tcp_read.read(&mut buf).await.context("tcp read failed")?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n])
                .await
                .context("quic write failed")?;
        }
        let _ = send.finish();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = to_remote => r?,
        r = to_local => r?,
    }
    Ok(())
}
