use std::net::SocketAddr;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{debug, info};

use crate::tls;

pub struct ClientOptions {
    pub remote: SocketAddr,
    pub server_name: String,
    pub fingerprint: Option<String>,
    pub bootstrap: Option<Bootstrap>,
}

pub struct Bootstrap {
    pub ssh_target: String,
    pub ssh_port: u16,
}

pub async fn run(opts: ClientOptions) -> Result<()> {
    let fingerprint = match &opts.fingerprint {
        Some(fp) => tls::parse_fingerprint(fp)?,
        None => {
            let bootstrap = opts
                .bootstrap
                .as_ref()
                .context("either --fingerprint or a bootstrap SSH target is required")?;
            let fp = fetch_fingerprint(bootstrap).await?;
            debug!("bootstrapped fingerprint: {}", hex::encode(fp));
            fp
        }
    };

    let client_config = tls::client_config(fingerprint)?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    info!("connecting to {} over QUIC", opts.remote);
    let conn = endpoint
        .connect(opts.remote, &opts.server_name)
        .with_context(|| format!("failed to start QUIC connection to {}", opts.remote))?
        .await
        .context("QUIC handshake failed")?;

    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;

    let to_quic = async {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = stdin.read(&mut buf).await.context("stdin read failed")?;
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

    let to_stdout = async {
        let mut stdout = tokio::io::stdout();
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
            stdout
                .write_all(&buf[..n])
                .await
                .context("stdout write failed")?;
        }
        stdout.flush().await.ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = to_quic => r?,
        r = to_stdout => r?,
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

async fn fetch_fingerprint(bootstrap: &Bootstrap) -> Result<[u8; 32]> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-T")
        .arg("-p")
        .arg(bootstrap.ssh_port.to_string())
        .arg("-o")
        .arg("ProxyCommand=none")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg(&bootstrap.ssh_target)
        .arg("quash server --print-fingerprint")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    debug!("bootstrapping fingerprint via ssh {}", bootstrap.ssh_target);
    let output = cmd.output().await.context("failed to run bootstrap ssh")?;
    if !output.status.success() {
        bail!("bootstrap ssh exited with {}", output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    tls::parse_fingerprint(text.lines().last().unwrap_or_default())
}
