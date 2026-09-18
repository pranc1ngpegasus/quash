use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

impl Identity {
    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.cert_der).into()
    }

    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }
}

pub fn default_cert_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".config")
        });
    base.join("quash")
}

pub fn load_or_create(dir: &Path) -> Result<Identity> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create cert dir {}", dir.display()))?;

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        return Ok(Identity {
            cert_der: read_cert_der(&cert_path)?,
            key_pkcs8_der: read_key_pkcs8_der(&key_path)?,
        });
    }

    let certified = rcgen::generate_simple_self_signed(vec!["quash".to_string()])
        .context("failed to generate self-signed certificate")?;
    let cert_der = certified.cert.der().to_vec();
    let key_pkcs8_der = certified.signing_key.serialize_der();

    std::fs::write(&cert_path, certified.cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    std::fs::write(&key_path, certified.signing_key.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;

    Ok(Identity {
        cert_der,
        key_pkcs8_der,
    })
}

fn read_cert_der(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .context("no certificate found in PEM")?
        .context("failed to parse certificate PEM")?;
    Ok(cert.to_vec())
}

fn read_key_pkcs8_der(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let key = rustls_pemfile::private_key(&mut reader)
        .context("failed to parse private key PEM")?
        .context("no private key found in PEM")?;
    match key {
        rustls::pki_types::PrivateKeyDer::Pkcs8(k) => Ok(k.secret_pkcs8_der().to_vec()),
        _ => bail!("only PKCS#8 private keys are supported"),
    }
}
