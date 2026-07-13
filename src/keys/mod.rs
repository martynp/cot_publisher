// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! This module provides an interface for handling PEM-encoded keys and certificates.

use pkcs8::{der::Encode, DecodePrivateKey, Error, PrivateKeyInfo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Source for PEM file data
pub enum Source {
    None,
    File(String),
    String(String),
}

impl Source {
    // Loads file content from the provided source
    pub fn load(&self) -> Result<String, std::io::Error> {
        match self {
            Source::None => Ok(String::new()),
            Source::File(path) => std::fs::read_to_string(path),
            Source::String(content) => Ok(content.clone()),
        }
    }
}

/// MockKey is a simple wrapper around a Vec<u8> to represent a private key.
pub struct MockKey(Vec<u8>);

impl AsRef<[u8]> for MockKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<PrivateKeyInfo<'_>> for MockKey {
    type Error = Error;

    fn try_from(pkcs8: PrivateKeyInfo<'_>) -> Result<MockKey, Error> {
        Ok(MockKey(pkcs8.to_der()?))
    }
}

/// Stores the credentials needed for TLS connections
pub struct Credentials<'a> {
    /// Public certificate in DER format
    pub certificate: CertificateDer<'a>,
    /// Private key in DER format
    pub private_key: PrivateKeyDer<'a>,
    /// Optional server root certificate
    pub root_certs: Option<Vec<CertificateDer<'a>>>,
}

impl<'a> Credentials<'a> {
    /// Creates Credentials from unencrypted PEM strings or files
    ///
    /// # Arguments
    ///
    /// * `certificate` - PEM-encoded certificate or path to certificate file
    /// * `private_key` - PEM-encoded private key or path to private key file
    /// * `root_certs` - Optional PEM-encoded root certificates or path to root certificates file
    ///
    pub fn from_unencrypted_pem(
        certificate: Source,
        private_key: Source,
        root_certs: Option<Source>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // If root certificates are provided, load them
        let root_certs = if let Some(root_source) = root_certs {
            Some(load_root_certificates(&root_source)?)
        } else {
            None
        };

        let certificates = parse_certificates(certificate.load()?)?;
        let certificate = certificates
            .into_iter()
            .next()
            .ok_or("No certificate found")?;

        let key_pem = private_key.load()?;

        // Parse the private key and convert to DER
        // Try PKCS8 format first
        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        let pkcs8_keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .filter_map(Result::ok)
            .collect();

        if let Some(pkcs8_key) = pkcs8_keys.into_iter().next() {
            return Ok(Self {
                certificate,
                private_key: PrivateKeyDer::Pkcs8(pkcs8_key),
                root_certs,
            });
        }

        // Try PKCS1 (RSA) format
        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .filter_map(Result::ok)
            .collect();

        if let Some(rsa_key) = rsa_keys.into_iter().next() {
            return Ok(Self {
                certificate,
                private_key: PrivateKeyDer::Pkcs1(rsa_key),
                root_certs,
            });
        }

        // Try SEC1 (EC) format
        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        let ec_keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut key_reader)
            .filter_map(Result::ok)
            .collect();

        if let Some(ec_key) = ec_keys.into_iter().next() {
            return Ok(Self {
                certificate,
                private_key: PrivateKeyDer::Sec1(ec_key),
                root_certs,
            });
        }

        Err("No valid private key found in the provided PEM".into())
    }

    /// Creates Credentials from encrypted PEM strings or files
    ///
    /// Note: This function currently does not support the Oid used by the default
    /// TakServer client certificates (OID: 1.2.840.113549.3.7). These certificates
    /// should be converted to unencrypted PEM format before use, or re-encrypted using
    /// a supported algorithm (see the pkcs8 crate / const-oid documentation for details).
    ///
    /// # Arguments
    ///
    /// * `certificate` - PEM-encoded certificate or path to certificate file
    /// * `private_key` - PEM-encoded private key or path to private key file
    /// * `root_certs` - Optional PEM-encoded root certificates or path to root certificates file
    /// * `password` - Password to decrypt the private key
    ///
    pub fn from_encrypted_pem(
        certificate: Source,
        private_key: Source,
        root_certs: Option<Source>,
        password: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // If root certificates are provided, load them
        let root_certs = if let Some(root_source) = root_certs {
            Some(load_root_certificates(&root_source)?)
        } else {
            None
        };

        let certificates = parse_certificates(certificate.load()?)?;
        let certificate = certificates
            .into_iter()
            .next()
            .ok_or("No certificate found")?;

        let key_pem = private_key.load()?;
        let decrypted_key = MockKey::from_pkcs8_encrypted_pem(&key_pem, password)
            .map_err(|e| format!("Failed to decrypt private key: {e}"))?;
        let private_key = PrivateKeyDer::try_from(decrypted_key.as_ref().to_owned())?;
        Ok(Self {
            certificate,
            private_key,
            root_certs,
        })
    }
}

/// Parses PEM-encoded certificates from a string
///
/// # Arguments
///
/// * `cert_pem` - PEM-encoded certificate string
///
pub fn parse_certificates<'a>(cert_pem: String) -> Result<Vec<CertificateDer<'a>>, std::io::Error> {
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let mut certs: Vec<CertificateDer<'a>> = Vec::new();
    for cert_result in rustls_pemfile::certs(&mut cert_reader) {
        certs.push(cert_result?);
    }
    Ok(certs)
}

fn load_root_certificates<'a>(source: &Source) -> Result<Vec<CertificateDer<'a>>, std::io::Error> {
    let mut root_certs: Vec<CertificateDer<'a>> = Vec::new();
    let root_cert_pem = source.load()?;
    let mut cert_reader = std::io::BufReader::new(root_cert_pem.as_bytes());
    for cert_result in rustls_pemfile::certs(&mut cert_reader) {
        root_certs.push(cert_result?);
    }

    Ok(root_certs)
}
