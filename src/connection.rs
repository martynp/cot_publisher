// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Martyn P <martyn@datasync.dev>

//! This module provides an interface for establishing TCP and TLS connections to TAK servers.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use url::Url;

/// Tak server connection settings
pub struct TakServerSetting<'a> {
    /// Use TLS for the connection
    pub tls: bool,
    /// Optional client credentials for mutual TLS authentication
    pub client_credentials: Option<crate::keys::Credentials<'a>>,
    /// Optional root certificate source for server certificate validation
    pub root_cert: Option<crate::keys::Source>,
    /// Ignore invalid server certificates (self-signed, expired, hostname mismatch) - WARNING this
    /// disables some protections, but may be necessary for some TAK server configurations
    pub ignore_invalid: bool,
    /// Verify the server hostname against the certificate (Common Name / SAN) - WARNING this disables
    /// some protections, but may be necessary for some TAK server configurations
    pub verify_hostname: bool,
    /// Automatically reconnect on connection loss
    pub auto_reconnect: bool,
}

/// Enum to handle different connection types
#[allow(clippy::large_enum_variant)]
pub enum Connection {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
}

// Implement AsyncWrite for our Connection enum
impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match &mut *self {
            Connection::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Connection::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut *self {
            Connection::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Connection::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut *self {
            Connection::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Connection::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

// Custom certificate verifier for when ignore_invalid is true
#[derive(Debug)]
struct DangerousAcceptAnyServerCertVerifier;

impl ServerCertVerifier for DangerousAcceptAnyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

// Main connection initialization method
pub async fn create_connection(
    address: Url,
    settings: TakServerSetting<'static>,
) -> Result<Connection, std::io::Error> {
    // Establish TCP connection first
    let tcp_stream = TcpStream::connect(&format!(
        "{}:{}",
        address
            .host_str()
            .ok_or(std::io::Error::other("Host string was missing"))?,
        address
            .port()
            .ok_or(std::io::Error::other("Port number was missing"))?
    ))
    .await?;

    if !settings.tls {
        // Plain TCP connection
        return Ok(Connection::Tcp(tcp_stream));
    }

    // Build TLS configuration
    let config = ClientConfig::builder();

    // Parse root certificate from PEM - the root certificate may be provided directly or from the
    // client credentials if a p12 package is used
    let mut root_store = RootCertStore::empty();
    let root_certs = if let Some(root_cert_source) = settings.root_cert {
        crate::keys::parse_certificates(root_cert_source.load()?)?
    } else if let Some(client_creds) = &settings.client_credentials {
        client_creds.root_cert.clone().ok_or(std::io::Error::other(
            "No root certificate provided for TLS connection",
        ))?
    } else {
        return Err(std::io::Error::other(
            "No root certificate provided for TLS connection",
        ));
    };

    for cert in root_certs {
        root_store.add(cert).map_err(|e| {
            std::io::Error::other(format!(
                "Failed to add certificate to root certificate store: {e}"
            ))
        })?;
    }

    // Build client config based on whether we have client credentials
    let client_config = if let Some(client_credentials) = settings.client_credentials {
        // Mutual TLS configuration
        let client_certs = vec![client_credentials.certificate.to_owned()];
        let private_key = client_credentials.private_key.clone_key();

        // Build config with client authentication
        if settings.ignore_invalid {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousAcceptAnyServerCertVerifier))
                .with_client_auth_cert(client_certs, private_key)
                .map_err(|e| std::io::Error::other(format!("Failed to build client config: {e}")))?
        } else {
            config
                .with_root_certificates(root_store)
                .with_client_auth_cert(client_certs, private_key)
                .map_err(|e| std::io::Error::other(format!("Failed to build client config: {e}")))?
        }
    } else {
        // Regular TLS configuration (no client auth)
        if settings.ignore_invalid {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousAcceptAnyServerCertVerifier))
                .with_no_client_auth()
        } else {
            config
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(address.host_str().unwrap().to_owned())
        .map_err(|e| std::io::Error::other(format!("Invalid server name: {e}")))?;
    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    Ok(Connection::Tls(tls_stream))
}
