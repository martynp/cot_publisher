// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2026 Martyn P <martyn@datasync.dev>

//! This module provides an interface for establishing TCP and TLS connections to TAK servers.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use url::Url;

/// Tak server connection settings
pub struct TakServerSetting<'a> {
    /// Use TLS for the connection
    pub tls: bool,
    /// Optional client credentials for mutual TLS authentication
    pub client_credentials: Option<crate::keys::Credentials<'a>>,
    /// Ignore invalid server certificates (self-signed, expired, hostname mismatch) - WARNING this
    /// disables some protections, but may be necessary for some TAK server configurations
    pub ignore_invalid: bool,
    /// Verify the server hostname against the certificate (Common Name / SAN). When `false`, the
    /// certificate chain of trust and expiry are still validated, but the hostname/SAN match is
    /// skipped - WARNING this disables some protections, but may be necessary for some TAK server
    /// configurations where the server certificate doesn't carry the connecting hostname. This is
    /// distinct from `ignore_invalid`, which skips chain/expiry validation entirely.
    pub verify_hostname: bool,
    /// Automatically reconnect on connection loss
    pub auto_reconnect: bool,
    /// Auto reconnect delay in seconds
    pub reconnect_delay: u64,
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

// Implement AsyncRead for our Connection enum, so callers can split the connection into
// independent read/write halves (needed to observe server traffic during TAK protocol
// negotiation while still being able to write CoT messages)
impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut *self {
            Connection::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Connection::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
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

// Certificate verifier for when verify_hostname is false but ignore_invalid is not set:
// validates the certificate chain of trust and expiry as normal, but deliberately skips the
// hostname/SAN match that `verify_server_name` would otherwise perform.
#[derive(Debug)]
struct ChainOnlyServerCertVerifier {
    roots: RootCertStore,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for ChainOnlyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported_algs.all,
        )?;
        // Deliberately not calling verify_server_name() here - that's the point of this verifier.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

// Main connection initialization method
pub async fn create_connection(
    address: Url,
    settings: &TakServerSetting<'static>,
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

    tcp_stream.set_linger(Some(std::time::Duration::from_secs(2)))?;
    tcp_stream.set_nodelay(true)?;

    if !settings.tls {
        // Plain TCP connection
        return Ok(Connection::Tcp(tcp_stream));
    }

    // Build TLS configuration
    let config = ClientConfig::builder();

    // Parse root certificates from PEM - the root certificates may be provided directly or from the
    // client credentials if a p12 package is used - otherwise the system root store will be used
    let mut root_store = RootCertStore::empty();
    if let Some(client_credentials) = &settings.client_credentials {
        if let Some(root_certs) = &client_credentials.root_certs {
            for cert in root_certs {
                root_store.add(cert.clone()).map_err(|e| {
                    std::io::Error::other(format!(
                        "Failed to add certificates from ClientCredentials to root certificate store: {e}"
                    ))
                })?;
            }
        }
    } else {
        // Load system root certificates if no root certs were provided
        let cert_result = rustls_native_certs::load_native_certs();
        if !cert_result.errors.is_empty() {
            return Err(std::io::Error::other(format!(
                "Failed to load system root certificates: {:?}",
                cert_result.errors
            )));
        }
        for cert in cert_result.certs {
            root_store.add(cert).map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to add system certificate to root certificate store: {e}"
                ))
            })?;
        }
    }

    // Build client config based on whether we have client credentials
    let client_config = if let Some(client_credentials) = &settings.client_credentials {
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
        } else if !settings.verify_hostname {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyServerCertVerifier {
                    roots: root_store,
                    supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                        .signature_verification_algorithms,
                }))
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
        } else if !settings.verify_hostname {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ChainOnlyServerCertVerifier {
                    roots: root_store,
                    supported_algs: rustls::crypto::aws_lc_rs::default_provider()
                        .signature_verification_algorithms,
                }))
                .with_no_client_auth()
        } else {
            config
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    };

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(
        address
            .host_str()
            .ok_or(std::io::Error::other("Host string was missing"))?
            .to_owned(),
    )
    .map_err(|e| std::io::Error::other(format!("Invalid server name: {e}")))?;
    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    Ok(Connection::Tls(tls_stream))
}
