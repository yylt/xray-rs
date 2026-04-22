use rustls::{
    crypto::{CryptoProvider, GetRandomFailed},
    pki_types,
    server::{ProducesTickets, ServerConfig},
    ticketer::TicketRotator,
    ClientConfig, RootCertStore, SupportedCipherSuite,
};
use serde::{Deserialize, Serialize};

use crate::common;
use std::{
    io::{Error, ErrorKind, Result},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    client::TlsStream as ClientTlsStream, server::TlsStream as ServerTlsStream, TlsAcceptor, TlsConnector,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(rename = "serverName")]
    pub server_name: Option<String>,

    #[serde(rename = "alpn")]
    alpn_protocols: Option<Vec<String>>,

    #[serde(rename = "allowInsecure")]
    pub allow_insecure: Option<bool>,

    #[serde(rename = "cipherSuites")]
    cipher_suites: Option<Vec<String>>,

    #[serde(rename = "certificates")]
    certificates: Option<Vec<Certificate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "keyFile")]
    key_file: String,
    #[serde(rename = "certFile", alias = "certificateFile")]
    cert_file: String,
}

fn resolve_cipher_suites(provider: &CryptoProvider, configured_suites: &[String]) -> Result<Vec<SupportedCipherSuite>> {
    if configured_suites.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "tlsSettings.cipherSuites must not be empty",
        ));
    }

    configured_suites
        .iter()
        .map(|configured_suite| {
            let suite_name = configured_suite.trim();
            provider
                .cipher_suites
                .iter()
                .copied()
                .find(|suite| suite.suite().as_str() == Some(suite_name))
                .ok_or_else(|| {
                    let supported_suites = provider
                        .cipher_suites
                        .iter()
                        .filter_map(|suite| suite.suite().as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "Unsupported tlsSettings.cipherSuites value `{}`. Supported values: {}",
                            configured_suite, supported_suites
                        ),
                    )
                })
        })
        .collect()
}

fn create_crypto_provider(settings: &TlsSettings) -> Result<Option<Arc<CryptoProvider>>> {
    let Some(configured_suites) = settings.cipher_suites.as_ref() else {
        return Ok(None);
    };

    let mut provider = ClientConfig::builder().crypto_provider().as_ref().clone();
    provider.cipher_suites = resolve_cipher_suites(&provider, configured_suites)?;

    Ok(Some(Arc::new(provider)))
}

fn create_server_config(settings: &TlsSettings) -> Result<ServerConfig> {
    let mut cert_resolver = common::tls::CertificateResolver::new();
    if let Some(cert_configs) = &settings.certificates {
        for cert_config in cert_configs.iter() {
            cert_resolver.add_certificate(&cert_config.cert_file, &cert_config.key_file)?;
        }
    } else {
        cert_resolver.add_self_signed_certificate();
    }

    let builder = if let Some(provider) = create_crypto_provider(settings)? {
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to apply tlsSettings.cipherSuites: {:?}", e),
                )
            })?
    } else {
        ServerConfig::builder()
    };

    let mut config = builder
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver));

    config.alpn_protocols = if let Some(alpn_protocols) = &settings.alpn_protocols {
        alpn_protocols.iter().map(|p| p.as_bytes().to_vec()).collect()
    } else {
        vec![
            b"h2".to_vec(),       // HTTP/2
            b"http/1.1".to_vec(), // HTTP/1.1
        ]
    };

    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

    let ticket_generator = || {
        let generator = common::tls::SecureTicketGenerator::new().map_err(|_| GetRandomFailed)?;
        Ok(Box::new(generator) as Box<dyn ProducesTickets>)
    };

    config.ticketer = Arc::new(
        TicketRotator::new(3600, ticket_generator)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create ticket rotator: {:?}", e)))?,
    );

    Ok(config)
}

fn create_client_config(settings: &TlsSettings) -> Result<ClientConfig> {
    let mut root_cert_store = RootCertStore::empty();
    let cert_result = rustls_native_certs::load_native_certs();

    if !cert_result.errors.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to load some native certs: {:?}", cert_result.errors),
        ));
    }

    for cert in cert_result.certs {
        root_cert_store
            .add(cert)
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to add cert: {:?}", e)))?;
    }

    let builder = if let Some(provider) = create_crypto_provider(settings)? {
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to apply tlsSettings.cipherSuites: {:?}", e),
                )
            })?
    } else {
        ClientConfig::builder()
    };

    let mut config = if settings.allow_insecure.map_or(false, |v| v) {
        let builder = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(common::tls::NoCertificateVerification));
        builder.with_no_client_auth()
    } else {
        builder.with_root_certificates(root_cert_store).with_no_client_auth()
    };

    if let Some(alpn_protocols) = &settings.alpn_protocols {
        config.alpn_protocols = alpn_protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
    } else {
        config.alpn_protocols = vec![
            b"h3".to_vec(),       // HTTP/3
            b"h2".to_vec(),       // HTTP/2
            b"http/1.1".to_vec(), // HTTP/1.1
        ];
    }
    config.enable_secret_extraction = true;
    config.enable_sni = true;
    config.resumption = rustls::client::Resumption::in_memory_sessions(256);

    Ok(config)
}

pub mod client {
    use super::*;

    #[derive(Clone)]
    pub struct Tls {
        connector: TlsConnector,
        server_name: Option<String>,
    }
    pub fn new(value: &TlsSettings) -> Result<Tls> {
        let tlsconnect = create_client_config(value).map(|cfg| {
            let arc_cfg = Arc::new(cfg);
            TlsConnector::from(arc_cfg)
        })?;
        Ok(Tls {
            server_name: value.server_name.clone(),
            connector: tlsconnect,
        })
    }
    impl Tls {
        pub async fn connect<IO>(&self, addr: &std::net::SocketAddr, stream: IO) -> Result<ClientTlsStream<IO>>
        where
            IO: AsyncRead + AsyncWrite + Unpin,
        {
            let server_name = if let Some(name) = &self.server_name {
                name.clone()
            } else {
                match addr {
                    std::net::SocketAddr::V4(v4) => v4.ip().to_string(),
                    std::net::SocketAddr::V6(v6) => v6.ip().to_string(),
                }
            };
            let tls_server_name = pki_types::ServerName::try_from(server_name)
                .map_err(|_| Error::new(ErrorKind::AddrNotAvailable, "not invalid server name"))?;
            Ok(self.connector.connect(tls_server_name, stream).await?)
        }
    }
}

pub mod server {
    use super::*;
    #[derive(Clone)]
    pub struct Tls {
        acceptor: TlsAcceptor,
    }
    pub fn new(value: &TlsSettings) -> Result<Tls> {
        let tlsacceptor = create_server_config(value).map(|cfg| {
            let arc_cfg = Arc::new(cfg);
            TlsAcceptor::from(arc_cfg)
        })?;
        Ok(Tls { acceptor: tlsacceptor })
    }

    impl Tls {
        pub async fn accept<IO>(&self, stream: IO) -> Result<ServerTlsStream<IO>>
        where
            IO: AsyncRead + AsyncWrite + Unpin,
        {
            let tls_stream = self.acceptor.accept(stream).await?;
            Ok(tls_stream)
        }
    }
}
