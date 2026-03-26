use ahash::RandomState;
use rcgen::generate_simple_self_signed;
use rustls::{
    crypto::CryptoProvider,
    crypto::GetRandomFailed,
    pki_types::*,
    server::{ClientHello, ProducesTickets, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Error, ErrorKind, Result as IoResult},
    path::Path,
    result::Result,
    sync::Arc,
};

use x509_parser::prelude::*;

use rand;
use ring::aead;

#[derive(Debug, Clone)]
pub struct SecureTicketGenerator {
    current_key: aead::LessSafeKey,
    previous_key: Option<aead::LessSafeKey>,
    key_version: u32,
    lifetime: u32,
}

impl SecureTicketGenerator {
    pub fn new() -> Result<Self, GetRandomFailed> {
        let key_bytes: [u8; 32] = rand::random();
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).map_err(|_| GetRandomFailed)?;
        let current_key = aead::LessSafeKey::new(unbound_key);

        Ok(Self {
            current_key,
            previous_key: None,
            key_version: 1,
            lifetime: 3600,
        })
    }
}

impl ProducesTickets for SecureTicketGenerator {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let nonce: [u8; 12] = rand::random();
        let mut in_out = plaintext.to_vec();

        // 添加版本信息
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.key_version.to_be_bytes());
        payload.extend_from_slice(&in_out);

        in_out = payload;

        let aad = aead::Aad::empty();

        self.current_key
            .seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aad, &mut in_out)
            .ok()?;

        // 组合 nonce + 密文
        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&in_out);
        Some(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            // nonce + 最小密文长度
            return None;
        }

        let nonce = &ciphertext[0..12];
        let mut data = ciphertext[12..].to_vec();

        let aad = aead::Aad::empty();
        if self
            .current_key
            .open_in_place(aead::Nonce::try_assume_unique_for_key(nonce).ok()?, aad, &mut data)
            .is_ok()
        {
            if data.len() >= 4 {
                let _version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                return Some(data[4..].to_vec());
            }
        }

        if let Some(prev_key) = &self.previous_key {
            let mut data = ciphertext[12..].to_vec();
            if prev_key
                .open_in_place(aead::Nonce::try_assume_unique_for_key(nonce).ok()?, aad, &mut data)
                .is_ok()
            {
                if data.len() >= 4 {
                    let _version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(data[4..].to_vec());
                }
            }
        }

        None
    }
}

#[derive(Debug)]
pub struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            // TLS 1.3
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
}

pub fn read_certificates<P: AsRef<Path>>(path: P) -> IoResult<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    Ok(certs)
}

pub fn read_private_key<P: AsRef<Path>>(path: P) -> IoResult<PrivateKeyDer<'static>> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("No private key found in file: {}", path.as_ref().display()),
        )
    })
}

#[derive(Debug, Clone)]
pub struct CertificateResolver {
    // 精确域名匹配: domain -> certificate
    exact_domains: HashMap<String, Arc<CertifiedKey>, RandomState>,
    // 泛域名匹配: base_domain -> certificate (如 "example.com" 对应 "*.example.com")
    wildcard_domains: HashMap<String, Arc<CertifiedKey>, RandomState>,
    // 默认证书
    default: Option<Arc<CertifiedKey>>,
}

impl CertificateResolver {
    pub fn new() -> Self {
        Self {
            exact_domains: HashMap::with_hasher(RandomState::new()),
            wildcard_domains: HashMap::with_hasher(RandomState::new()),
            default: None,
        }
    }

    pub fn add_certificate(&mut self, cert_file: &str, key_file: &str) -> IoResult<()> {
        // 读取证书和密钥
        let certs = read_certificates(cert_file)?;
        let key = read_private_key(key_file)?;

        // 使用默认的 CryptoProvider 创建 CertifiedKey
        let provider = CryptoProvider::get_default()
            .ok_or_else(|| Error::new(ErrorKind::Other, "No default crypto provider available"))?;

        let certified_key = Arc::new(
            CertifiedKey::from_der(certs.clone(), key, provider)
                .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create certified key: {:?}", e)))?,
        );

        // 解析证书中的域名
        let domains = self.extract_domains_from_cert(&certs[0])?;

        let mut has_exact_domain = false;
        let mut has_wildcard_domain = false;

        for domain in domains {
            if domain.starts_with("*.") {
                // 泛域名
                let base_domain = domain.trim_start_matches("*.").to_string();
                self.wildcard_domains.insert(base_domain, certified_key.clone());
                has_wildcard_domain = true;
            } else {
                // 精确域名
                self.exact_domains.insert(domain, certified_key.clone());
                has_exact_domain = true;
            }
        }

        // 如果没有找到任何域名，或者这是第一个证书，设置为默认证书
        if (!has_exact_domain && !has_wildcard_domain) || self.default.is_none() {
            self.default = Some(certified_key);
        }

        Ok(())
    }

    pub fn add_self_signed_certificate(&mut self) {
        let subject_alt_names = vec!["localhost".to_string()];
        let rcgen_cert_key = generate_simple_self_signed(subject_alt_names).unwrap();

        // 将 rcgen 的证书转换为 rustls 的格式
        let cert_der = rcgen_cert_key.cert.der().clone();

        // 先获取 serialized_der 的所有权
        let key_bytes = rcgen_cert_key.signing_key.serialized_der().to_vec();
        let key_der = PrivateKeyDer::try_from(key_bytes).expect("Failed to convert signing key");

        // 使用默认的 CryptoProvider 创建 CertifiedKey
        let provider = CryptoProvider::get_default().expect("No default crypto provider available");

        let certified_key = CertifiedKey::from_der(vec![cert_der], key_der, provider)
            .expect("Failed to create self-signed certificate");

        self.default = Some(Arc::new(certified_key));
    }

    /// 从证书中提取所有域名
    fn extract_domains_from_cert(&self, cert: &CertificateDer<'static>) -> IoResult<Vec<String>> {
        let (_, x509_cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse certificate: {}", e)))?;

        let mut domains = Vec::new();

        for rdn in x509_cert.subject().iter_common_name() {
            domains.push(
                rdn.as_str()
                    .map_err(|e| Error::new(ErrorKind::InvalidData, format!("Failed to parse CN: {:?}", e)))?
                    .to_string(),
            );
        }
        if let Ok(Some(san_extension)) = x509_cert.subject_alternative_name() {
            for name in &san_extension.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    domains.push(dns.to_string());
                }
            }
        }

        Ok(domains)
    }

    /// 查找匹配的证书
    fn find_certificate(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // 1. 首先尝试精确匹配
        if let Some(cert) = self.exact_domains.get(domain) {
            return Some(cert.clone());
        }

        // 2. 尝试泛域名匹配
        let domain_parts: Vec<&str> = domain.split('.').collect();

        // 从右向左尝试匹配泛域名
        for i in 1..domain_parts.len() {
            let base_domain = domain_parts[i..].join(".");
            if let Some(cert) = self.wildcard_domains.get(&base_domain) {
                return Some(cert.clone());
            }
        }

        None
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            if let Some(cert) = self.find_certificate(server_name) {
                return Some(cert);
            }
        }
        self.default.clone()
    }
}
