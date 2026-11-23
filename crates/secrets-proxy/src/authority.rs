//! The local CA of the proxy. Its key lives only in the vault and in memory; only the
//! certificate goes to disk, for agents to trust.

use std::collections::HashMap;
use std::sync::Mutex;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use secrecy::{ExposeSecret as _, SecretSlice};

use crate::ProxyError;

const COMMON_NAME: &str = "CrownOS secrets proxy CA";
const MAX_CACHED_LEAVES: usize = 256;

/// A leaf certificate chain and its key, for one host.
pub(crate) struct Leaf {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    key: SecretSlice<u8>,
}

impl Leaf {
    pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.expose_secret().to_vec()))
    }
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate: CertificateDer<'static>,
    leaves: Mutex<HashMap<String, std::sync::Arc<Leaf>>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

/// The issuer fields depend on nothing but the constants and the key, so a loaded CA signs leaves
/// that chain to the certificate made at generation.
fn authority_parameters() -> CertificateParams {
    let mut parameters = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, COMMON_NAME);
    parameters.distinguished_name = name;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    parameters
}

impl CertificateAuthority {
    /// A new CA. Returns it with its private key (PKCS#8) and certificate (DER) for the vault.
    ///
    /// # Errors
    ///
    /// Fails when the key or the certificate cannot be made.
    pub fn generate() -> Result<(Self, SecretSlice<u8>, Vec<u8>), ProxyError> {
        let key = KeyPair::generate()?;
        let certificate = authority_parameters().self_signed(&key)?;
        let key_der = SecretSlice::from(key.serialize_der());
        let certificate_der = certificate.der().to_vec();
        let authority = Self {
            issuer: Issuer::new(authority_parameters(), key),
            certificate: certificate.der().clone(),
            leaves: Mutex::new(HashMap::new()),
        };
        Ok((authority, key_der, certificate_der))
    }

    /// The CA from the key and certificate that [`Self::generate`] returned.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be parsed.
    pub fn load(key_der: &SecretSlice<u8>, certificate_der: &[u8]) -> Result<Self, ProxyError> {
        let key = KeyPair::try_from(key_der.expose_secret())?;
        Ok(Self {
            issuer: Issuer::new(authority_parameters(), key),
            certificate: CertificateDer::from(certificate_der.to_vec()),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn certificate_pem(&self) -> String {
        crate::util::pem::certificate_pem(&self.certificate)
    }

    /// A certificate for `host`, signed by this CA, from the cache when possible.
    pub(crate) fn leaf_for(&self, host: &str) -> Result<std::sync::Arc<Leaf>, ProxyError> {
        if let Ok(leaves) = self.leaves.lock()
            && let Some(leaf) = leaves.get(host)
        {
            return Ok(std::sync::Arc::clone(leaf));
        }
        let key = KeyPair::generate()?;
        let mut parameters = CertificateParams::new(vec![host.to_owned()])?;
        parameters.distinguished_name = DistinguishedName::new();
        parameters.distinguished_name.push(DnType::CommonName, host);
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        parameters.use_authority_key_identifier_extension = true;
        let certificate = parameters.signed_by(&key, &self.issuer)?;
        let leaf = std::sync::Arc::new(Leaf {
            chain: vec![certificate.der().clone(), self.certificate.clone()],
            key: SecretSlice::from(key.serialize_der()),
        });
        if let Ok(mut leaves) = self.leaves.lock() {
            if leaves.len() >= MAX_CACHED_LEAVES {
                leaves.clear();
            }
            leaves.insert(host.to_owned(), std::sync::Arc::clone(&leaf));
        }
        Ok(leaf)
    }
}
