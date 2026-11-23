//! The local CA of the proxy. Its key lives only in the vault and in memory; only the
//! certificate goes to disk, for agents to trust. It is valid for one year, its name constraints
//! permit only the bound hosts, and its leaf certificates are valid for one day.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::authority::host_of;
use time::OffsetDateTime;

use crate::ProxyError;

const COMMON_NAME: &str = "CrownOS secrets proxy CA";
const MAX_CACHED_LEAVES: usize = 256;
const AUTHORITY_LIFETIME: time::Duration = time::Duration::days(365);
const LEAF_LIFETIME: time::Duration = time::Duration::hours(24);
const CLOCK_SKEW: time::Duration = time::Duration::hours(1);
/// A cached leaf is made again after half its lifetime.
const LEAF_REUSE: Duration = Duration::from_secs(12 * 60 * 60);

/// A leaf certificate chain and its key, for one host.
pub(crate) struct Leaf {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    key: SecretSlice<u8>,
    made: Instant,
}

impl Leaf {
    pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.expose_secret().to_vec()))
    }
}

pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate: CertificateDer<'static>,
    leaves: Mutex<HashMap<String, Arc<Leaf>>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

/// A new CA with what the vault keeps of it.
#[derive(Debug)]
pub struct GeneratedAuthority {
    pub authority: CertificateAuthority,
    /// PKCS#8.
    pub key: SecretSlice<u8>,
    /// DER.
    pub certificate: Vec<u8>,
    /// Seconds since the Unix epoch.
    pub expires_at: i64,
}

/// The issuer fields depend on nothing but the constants and the key, so a loaded CA signs leaves
/// that chain to the certificate made at generation.
fn authority_parameters() -> CertificateParams {
    let mut parameters = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, COMMON_NAME);
    parameters.distinguished_name = name;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    parameters
}

/// Permitted subtrees for the bound host patterns: the DNS suffix after the last `*`, or the
/// single IP address. `None` when a pattern permits every name, such as `*`.
fn name_constraints(host_patterns: &[String]) -> Option<NameConstraints> {
    let mut permitted = Vec::with_capacity(host_patterns.len());
    for pattern in host_patterns {
        let host = host_of(pattern);
        if let Ok(address) = host.parse::<IpAddr>() {
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            permitted.push(GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                address, prefix,
            )));
            continue;
        }
        let suffix = host
            .rsplit('*')
            .next()
            .unwrap_or(host)
            .trim_start_matches('.');
        if suffix.is_empty() {
            return None;
        }
        permitted.push(GeneralSubtree::DnsName(suffix.to_owned()));
    }
    (!permitted.is_empty()).then_some(NameConstraints {
        permitted_subtrees: permitted,
        excluded_subtrees: Vec::new(),
    })
}

impl CertificateAuthority {
    /// A new CA for one year, constrained to `host_patterns` when that is possible.
    ///
    /// # Errors
    ///
    /// Fails when the key or the certificate cannot be made.
    pub fn generate(host_patterns: &[String]) -> Result<GeneratedAuthority, ProxyError> {
        let key = KeyPair::generate()?;
        let now = OffsetDateTime::now_utc();
        let mut parameters = authority_parameters();
        parameters.not_before = now - CLOCK_SKEW;
        parameters.not_after = now + AUTHORITY_LIFETIME;
        parameters.name_constraints = name_constraints(host_patterns);
        let certificate = parameters.self_signed(&key)?;
        Ok(GeneratedAuthority {
            key: SecretSlice::from(key.serialize_der()),
            certificate: certificate.der().to_vec(),
            expires_at: parameters.not_after.unix_timestamp(),
            authority: Self {
                issuer: Issuer::new(authority_parameters(), key),
                certificate: certificate.der().clone(),
                leaves: Mutex::new(HashMap::new()),
            },
        })
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

    /// A one-day certificate for `host`, signed by this CA, from the cache while it is fresh.
    pub(crate) fn leaf_for(&self, host: &str) -> Result<Arc<Leaf>, ProxyError> {
        if let Ok(leaves) = self.leaves.lock()
            && let Some(leaf) = leaves.get(host)
            && leaf.made.elapsed() < LEAF_REUSE
        {
            return Ok(Arc::clone(leaf));
        }
        let leaf = Arc::new(self.make_leaf(host)?);
        if let Ok(mut leaves) = self.leaves.lock() {
            if leaves.len() >= MAX_CACHED_LEAVES {
                leaves.clear();
            }
            leaves.insert(host.to_owned(), Arc::clone(&leaf));
        }
        Ok(leaf)
    }

    fn make_leaf(&self, host: &str) -> Result<Leaf, ProxyError> {
        let key = KeyPair::generate()?;
        let now = OffsetDateTime::now_utc();
        let mut parameters = CertificateParams::new(vec![host.to_owned()])?;
        parameters.distinguished_name = DistinguishedName::new();
        parameters.distinguished_name.push(DnType::CommonName, host);
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        parameters.use_authority_key_identifier_extension = true;
        parameters.not_before = now - CLOCK_SKEW;
        parameters.not_after = now + LEAF_LIFETIME;
        let certificate = parameters.signed_by(&key, &self.issuer)?;
        Ok(Leaf {
            chain: vec![certificate.der().clone(), self.certificate.clone()],
            key: SecretSlice::from(key.serialize_der()),
            made: Instant::now(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier as _;
    use rustls_pki_types::{ServerName, UnixTime};

    use super::*;

    fn verifies(authority: &GeneratedAuthority, host: &str) -> bool {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(authority.certificate.clone()))
            .unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let leaf = authority.authority.leaf_for(host).unwrap();
        verifier
            .verify_server_cert(
                &leaf.chain[0],
                &leaf.chain[1..],
                &ServerName::try_from(host.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn leaves_verify_only_inside_the_bound_hosts() {
        let authority =
            CertificateAuthority::generate(&["*.github.com".into(), "localhost:8443".into()])
                .unwrap();
        assert!(verifies(&authority, "api.github.com"));
        assert!(verifies(&authority, "localhost"));
        assert!(!verifies(&authority, "bank.example"));
        let year = 365 * 24 * 60 * 60;
        let left = authority.expires_at - OffsetDateTime::now_utc().unix_timestamp();
        assert!((year - 60..=year).contains(&left), "{left}");
    }

    #[test]
    fn a_pattern_for_every_name_gives_no_constraints() {
        assert!(name_constraints(&["*".into()]).is_none());
        assert!(name_constraints(&["127.0.0.1:8443".into()]).is_some());
    }
}
