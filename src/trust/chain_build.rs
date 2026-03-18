//! Chain building from a pool of certificates.
//!
//! Given a leaf certificate and an unordered pool of intermediate certificates,
//! build an ordered chain `[leaf, intermediate_0, ..., intermediate_n]` suitable
//! for [`TrustStore::verify_chain()`](super::TrustStore::verify_chain).
//!
//! This is a local-only chain builder (no network fetching). It matches
//! certificates by subject/issuer name and verifies each link's signature
//! before including it in the chain.

use crate::error::TrustError;
use der::Encode;
use x509_cert::Certificate;

/// Build an ordered certificate chain from a leaf to a trust anchor,
/// using a local pool of intermediate certificates.
///
/// The returned chain is ordered `[leaf, intermediate_0, ..., intermediate_n]`
/// and is ready to be passed to [`TrustStore::verify_chain()`](super::TrustStore::verify_chain).
///
/// The function walks from the leaf upward, matching each certificate's issuer
/// name against the subject names of certificates in the pool. At each step,
/// the candidate's signature is verified before it is added to the chain.
///
/// The walk stops when:
/// - A certificate's issuer matches a trust anchor's subject (chain is complete)
/// - A self-signed certificate is reached
/// - No issuer can be found in the pool (returns an error)
/// - The chain exceeds `max_depth` (default 10) to prevent infinite loops
///
/// # Arguments
///
/// * `leaf` — The leaf (end-entity) certificate to start from.
/// * `pool` — Unordered pool of intermediate certificates.
/// * `trust_anchor_subjects` — DER-encoded subject names of trust anchors.
///   Used to know when to stop walking (don't include anchors in the chain).
/// * `max_depth` — Maximum chain length (excluding the leaf). Pass `None` for default (10).
///
/// # Errors
///
/// Returns `TrustError` if no valid chain can be built.
pub fn build_chain_from_pool(
    leaf: &Certificate,
    pool: &[Certificate],
    trust_anchor_subjects: &[Vec<u8>],
    max_depth: Option<usize>,
) -> Result<Vec<Certificate>, TrustError> {
    let max_depth = max_depth.unwrap_or(10);
    let mut chain = vec![leaf.clone()];
    let mut current = leaf.clone();

    // Track visited certs by DER encoding to prevent cycles
    let mut visited: Vec<Vec<u8>> = vec![leaf
        .to_der()
        .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?];

    for _ in 0..max_depth {
        let issuer_name_der = current.tbs_certificate.issuer.to_der().unwrap_or_default();
        let subject_name_der = current.tbs_certificate.subject.to_der().unwrap_or_default();

        // If self-signed, stop (the trust store will handle root matching)
        if issuer_name_der == subject_name_der {
            break;
        }

        // If the issuer matches a trust anchor, we're done — the chain is complete
        if trust_anchor_subjects.iter().any(|s| *s == issuer_name_der) {
            break;
        }

        // Search the pool for an issuer
        let mut found = false;
        for candidate in pool {
            let candidate_der = candidate
                .to_der()
                .map_err(|e| TrustError::CertificateParse(format!("DER encode failed: {e}")))?;

            if visited.contains(&candidate_der) {
                continue; // avoid cycles
            }

            let candidate_subject_der = candidate
                .tbs_certificate
                .subject
                .to_der()
                .unwrap_or_default();

            if candidate_subject_der == issuer_name_der {
                // Verify the signature before accepting this link
                if crate::crypto::verify::verify_certificate_signature(&current, candidate).is_ok()
                {
                    visited.push(candidate_der);
                    chain.push(candidate.clone());
                    current = candidate.clone();
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err(TrustError::ChainBroken {
                index: chain.len() - 1,
                expected_issuer: format!("{}", current.tbs_certificate.issuer),
                found_subject: "no matching certificate in pool".into(),
            });
        }
    }

    Ok(chain)
}

/// Convenience: extract the DER-encoded subject names from a [`TrustStore`](super::TrustStore).
///
/// This is useful for passing to [`build_chain_from_pool`] as the
/// `trust_anchor_subjects` argument.
pub fn trust_anchor_subjects(store: &super::TrustStore) -> Vec<Vec<u8>> {
    store
        .certificates()
        .filter_map(|cert| cert.tbs_certificate.subject.to_der().ok())
        .collect()
}
