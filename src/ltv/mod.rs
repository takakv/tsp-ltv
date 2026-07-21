//! Long-term validation (LTV) support.
//!
//! Provides OCSP, CRL, and certificate chain infrastructure for
//! long-term signature validation across all AdES formats.
//!
//! # Architecture
//!
//! - [`OcspClient`] — Fetches OCSP responses from responders
//! - [`CrlClient`] — Fetches and caches CRLs from distribution points
//! - [`ChainBuilder`] — Discovers intermediate certs via AIA extensions
//! - [`RevocationConfig`] — Configuration for concurrent OCSP + CRL checking
//!
//! # AdES Conformance Levels
//!
//! | Level | LTV Data |
//! |-------|----------|
//! | B-B   | None |
//! | B-T   | Timestamp only |
//! | B-LT  | Certs + OCSP + CRLs |
//! | B-LTA | Above + archive timestamp |

#[cfg(feature = "net")]
pub mod chain;
pub mod crl;
pub mod name_constraints;
pub mod ocsp;
#[cfg(feature = "net")]
pub mod revocation;
pub mod status;
pub mod x509_ext;

// Re-exports
#[cfg(feature = "net")]
pub use chain::ChainBuilder;
#[cfg(feature = "net")]
pub use crl::CrlClient;
// Parsing, request building and verification: no network required.
pub use ocsp::{
    build_ocsp_request_with_nonce, extract_aia_urls, has_ocsp_nocheck_extension,
    parse_ocsp_response, AiaAccessMethod, CertStatus, OcspCheckOutcome, OcspFreshness,
    ParsedBasicOcspResponse, ResponderId, SingleResponse,
};
// Fetching against a live responder.
#[cfg(feature = "net")]
pub use ocsp::{
    check_revocation as ocsp_check_revocation,
    check_revocation_detailed as ocsp_check_revocation_detailed, OcspClient,
};
#[cfg(feature = "blocking")]
#[cfg(feature = "net")]
pub use revocation::check_certificate_revocation_blocking;
#[cfg(feature = "net")]
pub use revocation::{check_certificate_revocation, RevocationConfig};
pub use status::{resolve_priority, RevocationReason, RevocationSource, ValidationStatus};
pub use x509_ext::{
    check_basic_constraints, check_extended_key_usage, check_key_usage, has_extension,
    validate_extensions_for_role, CertRole, KeyUsageBits,
};
