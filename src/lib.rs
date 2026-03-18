//! # tsp-ltv
//!
//! Shared timestamping (RFC 3161) and long-term validation infrastructure
//! for Advanced Electronic Signature (AdES) formats.
//!
//! This crate provides the core types and network clients for:
//! - **TSP**: RFC 3161 timestamp requests, responses, and validation
//! - **OCSP**: Online Certificate Status Protocol client (RFC 6960)
//! - **CRL**: Certificate Revocation List fetching and caching (RFC 5280)
//! - **Trust**: Certificate trust stores, chain building, and validation
//!
//! It is format-agnostic — it does not know about PDF, XML, or JSON.
//! Each AdES crate (underskrift for PAdES/CAdES, bergshamra for XAdES,
//! jades for JAdES) builds its own format-specific embedding on top
//! of these shared clients.

// Always-compiled modules
pub mod crypto;
pub mod der_utils;
pub mod error;
pub mod trust;

// Feature-gated modules
#[cfg(feature = "tsp")]
pub mod tsp;

#[cfg(feature = "ltv")]
pub mod ltv;
