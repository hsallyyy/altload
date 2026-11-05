// Fails the build if anything under src/ could create or revoke a development
// certificate. This build signs only with the certificate iloader already made
// (src/install/identity.rs). A new one would use up the free account's few
// certificate slots, and revoking iloader's would stop the LiveContainer this
// app runs in, along with every app signed with it.
//
// It runs on every `cargo build`, unlike a unit test, and it reads the whole
// src/ tree, so new files are covered too.

use std::path::{Path, PathBuf};

/// isideload calls that request or revoke certificates, and the parts of its
/// signing flow that reach them.
const BANNED: &[&str] = &[
    "CertificateIdentity::retrieve",
    "submit_development_csr",
    "revoke_development_cert",
    "request_certificate",
    "SideloaderBuilder",
    "Sideloader",
    ".sign_app(",
    ".install_app(",
    "MaxCertsBehavior",
];

fn main() {
    println!("cargo:rerun-if-changed=src");

    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    scan(&root.join("src"), &mut found);
    if !found.is_empty() {
        panic!(
            "This build must never create or revoke a certificate, but src/ uses:\n  {}\nSign with the certificate from identity.rs (existing_identity) instead.",
            found.join("\n  ")
        );
    }
}

fn scan(dir: &Path, found: &mut Vec<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("Couldn't read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.unwrap_or_else(|e| panic!("Couldn't read {}: {e}", dir.display())).path();
        if path.is_dir() {
            scan(&path, found);
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("Couldn't read {}: {e}", path.display()));
        for banned in BANNED {
            if bytes.windows(banned.len()).any(|w| w == banned.as_bytes()) {
                found.push(format!("{}: {banned}", path.display()));
            }
        }
    }
}
