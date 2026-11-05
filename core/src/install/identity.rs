// Signing only with the certificate iloader already made on the PC.
//
// iloader's private key is imported once per Apple ID (the .p12 LiveContainer
// signs its guests with, or iloader's raw key file) and kept the way isideload
// keeps keys: "<sha256(lowercased Apple ID)>/key", base64 PKCS#8 DER, here in
// Application Support/AltLoad/iloader-key. The certificate is then found on the
// Apple account by its public key. Nothing in this build creates or revokes a
// certificate (build.rs fails the build if anything tries): when iloader's
// certificate is gone, installs and refreshes stop and say why.

use super::*;
use base64::prelude::*;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use x509_cert::der::Decode;
use x509_cert::Certificate;

const NO_KEY: &str = "No iloader key is imported for this Apple ID. Import the .p12 LiveContainer signs with (or iloader's key file) first: Reloader only signs with the certificate iloader made and never makes one of its own.";

const NOT_ON_ACCOUNT: &str = "Your iloader certificate isn't on this Apple ID any more (revoked or expired), or the imported key belongs to another Apple ID. Reloader never creates or revokes certificates. Install once with iloader on the PC: while iloader still has its key it makes a new certificate with that key, and Reloader finds it on the next try. If iloader made a new key instead, rebuild the .p12 and import it again on each device.";

const NOT_A_KEY: &str = "That isn't an RSA private key. For a .p12, enter its password.";

/// isideload's storage name for an Apple ID's private key, "<hex sha256(email)>/key"
/// (cert_identity.rs, retrieve_private_key). iloader hashes the lowercased email.
pub(super) fn key_name(apple_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(apple_id.trim().to_lowercase().as_bytes());
    format!("{}/key", hex::encode(hasher.finalize()))
}

/// Only the imported key, in a folder of its own: a key an upstream AltLoad build
/// generated (in signing/) must never pass for iloader's. No Keychain fallback.
fn key_storage() -> FileStorage {
    FileStorage::new("iloader-key", None)
}

/// The imported key for `apple_id`. Offline, so installs and refreshes check it
/// before anything is sent to Apple.
pub(super) fn imported_key(apple_id: &str) -> Result<RsaPrivateKey, String> {
    let der = key_storage()
        .retrieve_data(&key_name(apple_id))
        .map_err(|e| err("Couldn't read the imported iloader key", e))?
        .ok_or(NO_KEY)?;
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|e| err("The imported iloader key is damaged. Import it again", e))
}

/// The RSA public key as a certificate carries it (PKCS#1 inside the SPKI bit
/// string), the comparison isideload's own certificate lookup makes.
fn public_key_der(key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    key.to_public_key()
        .to_pkcs1_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| err("Couldn't read the key's public half", e))
}

fn cert_public_key(cert: &Certificate) -> Option<&[u8]> {
    cert.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes()
}

/// The serial as the developer portal and ALTCertificateID write it.
fn serial_of(cert: &Certificate) -> String {
    hex::encode_upper(cert.tbs_certificate.serial_number.as_bytes())
        .trim_start_matches('0')
        .to_string()
}

fn expires_of(cert: &Certificate) -> i64 {
    cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64
}

/// Short enough to compare by eye: the first 8 bytes of the public key's SHA-256.
fn fingerprint(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hex::encode_upper(&hasher.finalize()[..8])
}

/// A .p12 (with its password) or a raw RSA key: PKCS#8 DER (iloader's key), PKCS#1
/// DER, PEM, or bare base64 text.
fn parse_key(bytes: &[u8], password: Option<&str>) -> Result<(RsaPrivateKey, Option<Certificate>), String> {
    if let Some(password) = password.filter(|p| !p.is_empty()) {
        return match from_p12(bytes, password) {
            Ok(found) => Ok(found),
            // A raw key file with a password typed in anyway still imports.
            Err(e) => raw_key(bytes).map(|key| (key, None)).ok_or(e),
        };
    }
    if let Some(key) = raw_key(bytes) {
        return Ok((key, None));
    }
    // A .p12 exported without a password.
    from_p12(bytes, "").map_err(|_| NOT_A_KEY.to_string())
}

fn from_p12(bytes: &[u8], password: &str) -> Result<(RsaPrivateKey, Option<Certificate>), String> {
    let store = p12_keystore::KeyStore::from_pkcs12(bytes, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| err("Couldn't open the .p12 (is the password right?)", e))?;
    let (_, chain) = store.private_key_chain().ok_or("The .p12 has no private key in it.")?;
    let key = RsaPrivateKey::from_pkcs8_der(chain.key().as_der())
        .map_err(|e| err("The .p12's private key isn't an RSA key", e))?;
    let cert = chain.certs().first().and_then(|c| Certificate::from_der(c.as_der()).ok());
    Ok((key, cert))
}

fn raw_key(bytes: &[u8]) -> Option<RsaPrivateKey> {
    key_candidates(bytes).iter().find_map(|der| {
        RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
            .ok()
    })
}

/// The bytes as they are (DER), plus what the base64 in them decodes to when they're
/// text: PEM without its BEGIN/END lines, or bare base64 as isideload stores keys.
fn key_candidates(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut candidates = vec![bytes.to_vec()];
    if let Ok(text) = std::str::from_utf8(bytes) {
        let body: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("-----"))
            .flat_map(str::chars)
            .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\0')
            .collect();
        if let Ok(decoded) = BASE64_STANDARD.decode(body) {
            candidates.push(decoded);
        }
    }
    candidates
}

/// Saves iloader's key for `apple_id`. Offline: nothing is sent anywhere.
pub(super) fn import_key(apple_id: &str, bytes: &[u8], password: Option<&str>) -> Result<serde_json::Value, String> {
    if apple_id.trim().is_empty() {
        return Err("Enter the Apple ID iloader signs with.".to_string());
    }
    let (key, cert) = parse_key(bytes, password)?;
    let public_key = public_key_der(&key)?;
    if let Some(cert) = &cert {
        if cert_public_key(cert) != Some(public_key.as_slice()) {
            return Err("The certificate in this .p12 doesn't belong to its private key.".to_string());
        }
    }
    let der = key.to_pkcs8_der().map_err(|e| err("Couldn't encode the key", e))?;
    key_storage()
        .store_data(&key_name(apple_id), der.as_bytes())
        .map_err(|e| err("Couldn't save the key", e))?;
    Ok(import_json(&public_key, cert.as_ref()))
}

fn import_json(public_key: &[u8], cert: Option<&Certificate>) -> serde_json::Value {
    serde_json::json!({
        "fingerprint": fingerprint(public_key),
        "certificateSerial": cert.map(serial_of),
        "certificateExpires": cert.map(expires_of),
    })
}

/// iloader's certificate for the imported key, as it is on the account now: the
/// unexpired iOS development certificate with the key's public key. Never creates
/// or revokes one.
pub(super) async fn existing_identity(
    dev: &mut DeveloperSession,
    team: &DeveloperTeam,
    apple_id: &str,
) -> Result<CertificateIdentity, String> {
    let private_key = imported_key(apple_id)?;
    let public_key = public_key_der(&private_key)?;
    let now = unix_now();

    let found = dev
        .list_ios_certs(team)
        .await
        .map_err(|e| err("Couldn't list your certificates", e))?
        .into_iter()
        .filter(|c| c.status.as_deref().map_or(true, |s| !s.eq_ignore_ascii_case("revoked")))
        .filter_map(|c| {
            let x509 = Certificate::from_der(c.cert_content.as_ref()?.as_ref()).ok()?;
            let same_key = cert_public_key(&x509) == Some(public_key.as_slice());
            same_key.then_some((c, x509))
        })
        .filter(|(_, x509)| expires_of(x509) > now)
        .max_by_key(|(_, x509)| expires_of(x509));
    let Some((portal, certificate)) = found else {
        return Err(NOT_ON_ACCOUNT.to_string());
    };

    // ALTCertificate.p12 is encrypted with this, and SideStore opens it with the
    // portal's machineIdentifier, so it has to be Apple's value for this certificate.
    let machine_id = portal
        .machine_id
        .clone()
        .filter(|m| !m.is_empty())
        .ok_or("Apple didn't send the iloader certificate's machine ID. Try again.")?;
    Ok(CertificateIdentity {
        machine_id,
        machine_name: portal.machine_name.clone().unwrap_or_default(),
        private_key,
        certificate,
    })
}

// MARK: - FFI

/// Saves iloader's key for `apple_id`: a .p12 (password required) or a raw key
/// (password NULL). Offline. Returns 0 with
/// {"fingerprint","certificateSerial","certificateExpires"} in `*out_json`, or 1
/// with an error message. Free with `altload_string_free`.
#[no_mangle]
pub unsafe extern "C" fn altload_import_signing_key(
    apple_id: *const c_char,
    data: *const u8,
    len: usize,
    password: *const c_char,
    out_json: *mut *mut c_char,
) -> i32 {
    if out_json.is_null() {
        return 2;
    }
    *out_json = ptr::null_mut();

    let fail = |msg: String| -> i32 {
        *out_json = cstr(msg);
        1
    };
    let apple_id = match req(apple_id, "Apple ID") { Ok(v) => v, Err(e) => return fail(e) };
    if data.is_null() || len == 0 {
        return fail("The file is empty.".to_string());
    }
    let password = if password.is_null() { None } else { CStr::from_ptr(password).to_str().ok() };

    match import_key(&apple_id, std::slice::from_raw_parts(data, len), password) {
        Ok(json) => {
            *out_json = cstr(json.to_string());
            0
        }
        Err(e) => fail(e),
    }
}

/// 1 if a key is imported for `apple_id` (any case), else 0.
#[no_mangle]
pub unsafe extern "C" fn altload_has_signing_key(apple_id: *const c_char) -> i32 {
    match req(apple_id, "Apple ID") {
        Ok(id) => imported_key(&id).is_ok() as i32,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn key_name_is_isideloads_for_the_lowercased_email() {
        assert_eq!(key_name(" Me@Example.com "), key_name("me@example.com"));
        let name = key_name("me@example.com");
        assert!(name.ends_with("/key"));
        assert_eq!(name.len(), 64 + "/key".len());
        assert!(name[..64].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn pem_and_base64_text_decode_to_the_der_inside() {
        let der = vec![0x30, 0x82, 0x01, 0x02, 0xff, 0x00, 0x7f];
        let b64 = BASE64_STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n{}\n-----END PRIVATE KEY-----\n", &b64[..4], &b64[4..]);
        assert!(key_candidates(pem.as_bytes()).contains(&der));
        assert!(key_candidates(format!("\"{b64}\"\r\n").as_bytes()).contains(&der));
        assert_eq!(key_candidates(&der)[0], der);
    }

    #[test]
    fn something_else_is_refused_with_a_hint() {
        assert_eq!(parse_key(b"not a key", None).err().as_deref(), Some(NOT_A_KEY));
        assert!(parse_key(b"not a key", Some("secret")).err().unwrap_or_default().contains("password"));
    }

    #[test]
    fn import_json_has_the_contracts_shape() {
        let json = import_json(&[1, 2, 3], None);
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 3);
        assert_eq!(json["fingerprint"].as_str().map(str::len), Some(16));
        assert!(json["certificateSerial"].is_null());
        assert!(json["certificateExpires"].is_null());
    }
}
