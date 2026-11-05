import AltLoadFFI
import Foundation

/// iloader's private key, imported once per Apple ID: the .p12 LiveContainer signs its
/// guests with, or iloader's raw key file. The Rust core keeps it (Application
/// Support/AltLoad/iloader-key) and signs only with the certificate iloader already made
/// for that key. Nothing in Reloader creates, requests or revokes a certificate.
enum SigningKeyStore {
    /// What the core read from the imported file.
    struct Imported: Codable, Equatable {
        /// Short hex fingerprint of the key's public half.
        let fingerprint: String
        /// The certificate that came with a .p12; nil for a raw key.
        let certificateSerial: String?
        let certificateExpires: Int64?
        var importedAt: Date?

        var expiration: Date? { certificateExpires.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
    }

    struct ImportError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// The core's FileStorage folder for the key, under Application Support.
    private static let folder = "AltLoad/iloader-key"

    static func hasKey(for email: String) -> Bool {
        let email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !email.isEmpty else { return false }
        return email.withCString { altload_has_signing_key($0) } == 1
    }

    /// What was imported for this Apple ID last, as shown in Tools › Signing Certificate.
    static func lastImport(for email: String) -> Imported? {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey(email)) else { return nil }
        return try? JSONDecoder().decode(Imported.self, from: data)
    }

    /// Saves the key for `email`. `password` is the .p12's, or nil for a raw key file.
    /// Offline: nothing leaves the iPhone.
    @discardableResult
    static func importKey(_ data: Data, password: String?, email: String) throws -> Imported {
        let email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        var out: UnsafeMutablePointer<CChar>?
        let rc: Int32 = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Int32 in
            let bytes = raw.bindMemory(to: UInt8.self).baseAddress
            return email.withCString { emailC -> Int32 in
                guard let password else {
                    return altload_import_signing_key(emailC, bytes, raw.count, nil, &out)
                }
                return password.withCString { passwordC -> Int32 in
                    altload_import_signing_key(emailC, bytes, raw.count, passwordC, &out)
                }
            }
        }
        let text = out.map { String(cString: $0) } ?? ""
        if let out { altload_string_free(out) }
        guard rc == 0 else {
            throw ImportError(message: text.isEmpty ? String(localized: "Import failed (code \(rc)).") : text)
        }
        excludeFromBackup()
        var imported = try JSONDecoder().decode(Imported.self, from: Data(text.utf8))
        imported.importedAt = .now
        if let encoded = try? JSONEncoder().encode(imported) {
            UserDefaults.standard.set(encoded, forKey: defaultsKey(email))
        }
        return imported
    }

    /// Whether `serial` (as Apple lists it) is the certificate that came with the imported .p12.
    static func isImportedCertificate(serial: String, email: String) -> Bool {
        guard let imported = lastImport(for: email)?.certificateSerial, !serial.isEmpty else { return false }
        return normalized(imported) == normalized(serial)
    }

    private static func normalized(_ serial: String) -> String {
        String(serial.uppercased().drop { $0 == "0" })
    }

    private static func defaultsKey(_ email: String) -> String {
        "signingKey." + email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// The key shouldn't end up in iCloud or computer backups.
    private static func excludeFromBackup() {
        guard var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent(folder, isDirectory: true) else { return }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
    }
}
