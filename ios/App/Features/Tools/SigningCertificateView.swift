import SwiftUI
import UniformTypeIdentifiers

/// Tools › Signing Certificate: imports iloader's private key once per Apple ID, so
/// Reloader signs with the certificate iloader made on the PC. Inside LiveContainer
/// that's the .p12 LiveContainer already signs its guests with; otherwise the same .p12
/// (or iloader's raw key file) from Files. Reloader never makes or revokes a certificate.
struct SigningCertificateView: View {
    @State private var email = AppleIDStore.email
    @State private var password = ""
    @State private var fileName: String?
    @State private var fileData: Data?
    @State private var showImporter = false
    @State private var hasKey = false
    @State private var imported: SigningKeyStore.Imported?
    @State private var importing = false
    @State private var message: (text: String, failed: Bool)?

    private var trimmedEmail: String { email.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        AuroraScreen {
            header
            appleIDCard
            if Hosting.isHosted {
                liveContainerCard
            }
            fileCard
            if let message {
                GlassCard(tint: message.failed ? Aurora.danger : Aurora.success) {
                    Text(message.text)
                        .font(.footnote)
                        .foregroundStyle(Aurora.frost)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            Text("The key stays on this iPhone, outside backups, and is only used to sign. It never goes anywhere, Apple included. If iloader's certificate is revoked or expires, install once with iloader on your PC; if iloader made a new key too, import the new .p12 here.")
                .font(.system(size: 13))
                .foregroundStyle(Aurora.secondaryText)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 8)
        }
        .navigationTitle(String(localized: "Signing Certificate"))
        .toolbarTitleDisplayMode(.inlineLarge)
        .onAppear(perform: reloadStatus)
        .onChange(of: email) { _, _ in reloadStatus() }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [.pkcs12, .data]) { result in
            switch result {
            case .success(let url):
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                do {
                    fileData = try Data(contentsOf: url)
                    fileName = url.lastPathComponent
                    message = nil
                } catch {
                    message = (String(localized: "Couldn't read the file: \(error.localizedDescription)"), true)
                }
            case .failure(let error):
                message = (error.localizedDescription, true)
            }
        }
        .animation(.spring(duration: 0.4), value: hasKey)
    }

    // MARK: - Cards

    private var header: some View {
        VStack(spacing: 12) {
            GlassBadge(systemImage: hasKey ? "key.fill" : "key", tint: hasKey ? Aurora.success : Aurora.accent, size: 84)
            Text(hasKey ? "Signing with iloader's certificate" : "Import iloader's certificate")
                .font(.title2.bold())
                .foregroundStyle(Aurora.frost)
                .multilineTextAlignment(.center)
            Text("Reloader signs only with the certificate iloader made on your PC. It finds it on your Apple ID by this key.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, 4)
    }

    private var appleIDCard: some View {
        CardSection(title: "Apple ID", symbol: "person.fill") {
            TextField(String(localized: "Apple ID email"), text: $email)
                .textContentType(.username)
                .keyboardType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .inputField()
            if hasKey {
                Label(String(localized: "A key is imported for this Apple ID"), systemImage: "checkmark.seal.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Aurora.success)
                if let imported {
                    InfoRow(title: "Key", value: imported.fingerprint, monospaced: true)
                    if let serial = imported.certificateSerial {
                        InfoRow(title: "Certificate", value: serial, monospaced: true)
                    }
                    if let expiration = imported.expiration {
                        InfoRow(title: "Valid until", value: expiration.formatted(date: .abbreviated, time: .omitted))
                    }
                }
            } else {
                Label(String(localized: "No key imported for this Apple ID yet"), systemImage: "exclamationmark.triangle.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Aurora.ember)
            }
            footnote(String(localized: "The Apple ID iloader signs in with on your PC. Each device imports the key for its own Apple ID."))
        }
    }

    private var liveContainerCard: some View {
        CardSection(title: "From LiveContainer", symbol: "shippingbox.fill") {
            footnote(String(localized: "\(Hosting.hostName) signs its guests with the .p12 you imported in its settings, which holds iloader's key and certificate."))
            Button {
                guard let certificate = Hosting.liveContainerCertificate else {
                    message = (String(localized: "Couldn't read \(Hosting.hostName)'s certificate from here. Pick the same .p12 in Files below instead."), true)
                    return
                }
                runImport(certificate.data, password: certificate.password, source: Hosting.hostName)
            } label: {
                Label(String(localized: "Use LiveContainer's Certificate"), systemImage: "checkmark.shield")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(AltLoadButtonStyle())
            .disabled(trimmedEmail.isEmpty || importing)
        }
    }

    private var fileCard: some View {
        CardSection(title: "From a File", symbol: "doc.badge.plus") {
            Button {
                showImporter = true
            } label: {
                Label(fileName ?? String(localized: "Choose the .p12 or Key File…"), systemImage: "folder")
                    .frame(maxWidth: .infinity)
                    .lineLimit(1)
            }
            .buttonStyle(AltLoadButtonStyle(prominent: false))
            SecureField(String(localized: ".p12 password"), text: $password)
                .textContentType(.password)
                .inputField()
            Button {
                guard let fileData else { return }
                runImport(fileData, password: password.isEmpty ? nil : password, source: fileName ?? "")
            } label: {
                Label(String(localized: "Import"), systemImage: "square.and.arrow.down")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(AltLoadButtonStyle())
            .disabled(fileData == nil || trimmedEmail.isEmpty || importing)
            footnote(String(localized: "The LiveContainer .p12 you made from iloader's key, with its password. For iloader's raw key file (PKCS#8, PEM or base64), leave the password empty."))
        }
    }

    // MARK: - Import

    private func runImport(_ data: Data, password: String?, source: String) {
        let email = trimmedEmail
        importing = true
        message = nil
        Task {
            // Opening a .p12 runs its key derivation, so keep it off the main thread.
            let outcome = await Task.detached { () -> Result<SigningKeyStore.Imported, Error> in
                Result { try SigningKeyStore.importKey(data, password: password, email: email) }
            }.value
            importing = false
            switch outcome {
            case .success(let result):
                fileData = nil
                fileName = nil
                self.password = ""
                AppleIDStore.email = email
                reloadStatus()
                var text = String(localized: "Imported key \(result.fingerprint) from \(source).")
                if let serial = result.certificateSerial {
                    text += " " + String(localized: "Its certificate is \(serial)")
                    if let expiration = result.expiration {
                        text += String(localized: ", valid until \(expiration.formatted(date: .abbreviated, time: .omitted))")
                    }
                    text += "."
                }
                text += " " + String(localized: "Reloader looks for it on your Apple ID the next time it signs in.")
                message = (text, false)
            case .failure(let error):
                message = (error.localizedDescription, true)
            }
        }
    }

    private func reloadStatus() {
        hasKey = SigningKeyStore.hasKey(for: trimmedEmail)
        imported = hasKey ? SigningKeyStore.lastImport(for: trimmedEmail) : nil
    }

    private func footnote(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(Aurora.secondaryText)
            .fixedSize(horizontal: false, vertical: true)
    }
}
