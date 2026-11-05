import SwiftUI

// MARK: - Apple ID

/// Full-screen Apple ID sign-in (used by Tools › Certificates; installs sign in inside InstallFlowView).
struct SignInSheet: View {
    let anisetteURL: String
    let onContinue: (AppleIDCredentials, Bool) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var email = AppleIDStore.email
    @State private var password = ""
    @State private var remember = true

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(String(localized: "Apple ID email"), text: $email)
                        .textContentType(.username)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField(String(localized: "Password"), text: $password)
                        .textContentType(.password)
                } footer: {
                    Text("Your password goes only to Apple. Apple also requires device-identity headers (\"anisette\"), which Reloader gets from \(host). Use the Apple ID iloader signs with on your PC.")
                }
                .auroraRow()

                Section {
                    Toggle(String(localized: "Remember password"), isOn: $remember)
                } footer: {
                    Text("Kept in this iPhone's Keychain so refreshing is one tap. It never syncs to iCloud.")
                }
                .auroraRow()
            }
            .auroraListBackground()
            .navigationTitle(String(localized: "Apple ID"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CloseButton { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(String(localized: "Continue")) {
                        onContinue(AppleIDCredentials(email: email.trimmingCharacters(in: .whitespaces), password: password), remember)
                        dismiss()
                    }
                    .disabled(email.isEmpty || password.isEmpty)
                }
            }
            .onAppear {
                if password.isEmpty, !email.isEmpty, let saved = AppleIDStore.password(for: email) {
                    password = saved
                }
            }
        }
    }

    private var host: String {
        if anisetteURL == AnisetteServers.automatic { return String(localized: "a public server that's working right now") }
        return URL(string: anisetteURL)?.host() ?? anisetteURL
    }
}

// MARK: - Two-factor

struct TwoFactorSheet: View {
    let prompt: TwoFactorPrompt
    let respond: (String) -> Void
    @State private var code = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("000000", text: $code)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .font(.system(size: 30, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .multilineTextAlignment(.center)
                        .onChange(of: code) { _, value in
                            code = String(value.filter(\.isNumber).prefix(6))
                        }
                } header: {
                    Text(headline)
                } footer: {
                    if let error = prompt.lastError, !error.isEmpty {
                        Text(error).foregroundStyle(Aurora.danger)
                    }
                }
                .auroraRow()

                Section(String(localized: "Other options")) {
                    Button(String(localized: "Send code to my Apple devices")) { respond("devices") }
                    ForEach(prompt.numbers.filter { $0.id != prompt.selectedNumberID || !prompt.sms }) { number in
                        Button("Text \(number.number)") { respond("sms:\(number.id)") }
                    }
                    if !prompt.unknown {
                        Button(String(localized: "Resend code")) { respond("resend") }
                    }
                }
                .auroraRow()
            }
            .auroraListBackground()
            .navigationTitle(String(localized: "Verification"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(String(localized: "Cancel"), role: .cancel) { respond("abort") }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Verify") { respond("code:\(code)") }
                        .disabled(code.count != 6)
                }
            }
        }
    }

    private var headline: String {
        if prompt.unknown { return String(localized: "Choose where to get your code") }
        if prompt.sms,
           let id = prompt.selectedNumberID,
           let number = prompt.numbers.first(where: { $0.id == id }) {
            return String(localized: "Enter the code sent to \(number.number)")
        }
        return String(localized: "Enter the code shown on your other Apple devices")
    }
}
