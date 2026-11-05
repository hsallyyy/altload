import SwiftUI

/// The signed-in Apple ID's own development certificates and their details, with the
/// one iloader made (the only one Reloader signs with) marked. Nothing here revokes a
/// certificate. Also shows the App IDs and registered devices on the team.
struct CertificatesView: View {
    @StateObject private var controller = CertificatesController.shared
    @State private var showSignIn = false

    var body: some View {
        AuroraScreen {
            header

            switch controller.phase {
            case .signedOut:
                signedOut
            case .loading(let stage):
                loading(stage)
            case .loaded:
                if let overview = controller.overview {
                    content(overview)
                }
            case .failed(let message):
                failure(message)
            }
        }
        .navigationTitle(String(localized: "Certificates"))
        .toolbarTitleDisplayMode(.inlineLarge)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    controller.refresh()
                } label: {
                    Label(String(localized: "Refresh"), systemImage: "arrow.clockwise")
                }
                .disabled(controller.isBusy || controller.overview == nil)
            }
        }
        .fullScreenCover(isPresented: $showSignIn) {
            SignInSheet(anisetteURL: InstallController.shared.anisetteURL) { credentials, remember in
                controller.load(with: credentials, remember: remember)
            }
            .auroraTheme()
        }
        .fullScreenCover(item: $controller.twoFactor) { prompt in
            TwoFactorSheet(prompt: prompt) { controller.respond($0) }
                .auroraTheme()
        }
        .animation(.spring(duration: 0.5, bounce: 0.2), value: controller.phase)
    }

    // MARK: - Header

    private var header: some View {
        VStack(spacing: 12) {
            GlassBadge(systemImage: "checkmark.seal", tint: Aurora.accent, size: 84)
            Text("Your certificates")
                .font(.title2.bold())
                .foregroundStyle(Aurora.frost)
            Text("The development certificates on your own Apple ID.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, 4)
    }

    // MARK: - States

    private var signedOut: some View {
        VStack(spacing: 14) {
            GlassCard {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Sign in to see your certificates")
                        .font(.headline)
                    Text("Reloader reads the development certificates on your Apple ID. It signs only with the one iloader made on your PC, and never creates or revokes any.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            GlassActionButton(title: "Sign In", systemImage: "person.crop.circle", prominent: true) {
                if let saved = controller.savedCredentials {
                    controller.load(with: saved)
                } else {
                    showSignIn = true
                }
            }
        }
    }

    private func loading(_ stage: String) -> some View {
        GlassCard {
            HStack(spacing: 16) {
                ProgressRing(value: nil, lineWidth: 6, size: 44)
                Text(stage)
                    .font(.headline)
                    .contentTransition(.opacity)
            }
        }
    }

    private func failure(_ message: String) -> some View {
        VStack(spacing: 14) {
            GlassCard(tint: Aurora.danger) {
                VStack(alignment: .leading, spacing: 8) {
                    Label(String(localized: "Couldn't load"), systemImage: "xmark.octagon.fill")
                        .font(.title3.bold())
                        .foregroundStyle(Aurora.danger)
                    Text(message)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            GlassActionButton(title: "Try Again", systemImage: "arrow.clockwise", prominent: true) {
                if let saved = controller.savedCredentials {
                    controller.load(with: saved)
                } else {
                    showSignIn = true
                }
            }
        }
    }

    // MARK: - Loaded content

    private func content(_ overview: AccountOverview) -> some View {
        VStack(spacing: 22) {
            usageCard(overview)

            VStack(spacing: 10) {
                SectionLabel(title: "Certificates", trailing: "\(overview.certificates.count)")
                if overview.certificates.isEmpty {
                    GlassCard(tint: Aurora.danger) {
                        Text("No development certificates on this Apple ID. Reloader never creates one: install an app once with iloader on your PC, then import its certificate in Tools › Signing Certificate.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    if !overview.certificates.contains(where: \.isInUse) {
                        GlassCard(tint: Aurora.ember) {
                            Text("None of these looks like iloader's certificate. If it was revoked or has expired, install once with iloader on your PC to get a new one, then import it again in Tools › Signing Certificate.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                    ForEach(overview.certificates) { cert in
                        certificateCard(cert)
                    }
                }
            }

            if let items = overview.appIds.items, !items.isEmpty {
                VStack(spacing: 10) {
                    SectionLabel(title: "App IDs", trailing: appIdTrailing(overview.appIds))
                    GlassCard {
                        VStack(spacing: 12) {
                            ForEach(items.prefix(8)) { appID in
                                appIdRow(appID)
                                if appID.id != items.prefix(8).last?.id { Divider().overlay(Aurora.frost.opacity(0.1)) }
                            }
                            if items.count > 8 {
                                Text("+ \(items.count - 8) more")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
            }

            if !overview.devices.isEmpty {
                VStack(spacing: 10) {
                    SectionLabel(title: "Devices", trailing: "\(overview.devices.count)")
                    GlassCard {
                        VStack(spacing: 12) {
                            ForEach(overview.devices) { device in
                                deviceRow(device)
                                if device.id != overview.devices.last?.id { Divider().overlay(Aurora.frost.opacity(0.1)) }
                            }
                        }
                    }
                }
            }

            toolsSection(overview)

            if let updated = controller.lastUpdated {
                Text("Updated \(updated.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func usageCard(_ overview: AccountOverview) -> some View {
        GlassCard {
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(overview.team.name.isEmpty ? "Your team" : overview.team.name)
                        .font(.headline)
                    Text(usageText(overview))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                if let limit = overview.certificateLimit {
                    ProgressRing(value: Double(overview.certificates.count) / Double(max(limit, 1)),
                                 size: 54, showsPercent: false)
                        .overlay {
                            Text("\(overview.certificates.count)/\(limit)")
                                .font(.caption.bold().monospacedDigit())
                                .foregroundStyle(Aurora.frost)
                        }
                }
            }
        }
    }

    private func certificateCard(_ cert: DevCertificate) -> some View {
        GlassCard(tint: cert.isExpired ? Aurora.danger : nil) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.title3)
                        .foregroundStyle(cert.isExpired ? Aurora.danger : Aurora.success)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(cert.displayName)
                            .font(.headline)
                        if !cert.type.isEmpty {
                            Text(cert.type)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 0)
                    if cert.isInUse {
                        GlassChip(text: String(localized: "In use"), tint: Aurora.accent)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    if let expiration = cert.expiration {
                        detail(String(localized: "Expires"), expiration.formatted(date: .abbreviated, time: .omitted)
                               + (cert.isExpired ? String(localized: " · expired") : ""))
                    }
                    if !cert.serial.isEmpty { detail(String(localized: "Serial"), cert.serial, mono: true) }
                    if !cert.machineName.isEmpty { detail(String(localized: "Machine"), cert.machineName) }
                }
            }
        }
    }

    private func toolsSection(_ overview: AccountOverview) -> some View {
        VStack(spacing: 10) {
            SectionLabel(title: "Tools")
            GlassCard {
                VStack(spacing: 14) {
                    toolRow(
                        title: "Sign out",
                        detail: AppleIDStore.email,
                        systemImage: "person.crop.circle.badge.xmark",
                        tint: Aurora.mist,
                        disabled: controller.isBusy
                    ) {
                        controller.signOut()
                    }
                }
            }
        }
    }

    // MARK: - Rows

    private func appIdRow(_ appID: DevAppID) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "app.badge")
                .foregroundStyle(Aurora.mist)
            VStack(alignment: .leading, spacing: 1) {
                Text(appID.name).font(.subheadline.weight(.medium))
                Text(appID.identifier).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
    }

    private func deviceRow(_ device: DevDevice) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "iphone.gen3")
                .foregroundStyle(Aurora.mist)
            VStack(alignment: .leading, spacing: 1) {
                Text(device.name.isEmpty ? "Device" : device.name).font(.subheadline.weight(.medium))
                Text(device.udid).font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
    }

    private func toolRow(title: LocalizedStringKey, detail: String, systemImage: String, tint: Color, disabled: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                IconTile(symbol: systemImage, tint: tint, size: 34)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(Aurora.frost)
                    if !detail.isEmpty {
                        Text(detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled ? 0.5 : 1)
    }

    private func detail(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 64, alignment: .leading)
            Text(value)
                .font(mono ? .caption.monospaced() : .caption)
                .foregroundStyle(Aurora.frost)
                .textSelection(.enabled)
        }
    }

    private func usageText(_ overview: AccountOverview) -> String {
        var parts: [String] = []
        if let limit = overview.certificateLimit {
            parts.append(String(localized: "\(overview.certificates.count) of \(limit) certificates"))
        } else {
            parts.append(String(localized: "\(overview.certificates.count) certificates"))
        }
        if let available = overview.appIds.available, let max = overview.appIds.max {
            parts.append(String(localized: "\(max - available)/\(max) App IDs"))
        }
        return parts.joined(separator: " · ")
    }

    private func appIdTrailing(_ appIds: AccountOverview.AppIDs) -> String {
        guard let items = appIds.items else { return "" }
        if let max = appIds.max { return String(localized: "\(items.count)/\(max)") }
        return String(localized: "\(items.count)")
    }
}
