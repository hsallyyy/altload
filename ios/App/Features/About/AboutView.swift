import SwiftUI

/// About Reloader: version, the people whose work it builds on, and the credit and
/// licence AltLoad's license asks a modified build to carry. Settings live behind the
/// gear at the top right.
struct AboutView: View {
    @ObservedObject private var install = InstallController.shared
    @ObservedObject private var altServer = AltServerHost.shared
    @ObservedObject private var entitlements = EntitlementSettings.shared
    @State private var notice: Notice?

    /// LICENSE.md or THIRD_PARTY_NOTICES.md as this build carries them: the license wants
    /// its notice in every copy, so they're bundled rather than linked.
    private struct Notice: Identifiable {
        let title: String
        let resource: String
        var id: String { resource }

        var text: String {
            Bundle.main.url(forResource: resource, withExtension: "md")
                .flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
        }
    }

    private var version: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "–"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "–"
        let pre = Bundle.main.infoDictionary?["AltLoadPrerelease"] as? String ?? ""
        return pre.isEmpty ? "\(v) (\(b))" : "\(v) \(pre) (\(b))"
    }

    var body: some View {
        NavigationStack {
            AuroraScreen {
                hero

                HStack(spacing: 8) {
                    StatTile(title: "Apps", value: "\(install.apps.count)")
                    StatTile(title: "Entitlements", value: "\(entitlements.enabled.count)")
                    StatTile(title: "AltServer", value: altServer.isRunning ? "On" : "Off")
                }

                VStack(spacing: 10) {
                    SectionLabel(title: "Special Thanks")
                    VStack(spacing: 0) {
                        credit("jkcoxson", work: String(localized: "idevice and LocalDevVPN: the link from this iPhone to itself"),
                               symbol: "cable.connector", tint: Aurora.accentDeep, url: "https://github.com/jkcoxson")
                        divider
                        credit("nab138", work: String(localized: "isideload: Apple ID sign-in and code signing"),
                               symbol: "signature", tint: Aurora.forest, url: "https://github.com/nab138/isideload")
                        divider
                        credit("StephenDev0", work: String(localized: "StikPair and StikDebug: pairing and JIT"),
                               symbol: "antenna.radiowaves.left.and.right", tint: Color(red: 0.42, green: 0.30, blue: 0.70), url: "https://github.com/StephenDev0")
                        divider
                        credit(String(localized: "Riley Testut"), work: String(localized: "AltStore and the AltServer protocol"),
                               symbol: "square.stack.3d.up.fill", tint: Color(red: 0.02, green: 0.48, blue: 0.48), url: "https://github.com/altstoreio/AltStore")
                        divider
                        credit(String(localized: "SideStore Team"), work: String(localized: "SideStore and the public anisette servers"),
                               symbol: "arrow.triangle.2.circlepath", tint: Color(red: 0.55, green: 0.30, blue: 0.62), url: "https://github.com/SideStore")
                        divider
                        credit(String(localized: "LiveContainer"), work: String(localized: "Running apps without installing them"),
                               symbol: "shippingbox.fill", tint: Color(red: 0.70, green: 0.42, blue: 0.16), url: "https://github.com/LiveContainer/LiveContainer")
                    }
                    .cardSurface()
                }

                VStack(spacing: 10) {
                    SectionLabel(title: "Credits")
                    VStack(spacing: 0) {
                        // Word for word as AltLoad's LICENSE.md (section 4) asks; not localized.
                        link("Based on AltLoad by mirazbakis – https://github.com/mirazbakis/AltLoad",
                             symbol: "checkmark.seal", url: "https://github.com/mirazbakis/AltLoad")
                        divider
                        noticeRow(Notice(title: String(localized: "AltLoad License"), resource: "LICENSE"), symbol: "doc.text")
                        divider
                        noticeRow(Notice(title: String(localized: "Third-Party Notices"), resource: "THIRD_PARTY_NOTICES"), symbol: "list.bullet")
                    }
                    .cardSurface()
                }

                Text("Reloader is a personal build and isn't the official AltLoad. It isn't affiliated with mirazbakis, AltStore, SideStore, LiveContainer, Husk, Riley Testut or Apple. Apple, iPhone and iOS are trademarks of Apple Inc.")
                    .font(.caption)
                    .foregroundStyle(Aurora.secondaryText)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 8)
            }
            .navigationTitle(String(localized: "About"))
            .toolbarTitleDisplayMode(.inlineLarge)
            .settingsButton()
            .sheet(item: $notice) { notice in
                NavigationStack {
                    ScrollView {
                        Text(notice.text)
                            .font(.footnote.monospaced())
                            .foregroundStyle(Aurora.frost)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(20)
                    }
                    .navigationTitle(notice.title)
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            CloseButton { self.notice = nil }
                        }
                    }
                }
                .auroraTheme()
                .presentationBackground(Aurora.night)
            }
        }
    }

    private var hero: some View {
        VStack(spacing: 14) {
            AltLoadMark(size: 104)
            VStack(spacing: 4) {
                Text("Reloader")
                    .font(.system(size: 30, weight: .bold))
                    .foregroundStyle(Aurora.frost)
                Text("Version \(version)")
                    .font(.subheadline)
                    .foregroundStyle(Aurora.secondaryText)
            }
            Text("Keeps LiveContainer and your other apps signed with iloader's certificate, by renewing their profiles on this iPhone.")
                .font(.subheadline)
                .foregroundStyle(Aurora.mist)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 12)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 8)
    }

    private var divider: some View {
        Rectangle()
            .fill(Aurora.hairline)
            .frame(height: 1)
            .padding(.leading, 66)
    }

    private func credit(_ name: String, work: String, symbol: String, tint: Color, url: String) -> some View {
        Link(destination: URL(string: url)!) {
            HStack(spacing: 14) {
                IconTile(symbol: symbol, tint: tint, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.subheadline.weight(.semibold)).foregroundStyle(Aurora.frost)
                    Text(work).font(.caption).foregroundStyle(Aurora.secondaryText)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                Image(systemName: "arrow.up.right")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(Aurora.secondaryText)
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 64)
            .contentShape(.rect)
        }
    }

    private func link(_ title: String, symbol: String, url: String) -> some View {
        Link(destination: URL(string: url)!) {
            row(title, symbol: symbol, accessory: "arrow.up.right")
        }
    }

    private func noticeRow(_ notice: Notice, symbol: String) -> some View {
        Button { self.notice = notice } label: {
            row(notice.title, symbol: symbol, accessory: "chevron.right")
        }
        .buttonStyle(.plain)
    }

    private func row(_ title: String, symbol: String, accessory: String) -> some View {
        HStack(spacing: 14) {
            IconTile(symbol: symbol, tint: Aurora.mist, size: 36)
            Text(title).font(.subheadline.weight(.medium)).foregroundStyle(Aurora.frost)
                .multilineTextAlignment(.leading)
            Spacer()
            Image(systemName: accessory)
                .font(.caption.weight(.bold))
                .foregroundStyle(Aurora.secondaryText)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .frame(minHeight: 56)
        .contentShape(.rect)
    }
}
