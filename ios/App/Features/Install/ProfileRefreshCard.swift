import SwiftUI

/// "Refresh Profiles" on the Install tab: new 7-day profiles for the apps signed with
/// iloader's certificate (inside LiveContainer, LiveContainer first), with what happened
/// to each one.
struct ProfileRefreshCard: View {
    @ObservedObject private var refresher = ProfileRefresher.shared

    var body: some View {
        VStack(spacing: 10) {
            SectionLabel(title: "Refresh Profiles", trailing: lastRun)
            GlassCard(tint: tint) {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(alignment: .top, spacing: 12) {
                        if refresher.isBusy {
                            ProgressRing(value: nil, lineWidth: 3, size: 22, showsPercent: false)
                        }
                        Text(status)
                            .font(.subheadline)
                            .foregroundStyle(Aurora.secondaryText)
                            .fixedSize(horizontal: false, vertical: true)
                            .contentTransition(.opacity)
                            .textSelection(.enabled)
                    }
                    if let report = refresher.last, !report.results.isEmpty {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(Array(report.results.enumerated()), id: \.offset) { _, row in
                                resultRow(row, app: appBundleID(of: row, in: report.results))
                            }
                        }
                    }
                }
            }
            actions
        }
        .animation(.spring(duration: 0.4), value: refresher.phase)
    }

    // MARK: - Actions

    @ViewBuilder
    private var actions: some View {
        switch refresher.phase {
        case .running:
            GlassActionButton(title: "Cancel", systemImage: "xmark") { refresher.cancel() }
        case .needsVPN:
            VStack(spacing: 12) {
                GlassActionButton(title: "Turn On LocalDevVPN", systemImage: "power", prominent: true) {
                    LocalDevVPN.turnOn()
                }
                HStack(spacing: 12) {
                    GlassActionButton(title: "It's On, Continue", systemImage: "arrow.right") {
                        refresher.resumeIfParked(skipVPNCheck: true)
                    }
                    GlassActionButton(title: "Cancel", systemImage: "xmark") { refresher.cancel() }
                }
            }
        default:
            VStack(spacing: 12) {
                GlassActionButton(title: "Refresh Profiles", systemImage: "arrow.triangle.2.circlepath", prominent: true) {
                    refresher.start()
                }
                GlassActionButton(title: "Check Only", systemImage: "list.bullet.clipboard") {
                    refresher.start(dryRun: true)
                }
                Text("Check Only asks Apple and lists what a refresh would do. It installs nothing and registers no App IDs.")
                    .font(.caption)
                    .foregroundStyle(Aurora.secondaryText)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 4)
            }
        }
    }

    // MARK: - Rows

    /// Long-press a row to renew just that app (an extension's row means its app), for
    /// a first test on LiveContainer alone.
    private func resultRow(_ row: ProfileRefreshRow, app: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol(row))
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(color(row))
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(row.app.isEmpty ? row.bundleId : row.app)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(Aurora.frost)
                    if row.bundleId == Hosting.hostBundleID {
                        GlassChip(text: String(localized: "Running Reloader"), tint: Aurora.accent)
                            .scaleEffect(0.85, anchor: .leading)
                    }
                }
                Text(detail(row))
                    .font(.caption)
                    .foregroundStyle(row.needsAttention ? Aurora.danger : Aurora.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                Text(row.bundleId)
                    .font(.caption2.monospaced())
                    .foregroundStyle(Aurora.secondaryText.opacity(0.8))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .contentShape(.rect)
        .contextMenu {
            Button(String(localized: "Refresh Only This App"), systemImage: "arrow.triangle.2.circlepath") {
                refresher.start(only: [app])
            }
            .disabled(refresher.isBusy)
            Button(String(localized: "Check Only This App"), systemImage: "list.bullet.clipboard") {
                refresher.start(dryRun: true, only: [app])
            }
            .disabled(refresher.isBusy)
        }
    }

    /// The core reports an extension's own profile right after its app, under the app's
    /// identifier plus a suffix. "only" takes the installed app's bundle ID, so an
    /// extension's row stands for its app.
    private func appBundleID(of row: ProfileRefreshRow, in rows: [ProfileRefreshRow]) -> String {
        rows.map(\.bundleId)
            .filter { row.bundleId.lowercased().hasPrefix($0.lowercased() + ".") }
            .min { $0.count < $1.count } ?? row.bundleId
    }

    private func symbol(_ row: ProfileRefreshRow) -> String {
        switch row.status {
        case "refreshed": "checkmark.seal.fill"
        case "planned": "clock.badge.checkmark"
        case "skipped": "exclamationmark.triangle.fill"
        default: "xmark.octagon.fill"
        }
    }

    private func color(_ row: ProfileRefreshRow) -> Color {
        switch row.status {
        case "refreshed", "planned": Aurora.success
        case "skipped": Aurora.ember
        default: Aurora.danger
        }
    }

    private func detail(_ row: ProfileRefreshRow) -> String {
        func day(_ date: Date) -> String { date.formatted(date: .abbreviated, time: .shortened) }
        switch row.status {
        case "refreshed":
            return row.newExpiration.map { String(localized: "Renewed until \(day($0))") } ?? String(localized: "Renewed")
        case "planned":
            let now = row.oldExpiration.map { String(localized: "Runs out \(day($0)). ") } ?? ""
            return now + (row.reason ?? String(localized: "A refresh would renew it."))
        default:
            return row.reason ?? String(localized: "Not renewed.")
        }
    }

    // MARK: - Status

    private var lastRun: String? {
        guard let finished = refresher.last?.finishedAt else { return nil }
        let when = finished.formatted(.relative(presentation: .named))
        return refresher.last?.dryRun == true ? String(localized: "Checked \(when)") : String(localized: "Refreshed \(when)")
    }

    private var tint: Color? {
        switch refresher.phase {
        case .failed: Aurora.danger
        case .needsVPN: Aurora.accent
        default: nil
        }
    }

    private var status: String {
        switch refresher.phase {
        case .idle, .finished:
            if let report = refresher.last, let available = report.appIdsAvailable {
                return String(localized: "\(intro) \(available) App IDs left this week.")
            }
            return intro
        case .needsVPN:
            return String(localized: "Waiting for LocalDevVPN. Turn it on, then come back and Reloader carries on.")
        case .running(let stage):
            return stage
        case .failed(let message):
            return message
        }
    }

    private var intro: String {
        if Hosting.isHosted {
            return String(localized: "Gets new 7-day profiles from Apple for \(Hosting.hostName), which Reloader is running in, and the other apps signed with your certificate, and installs them over LocalDevVPN. Nothing is re-signed or reinstalled.")
        }
        return String(localized: "Gets new 7-day profiles from Apple for the apps signed with iloader's certificate, Reloader included, and installs them over LocalDevVPN. Nothing is re-signed or reinstalled.")
    }
}
