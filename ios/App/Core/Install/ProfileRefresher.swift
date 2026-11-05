import AltLoadFFI
import Foundation
import UIKit
import UserNotifications

/// One App ID from a profile refresh, as the Rust core reports it.
struct ProfileRefreshRow: Codable, Equatable {
    /// The App ID's identifier, e.g. com.kdt.livecontainer.ABCDE12345.
    let bundleId: String
    let app: String
    /// "refreshed", "planned" (a check), "skipped" or "failed".
    let status: String
    let reason: String?
    let oldExpires: Int64?
    let newExpires: Int64?

    var oldExpiration: Date? { oldExpires.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
    var newExpiration: Date? { newExpires.map { Date(timeIntervalSince1970: TimeInterval($0)) } }
    var needsAttention: Bool { status == "skipped" || status == "failed" }
}

struct ProfileRefreshReport: Codable, Equatable {
    let team: String
    let udid: String
    let dryRun: Bool
    /// App IDs the free account can still register this week.
    let appIdsAvailable: Int?
    let results: [ProfileRefreshRow]
    var finishedAt: Date?
}

/// Renews the 7-day provisioning profiles of the apps on this iPhone that are signed with
/// iloader's certificate, LiveContainer first, and installs them with misagent. Nothing
/// is re-signed or reinstalled, and no certificate is made or revoked. Runs from the
/// Install tab, from reloader://refresh-profiles and from the "Refresh App Profiles"
/// shortcut.
@MainActor
final class ProfileRefresher: ObservableObject {
    static let shared = ProfileRefresher()

    enum Phase: Equatable {
        case idle
        /// Waiting for LocalDevVPN. Carries on when Reloader comes back to the front.
        case needsVPN
        case running(String)
        case finished
        case failed(String)
    }

    struct Request: Equatable {
        /// Ask Apple and report what would change, without installing anything or
        /// registering App IDs.
        var dryRun = false
        /// Only these bundle IDs, or nil for every app signed with the certificate.
        var only: [String]?
        /// Post the outcome as a notification: the run came from a Shortcut or a link.
        var announce = false
    }

    @Published private(set) var phase: Phase = .idle
    /// The last report, from a check or a refresh.
    @Published private(set) var last: ProfileRefreshReport?
    @Published var twoFactor: TwoFactorPrompt?

    /// Identifiers of every notification this posts, so they show while Reloader is open.
    nonisolated static let notificationPrefix = "reloader.refresh"
    private static let reminderID = "reloader.refresh.reminder"
    private static let resultID = "reloader.refresh.result"
    private let lastKey = "profileRefresh.last"
    private let refreshedKey = "profileRefresh.refreshedAt"

    private var session: OpaquePointer?
    private var parked: Request?
    private let keepAlive = KeepAlive()
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid

    var isBusy: Bool {
        if case .running = phase { return true }
        return false
    }

    /// When a run last installed profiles (checks don't count).
    var lastRefreshed: Date? { UserDefaults.standard.object(forKey: refreshedKey) as? Date }

    private init() {
        if let data = UserDefaults.standard.data(forKey: lastKey) {
            last = try? JSONDecoder().decode(ProfileRefreshReport.self, from: data)
        }
    }

    func start(dryRun: Bool = false, only: [String]? = nil, announce: Bool = false) {
        let request = Request(dryRun: dryRun, only: only, announce: announce)
        Task { await run(request) }
    }

    /// Back in front with a refresh parked for LocalDevVPN: carry on once the VPN is up.
    /// LocalDevVPN hands control back before the tunnel is fully configured, so this
    /// gives it a few seconds. `skipVPNCheck` is "It's On, Continue".
    func resumeIfParked(skipVPNCheck: Bool = false) {
        guard case .needsVPN = phase, let request = parked else { return }
        if skipVPNCheck {
            parked = nil
            Task { await run(request, skipVPNCheck: true) }
            return
        }
        Task {
            for _ in 0..<12 {
                if LocalDevVPN.isActive, case .needsVPN = phase, parked == request {
                    parked = nil
                    await run(request)
                    return
                }
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
    }

    func respond(_ response: String) {
        twoFactor = nil
        guard let session else { return }
        _ = response.withCString { altload_install_session_respond(session, $0) }
    }

    func cancel() {
        twoFactor = nil
        if let session {
            altload_install_session_cancel(session)
        } else if case .needsVPN = phase {
            parked = nil
            phase = .idle
        }
    }

    // MARK: - Run

    /// Runs one refresh. Returns nil when it couldn't start, failed, or is parked for LocalDevVPN.
    @discardableResult
    func run(_ request: Request, skipVPNCheck: Bool = false) async -> ProfileRefreshReport? {
        guard !isBusy else { return nil }
        if let reason = otherWork { return fail(reason, request) }
        guard let pairing = PairingStore.shared.selfPairing else {
            return fail(String(localized: "There's no pairing file for this iPhone yet. Import one in Tools › Pair."), request)
        }
        let email = AppleIDStore.email
        // Kept WhenUnlockedThisDeviceOnly, so this also fails while the iPhone is locked.
        guard !email.isEmpty, let password = AppleIDStore.password(for: email) else {
            return fail(String(localized: "Reloader needs your Apple ID with a remembered password. Sign in once in Settings › Apple ID with Remember Password on, and keep the iPhone unlocked while it refreshes."), request)
        }
        if !skipVPNCheck && !LocalDevVPN.isActive {
            parked = request
            phase = .needsVPN
            LocalDevVPN.turnOn()
            return nil
        }

        // A device task that's already running (AltServer, Pairing File to Apps) may be
        // adding or removing profiles too. Let it finish; new ones wait for this run.
        for _ in 0..<20 where DeviceOps.running > 0 {
            try? await Task.sleep(for: .milliseconds(500))
        }
        guard !isBusy else { return nil }
        if let reason = otherWork { return fail(reason, request) }
        guard DeviceOps.running == 0 else {
            return fail(String(localized: "Another device task is still running. Try again in a minute."), request)
        }

        phase = .running(request.dryRun ? String(localized: "Checking…") : String(localized: "Starting…"))
        stayAwake(true)
        defer { stayAwake(false) }

        let anisette = AnisetteServers.refreshServer(preferred: InstallController.shared.anisetteURL)
        var body: [String: Any] = [
            "dryRun": request.dryRun,
            // A check mustn't change the account: re-registering an expired App ID uses
            // one of the 10 a free account gets each week.
            "registerMissingAppIds": !request.dryRun,
            "only": NSNull(),
            "hostBundleId": NSNull()
        ]
        if let only = request.only { body["only"] = only }
        if let host = Hosting.hostBundleID { body["hostBundleId"] = host }
        let requestJSON = (try? JSONSerialization.data(withJSONObject: body))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

        let (code, output) = await runSession(
            email: email, password: password, anisette: anisette,
            pairingPath: pairing.fileURL.path, requestJSON: requestJSON)

        guard code == 0 else {
            if output == "Cancelled." {
                phase = .idle
                return nil
            }
            AppleIDStore.forgetPasswordIfRejected(message: output, email: email)
            var message = output.isEmpty ? String(localized: "The refresh failed (code \(code)).") : output
            if output.localizedCaseInsensitiveContains("anisette") || output.contains("-80045") || output.contains("-45061") {
                let host = URL(string: anisette)?.host() ?? anisette
                message += String(localized: "\n\nApple refused the sign-in data from \(host). Refreshes always use this one server, so Apple keeps seeing the same device. Pick another in Settings › Anisette, or tap Reset Anisette Data there, and try again in a few minutes.")
            }
            return fail(message, request)
        }
        guard var report = try? JSONDecoder().decode(ProfileRefreshReport.self, from: Data(output.utf8)) else {
            return fail(String(localized: "Couldn't read the refresh result."), request)
        }
        report.finishedAt = .now
        last = report
        if let data = try? JSONEncoder().encode(report) {
            UserDefaults.standard.set(data, forKey: lastKey)
        }
        if !report.dryRun {
            UserDefaults.standard.set(Date.now, forKey: refreshedKey)
            for row in report.results where row.status == "refreshed" {
                if let expiry = row.newExpiration {
                    InstallController.shared.recordProfileRefresh(bundleID: row.bundleId, expiration: expiry)
                }
            }
            scheduleReminder(report)
        }
        phase = .finished
        if request.announce {
            let (title, text) = Self.summary(report)
            notify(id: Self.resultID, title: title, body: text)
        }
        return report
    }

    /// Another job that signs in or opens a tunnel. One at a time, so the Apple session
    /// and the profiles on the device are never changed by two jobs at once.
    private var otherWork: String? {
        if InstallController.shared.isBusy {
            return String(localized: "An install is running. Refresh when it's done.")
        }
        if CertificatesController.shared.isBusy {
            return String(localized: "Reloader is loading your Apple ID's certificates. Refresh when that's done.")
        }
        return nil
    }

    @discardableResult
    private func fail(_ message: String, _ request: Request) -> ProfileRefreshReport? {
        phase = .failed(message)
        if request.announce {
            notify(id: Self.resultID, title: String(localized: "Couldn't refresh app profiles"), body: message)
        }
        return nil
    }

    private static func summary(_ report: ProfileRefreshReport) -> (String, String) {
        let attention = report.results.filter(\.needsAttention)
        let detail = attention.first.map { "\($0.app): \($0.reason ?? String(localized: "not renewed"))" }
        if report.dryRun {
            let planned = report.results.filter { $0.status == "planned" }.count
            let title = String(localized: "Checked app profiles")
            if let detail {
                return (title, String(localized: "\(planned) can be renewed, \(attention.count) need attention. \(detail)"))
            }
            return (title, String(localized: "\(planned) can be renewed. Nothing was installed."))
        }
        let renewed = report.results.filter { $0.status == "refreshed" }.count
        let title = renewed == 1 ? String(localized: "Renewed 1 profile") : String(localized: "Renewed \(renewed) profiles")
        if let detail {
            return (title, String(localized: "\(attention.count) need attention. \(detail)"))
        }
        let until = report.results.compactMap(\.newExpiration).min()
        return (title, until.map { String(localized: "Good until \($0.formatted(date: .abbreviated, time: .shortened)).") }
                ?? String(localized: "Everything is up to date."))
    }

    // MARK: - Rust bridge

    private func runSession(
        email: String,
        password: String,
        anisette: String,
        pairingPath: String,
        requestJSON: String
    ) async -> (Int32, String) {
        guard let session = altload_install_session_new() else {
            return (2, String(localized: "Couldn't start a session."))
        }
        self.session = session
        let ctx = Unmanaged.passRetained(self).toOpaque()
        let ctxBits = UInt(bitPattern: ctx)
        let sessionBits = UInt(bitPattern: session)
        let host = LocalDevVPN.targetIP
        let port = LocalDevVPN.remotePairingPort
        let deviceName = UIDevice.current.name

        let result: (Int32, String) = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let session = OpaquePointer(bitPattern: sessionBits) else {
                    continuation.resume(returning: (2, String(localized: "Invalid session.")))
                    return
                }
                var owned: [UnsafeMutablePointer<CChar>] = []
                func c(_ s: String) -> UnsafePointer<CChar>? {
                    guard let p = strdup(s) else { return nil }
                    owned.append(p)
                    return UnsafePointer(p)
                }
                var endpoint = AltLoadEndpoint(host: c(host), port: UInt16(clamping: port), identifier: nil, auth_tag: nil)
                var out: UnsafeMutablePointer<CChar>?
                let rc: Int32 = withUnsafePointer(to: &endpoint) { endpointPointer in
                    var config = AltLoadInstallConfig(
                        apple_id: c(email),
                        password: c(password),
                        anisette_url: c(anisette),
                        pairing_file_path: c(pairingPath),
                        host_name: c(PairingController.hostName),
                        endpoints: endpointPointer,
                        endpoint_count: 1,
                        ipa_path: nil, device_name: c(deviceName), machine_name: nil, server_id: nil,
                        capabilities: nil, extensions_mode: 0)
                    return altload_refresh_profiles_run(
                        session, &config, requestJSON,
                        refreshProgressCallback, refreshPromptCallback,
                        UnsafeMutableRawPointer(bitPattern: ctxBits), &out)
                }
                let text = out.map { String(cString: $0) } ?? ""
                if let out { altload_string_free(out) }
                // Wipe secrets before freeing.
                for p in owned {
                    memset(p, 0, strlen(p))
                    free(p)
                }
                continuation.resume(returning: (rc, text))
            }
        }

        altload_install_session_free(session)
        self.session = nil
        Unmanaged<ProfileRefresher>.fromOpaque(ctx).release()
        twoFactor = nil
        return result
    }

    // MARK: - Callbacks from Rust (hopped to main)

    fileprivate func updateProgress(_ stage: String) {
        guard isBusy else { return }
        phase = .running(stage)
    }

    fileprivate func presentPrompt(kind: Int32, json: Data) {
        // Only two-factor comes from a refresh; the core never asks to revoke anything.
        guard kind == 1 else {
            respond("abort")
            return
        }
        struct Payload: Decodable {
            let unknown: Bool
            let sms: Bool
            let lastError: String?
            let selectedNumberId: Int?
            let numbers: [TwoFactorPrompt.TrustedNumber]
        }
        guard let p = try? JSONDecoder().decode(Payload.self, from: json) else {
            respond("devices")
            return
        }
        twoFactor = TwoFactorPrompt(
            sms: p.sms, unknown: p.unknown, lastError: p.lastError,
            numbers: p.numbers, selectedNumberID: p.selectedNumberId)
    }

    // MARK: - Staying awake

    /// A refresh signs in, talks to Apple and opens two tunnels, which can outlast a
    /// trip to LocalDevVPN or the Home Screen. Silent audio keeps Reloader (and the
    /// LiveContainer it runs in) going meanwhile, whether or not AltServer is on.
    private func stayAwake(_ awake: Bool) {
        UIApplication.shared.isIdleTimerDisabled = awake
        guard awake else {
            keepAlive.stopAudio()
            endBackgroundTask()
            return
        }
        backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "Profile refresh") { [weak self] in
            MainActor.assumeIsolated { self?.endBackgroundTask() }
        }
        // AltServer's background audio already does this when it's on, and two players
        // would fight over the one audio session.
        if !AltServerHost.shared.keepAwake { keepAlive.startAudio() }
    }

    private func endBackgroundTask() {
        guard backgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }

    // MARK: - Notifications

    /// One reminder two days before the first renewed profile runs out.
    private func scheduleReminder(_ report: ProfileRefreshReport) {
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [Self.reminderID])
        let renewed = report.results.filter { $0.status == "refreshed" }
            .compactMap { row in row.newExpiration.map { (app: row.app, expires: $0) } }
        guard let first = renewed.min(by: { $0.expires < $1.expires }) else { return }
        let fireDate = first.expires.addingTimeInterval(-2 * 24 * 60 * 60)
        guard fireDate > .now else { return }
        let open = Hosting.isHosted
            ? String(localized: "Open \(Hosting.hostName), then Reloader, and tap Refresh Profiles.")
            : String(localized: "Open Reloader and tap Refresh Profiles.")
        notify(id: Self.reminderID,
               title: String(localized: "Refresh app profiles"),
               body: String(localized: "\(first.app)'s profile runs out in 2 days.") + " " + open,
               at: fireDate)
    }

    private func notify(id: String, title: String, body: String, at date: Date? = nil) {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let trigger = date.map {
                UNCalendarNotificationTrigger(
                    dateMatching: Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: $0),
                    repeats: false)
            }
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: trigger))
        }
    }
}

private let refreshProgressCallback: AltLoadProgressCb = { ctx, stage, _ in
    guard let ctx, let stage else { return }
    let refresher = Unmanaged<ProfileRefresher>.fromOpaque(ctx).takeUnretainedValue()
    let text = String(cString: stage)
    DispatchQueue.main.async { refresher.updateProgress(text) }
}

private let refreshPromptCallback: AltLoadPromptCb = { ctx, kind, json in
    guard let ctx, let json else { return }
    let refresher = Unmanaged<ProfileRefresher>.fromOpaque(ctx).takeUnretainedValue()
    let data = Data(String(cString: json).utf8)
    DispatchQueue.main.async { refresher.presentPrompt(kind: kind, json: data) }
}
