import AppIntents
import Foundation

/// "Refresh App Profiles" for Shortcuts, for a weekly personal automation (Time of Day,
/// Run Immediately, at an hour the iPhone is usually unlocked: the remembered password
/// and opening an app both need that). It opens Reloader, starts the refresh and returns
/// straight away; the result arrives as a notification. Only a Reloader installed as its
/// own app shows up in Shortcuts: iOS doesn't know about LiveContainer's guests.
struct RefreshProfilesIntent: AppIntent {
    static var title: LocalizedStringResource = "Refresh App Profiles"
    static var description = IntentDescription("Renews the 7-day provisioning profiles of the apps signed with your certificate, without reinstalling them.")
    static var openAppWhenRun: Bool = true

    @Parameter(title: "Check Only", description: "Lists what a refresh would do, without installing anything or registering App IDs.", default: false)
    var checkOnly: Bool

    @Parameter(title: "Only This App", description: "A bundle ID such as com.kdt.livecontainer.ABCDE12345. Leave empty for every app.")
    var bundleID: String?

    @Parameter(title: "Skip If Refreshed Within (Days)", default: 0)
    var skipIfRefreshedWithinDays: Int

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let refresher = ProfileRefresher.shared
        if skipIfRefreshedWithinDays > 0, let last = refresher.lastRefreshed,
           Date.now.timeIntervalSince(last) < Double(skipIfRefreshedWithinDays) * 24 * 60 * 60 {
            let when = last.formatted(.relative(presentation: .named))
            return .result(dialog: "Skipped. Reloader refreshed app profiles \(when).")
        }
        guard !refresher.isBusy else {
            return .result(dialog: "Reloader is already refreshing app profiles.")
        }
        let only = bundleID?.trimmingCharacters(in: .whitespacesAndNewlines)
        refresher.start(dryRun: checkOnly, only: only.flatMap { $0.isEmpty ? nil : [$0] }, announce: true)
        return .result(dialog: checkOnly
            ? "Checking app profiles. Reloader sends a notification with what it found."
            : "Refreshing app profiles. Reloader sends a notification when it's done.")
    }
}

struct ReloaderShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: RefreshProfilesIntent(),
            phrases: [
                "Refresh app profiles with \(.applicationName)",
                "Refresh profiles in \(.applicationName)"
            ],
            shortTitle: "Refresh App Profiles",
            systemImageName: "arrow.triangle.2.circlepath")
    }
}
