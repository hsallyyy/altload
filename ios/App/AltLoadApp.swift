import SwiftUI
import UserNotifications

@main
struct AltLoadApp: App {
    /// Reloader's own URL scheme: LocalDevVPN hands control back through it, and
    /// reloader://refresh-profiles[?only=<bundle ID>] starts a profile refresh.
    nonisolated static let urlScheme = "reloader"

    init() {
        PairingController.shared.registerBackgroundTask()
        UNUserNotificationCenter.current().delegate = NotificationPresenter.shared
        // Be ready as soon as AltStore looks for an AltServer.
        AltServerHost.shared.startIfEnabled()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .auroraTheme()
        }
    }
}

enum AppTab: Hashable {
    case install, tools, about
}

struct RootView: View {
    @State private var tab: AppTab = .install
    @StateObject private var install = InstallController.shared
    @StateObject private var refresher = ProfileRefresher.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView(selection: $tab) {
            Tab(String(localized: "Install"), systemImage: "tray.and.arrow.down.fill", value: AppTab.install) {
                InstallView(selectedTab: $tab)
            }
            Tab(String(localized: "Tools"), systemImage: "wrench.and.screwdriver.fill", value: AppTab.tools) {
                ToolsView()
            }
            .badge(expiringSoon)
            Tab(String(localized: "About"), systemImage: "info", value: AppTab.about) {
                AboutView()
            }
        }
        .minimizingTabBarOnScroll()
        // Installs and refreshes run full screen over whichever tab started them.
        .fullScreenCover(item: $install.flow) { target in
            InstallFlowView(target: target) { RootView.openPair(tab: $tab) }
                .auroraTheme()
        }
        // Two-factor for a profile refresh, wherever it was started from.
        .fullScreenCover(item: $refresher.twoFactor) { prompt in
            TwoFactorSheet(prompt: prompt) { refresher.respond($0) }
                .auroraTheme()
        }
        .onOpenURL { url in
            guard url.scheme == AltLoadApp.urlScheme else { return }
            if url.host() == "refresh-profiles" {
                let only = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                    .queryItems?.first(where: { $0.name == "only" })?.value
                tab = .install
                // An idle install flow would cover the two-factor sheet. One waiting for
                // LocalDevVPN stays open.
                if install.flow != nil && !install.isBusy && install.phase != .needsVPN { install.finish() }
                refresher.start(only: only.flatMap { $0.isEmpty ? nil : [$0] }, announce: true)
                return
            }
            // LocalDevVPN returns here after switching the VPN on.
            install.resumeWhenVPNReady()
            refresher.resumeIfParked()
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                AltServerHost.shared.refresh()
                // Inside LiveContainer, LocalDevVPN can only send the user back to
                // LiveContainer, so coming to the front is the signal to carry on.
                refresher.resumeIfParked()
            }
        }
    }

    /// Apps that expire within a day (or already have), shown on the Tools tab.
    private var expiringSoon: Int {
        install.apps.filter { $0.isExpired || ($0.daysLeft ?? 99) < 1 }.count
    }

    /// Switches to Tools and opens Pair.
    static func openPair(tab: Binding<AppTab>) {
        tab.wrappedValue = .tools
        ToolsRouter.shared.path = [.pair]
    }
}

/// Shows Reloader's own refresh notifications while it's open too (a Shortcut brings it
/// to the front before the refresh finishes). Everything else stays quiet in the
/// foreground, as it did before there was a delegate.
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationPresenter()

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        let identifier = notification.request.identifier
        completionHandler(identifier.hasPrefix(ProfileRefresher.notificationPrefix) ? [.banner, .list, .sound] : [])
    }
}

private extension View {
    /// Tucks the tab bar away while scrolling down, on iOS 26 and later.
    @ViewBuilder
    func minimizingTabBarOnScroll() -> some View {
        if #available(iOS 26, *) {
            tabBarMinimizeBehavior(.onScrollDown)
        } else {
            self
        }
    }
}
