import ActivityKit
import Foundation

/// Shows the pairing code in the Dynamic Island (and on the Lock Screen on
/// iPhones without one) while the user is in Settings entering it.
///
/// A Live Activity can only be started while Reloader is in the foreground, so
/// it starts when pairing starts and is updated with the code from the background.
/// Inside LiveContainer there's no widget extension to draw it, so it's skipped there
/// and the code arrives as a notification instead.
@MainActor
final class PairingLiveActivity {
    static let shared = PairingLiveActivity()

    private var activity: Activity<PairingActivityAttributes>?

    private init() {}

    func start(hostName: String) {
        guard !Hosting.isHosted, ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        endAll()
        let state = PairingActivityAttributes.ContentState(status: .waiting, code: nil)
        activity = try? Activity.request(
            attributes: PairingActivityAttributes(hostName: hostName),
            content: ActivityContent(state: state, staleDate: nil, relevanceScore: 100))
    }

    func show(code: String) {
        update(.init(status: .code, code: code))
    }

    /// Leaves the result up for a few seconds, then removes it.
    func finish(success: Bool) {
        guard let activity else { return }
        self.activity = nil
        let state = PairingActivityAttributes.ContentState(status: success ? .paired : .failed, code: nil)
        Task {
            await activity.end(ActivityContent(state: state, staleDate: nil),
                               dismissalPolicy: .after(.now + 4))
        }
    }

    /// Removes every pairing activity right away, including ones left over from
    /// an earlier launch that ended without cleaning up.
    func endAll() {
        activity = nil
        guard !Hosting.isHosted else { return }
        for leftover in Activity<PairingActivityAttributes>.activities {
            Task { await leftover.end(nil, dismissalPolicy: .immediate) }
        }
    }

    private func update(_ state: PairingActivityAttributes.ContentState) {
        guard let activity else { return }
        Task {
            await activity.update(ActivityContent(state: state, staleDate: nil, relevanceScore: 100))
        }
    }
}
