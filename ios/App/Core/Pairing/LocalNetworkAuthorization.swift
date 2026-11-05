import Foundation
import Network

@MainActor
final class LocalNetworkAuthorization {
    private var browser: NWBrowser?
    private var listener: NWListener?
    private var continuation: CheckedContinuation<Bool, Never>?

    /// Bonjour only works for types the app's Info.plist lists. Inside LiveContainer that's
    /// LiveContainer's list, which declares _stikpairprobe._tcp for this same purpose.
    private let probeType = Hosting.isHosted ? "_stikpairprobe._tcp" : "_reloaderprobe._tcp"

    func request(timeout: TimeInterval = 60) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            self.continuation = cont

            let params = NWParameters.tcp
            params.includePeerToPeer = true

            let listener = try? NWListener(using: params)
            listener?.service = NWListener.Service(name: "ReloaderProbe", type: probeType)
            listener?.newConnectionHandler = { $0.cancel() }
            listener?.stateUpdateHandler = { [weak self] state in
                if case .failed = state {
                    MainActor.assumeIsolated { self?.finish(false) }
                }
            }
            self.listener = listener

            let browser = NWBrowser(for: .bonjour(type: probeType, domain: nil), using: params)
            browser.stateUpdateHandler = { [weak self] state in
                switch state {
                case .failed:
                    MainActor.assumeIsolated { self?.finish(false) }
                // A refused Bonjour browse waits (kDNSServiceErr_PolicyDenied) instead of
                // failing. Inside LiveContainer that's what a denied permission looks like,
                // so don't sit out the whole timeout. The browse also waits while the Local
                // Network alert is still up, so give the user time to answer it first.
                case .waiting where Hosting.isHosted:
                    DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
                        MainActor.assumeIsolated {
                            guard let self, case .waiting = self.browser?.state else { return }
                            self.finish(false)
                        }
                    }
                default:
                    break
                }
            }
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                if !results.isEmpty {
                    MainActor.assumeIsolated { self?.finish(true) }
                }
            }
            self.browser = browser

            listener?.start(queue: .main)
            browser.start(queue: .main)

            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
                MainActor.assumeIsolated { self?.finish(false) }
            }
        }
    }

    private func finish(_ authorized: Bool) {
        guard let cont = continuation else { return }
        continuation = nil
        cont.resume(returning: authorized)
        browser?.cancel(); browser = nil
        listener?.cancel(); listener = nil
    }
}
