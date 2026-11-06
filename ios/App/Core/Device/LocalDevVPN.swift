import Darwin
import Foundation
import UIKit

/// LocalDevVPN (App Store, by jkcoxson / Stossy11) is a loopback VPN. It routes
/// 10.7.0.1 into a tunnel whose provider swaps each packet's source and
/// destination addresses and writes it straight back. A connection Reloader opens
/// to 10.7.0.1 therefore arrives at this iPhone's own services as if it came from
/// another machine, which is what remotepairingd needs. No computer is involved.
enum LocalDevVPN {
    static let appStoreURL = URL(string: "https://apps.apple.com/app/id6755608044")!
    static let defaultTargetIP = "10.7.0.1"
    /// remotepairingd's RemotePairing port (the same one StikDebug uses).
    static let remotePairingPort = 49152

    /// Opens LocalDevVPN, turns the VPN on and comes back through `scheme`. A guest's
    /// own scheme isn't registered with iOS, so inside LiveContainer it's LiveContainer's,
    /// which only brings LiveContainer to the front; Reloader carries on from there.
    static var enableURL: URL {
        let scheme = Hosting.urlScheme ?? AltLoadApp.urlScheme
        return URL(string: "localdevvpn://enable?scheme=\(scheme)")!
    }

    static var targetIP: String {
        get {
            let stored = UserDefaults.standard.string(forKey: "vpn.targetIP")?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return (stored?.isEmpty == false) ? stored! : defaultTargetIP
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed == defaultTargetIP {
                UserDefaults.standard.removeObject(forKey: "vpn.targetIP")
            } else {
                UserDefaults.standard.set(trimmed, forKey: "vpn.targetIP")
            }
        }
    }

    /// Inside LiveContainer iOS can't say: canOpenURL only answers for schemes the host
    /// app lists, and LiveContainer doesn't list localdevvpn. Then assume it's there and
    /// let turnOn() fall back to the App Store.
    @MainActor
    static var isInstalled: Bool {
        Hosting.isHosted || UIApplication.shared.canOpenURL(URL(string: "localdevvpn://")!)
    }

    /// True when a VPN interface (utun*) holds an address in the same /16 as the
    /// target (LocalDevVPN's defaults: interface 10.7.1.1, peer 10.7.0.1).
    static var isActive: Bool {
        // Another device on the same Wi-Fi is reached directly, not through LocalDevVPN.
        if !targetIP.hasPrefix("10.7.") { return true }
        let prefix = targetIP.split(separator: ".").prefix(2).joined(separator: ".") + "."
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return false }
        defer { freeifaddrs(head) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            guard name.hasPrefix("utun"),
                  let addr = entry.pointee.ifa_addr,
                  addr.pointee.sa_family == sa_family_t(AF_INET),
                  (entry.pointee.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count),
                           nil, 0, NI_NUMERICHOST) == 0,
               String(cString: host).hasPrefix(prefix) {
                return true
            }
        }
        return false
    }

    /// Asks LocalDevVPN to turn the VPN on. Only when iOS can't open it (it isn't
    /// installed) does this go to its App Store page instead.
    @MainActor
    static func turnOn() {
        Task {
            let opened = await UIApplication.shared.open(enableURL)
            if !opened { _ = await UIApplication.shared.open(appStoreURL) }
        }
    }
}
