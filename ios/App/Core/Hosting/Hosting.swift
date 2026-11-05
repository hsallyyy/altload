import Foundation
import ObjectiveC

/// Reloader usually runs as a JIT-less guest inside LiveContainer, which signs it on the
/// device with the .p12 imported there and starts it in LiveContainer's own process. This
/// tells the two cases apart and reads what LiveContainer leaves for its guests. Every
/// name used here comes from LiveContainer's source (LCBootstrap.m, LCSharedUtils.m).
enum Hosting {
    /// LiveContainer's own home folder. LiveContainer sets LC_HOME_PATH before it points
    /// HOME at the guest's data folder, so it's only there when Reloader runs as a guest.
    /// In multitasking mode LiveProcess sets it to LiveContainer's home as well.
    static let liveContainerHome: URL? = {
        guard let raw = getenv("LC_HOME_PATH") else { return nil }
        let path = String(cString: raw)
        return path.isEmpty ? nil : URL(fileURLWithPath: path, isDirectory: true)
    }()

    static var isHosted: Bool { liveContainerHome != nil }

    /// LiveContainer's own bundle. Bundle.main is Reloader's inside a guest, so this comes
    /// from +[NSUserDefaults lcMainBundle], which LiveContainer saves before the swap. In
    /// a LiveProcess window that's the extension, so step out to the app around it.
    static let hostBundle: Bundle? = {
        guard Hosting.isHosted, let bundle = Hosting.liveContainerObject("lcMainBundle") as? Bundle else { return nil }
        guard bundle.bundleURL.pathExtension == "appex" else { return bundle }
        return Bundle(url: bundle.bundleURL.deletingLastPathComponent().deletingLastPathComponent()) ?? bundle
    }()

    /// LiveContainer's installed bundle ID, e.g. com.kdt.livecontainer.ABCDE12345
    /// (isideload appends the team ID when it signs). Without its bundle, the ID iloader
    /// gives it for the team it's signed with.
    static var hostBundleID: String? {
        hostBundle?.bundleIdentifier ?? teamID.map { "com.kdt.livecontainer.\($0)" }
    }

    static var hostName: String {
        hostBundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? "LiveContainer"
    }

    /// The team LiveContainer is signed with, from +[LCSharedUtils teamIdentifier]
    /// (its com.apple.developer.team-identifier entitlement). Not from hostBundleID,
    /// which falls back on this.
    static let teamID: String? = {
        guard Hosting.isHosted,
              let team = Hosting.liveContainerObject("teamIdentifier", of: "LCSharedUtils") as? String,
              !team.isEmpty else { return nil }
        return team
    }()

    /// The scheme LiveContainer registered (+[NSUserDefaults lcAppUrlScheme]): livecontainer,
    /// livecontainer2… Opening it with no host just brings LiveContainer to the front.
    static let urlScheme: String? = Hosting.isHosted ? Hosting.liveContainerObject("lcAppUrlScheme") as? String : nil

    /// The pairing file iloader puts into LiveContainer's built-in SideStore: house_arrest
    /// Documents, then SideStore/Documents/ALTPairingFile.mobiledevicepairing
    /// (iloader src-tauri/src/pairing.rs).
    static var iloaderPairingFile: URL? {
        guard let home = liveContainerHome else { return nil }
        let url = home.appendingPathComponent("Documents/SideStore/Documents/ALTPairingFile.mobiledevicepairing")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    /// Whether installing an IPA with this bundle ID would replace the LiveContainer that
    /// Reloader is running in. Signing turns com.kdt.livecontainer into
    /// com.kdt.livecontainer.<team>, so compare with the team suffix added.
    static func wouldReplaceHost(_ bundleID: String) -> Bool {
        let id = bundleID.lowercased()
        // A guest that can't tell which LiveContainer it's in treats every one as its host.
        guard let host = hostBundleID?.lowercased() else { return isHosted && id.hasPrefix("com.kdt.livecontainer") }
        if id == host { return true }
        guard let team = teamID?.lowercased() else { return host.hasPrefix(id + ".") }
        return "\(id).\(team)" == host
    }

    /// The .p12 and password LiveContainer signs its guests with (its JIT-less setup). It
    /// keeps them in its app-group defaults as LCCertificateData and LCCertificatePassword.
    /// A guest's own NSUserDefaults are redirected into its data folder, so this goes
    /// through +[NSUserDefaults lcSharedDefaults], the instance LiveContainer opened
    /// before it started the guest.
    static var liveContainerCertificate: (data: Data, password: String)? {
        guard isHosted, let shared = liveContainerObject("lcSharedDefaults") as? UserDefaults,
              let data = shared.data(forKey: "LCCertificateData"), !data.isEmpty else { return nil }
        let own = liveContainerObject("lcUserDefaults") as? UserDefaults
        guard let password = shared.string(forKey: "LCCertificatePassword")
                ?? own?.string(forKey: "LCCertificatePassword") else { return nil }
        return (data, password)
    }

    /// Calls a class method LiveContainer adds (a category on NSUserDefaults, or its
    /// LCSharedUtils class) that takes no arguments and returns an object.
    private static func liveContainerObject(_ selectorName: String, of className: String = "NSUserDefaults") -> AnyObject? {
        guard let cls = NSClassFromString(className) else { return nil }
        let selector = NSSelectorFromString(selectorName)
        guard let method = class_getClassMethod(cls, selector) else { return nil }
        typealias Getter = @convention(c) (AnyObject, Selector) -> Unmanaged<AnyObject>?
        let getter = unsafeBitCast(method_getImplementation(method), to: Getter.self)
        return getter(cls as AnyObject, selector)?.takeUnretainedValue()
    }
}
