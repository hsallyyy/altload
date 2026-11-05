import Foundation

/// Public anisette v3 servers. Reloader ships a built-in list and refreshes it
/// from SideStore's community list (https://servers.sidestore.io/servers.json).
struct AnisetteServer: Codable, Hashable, Identifiable {
    let name: String
    let address: String
    /// servers.json "kind": 2 for Mac-ADI servers (mac-ani.jkcoxson.com,
    /// new.ani.sidestore.io), 1 for Windows-ADI ones. nil for the built-in entries.
    var kind: Int? = nil
    var id: String { address }
}

@MainActor
final class AnisetteServers: ObservableObject {
    static let shared = AnisetteServers()

    static let listURL = URL(string: "https://servers.sidestore.io/servers.json")!

    /// Stored as the anisette choice when Reloader should pick a working server itself.
    static let automatic = "auto"

    /// iloader 2.4.1's default server. Profile refreshes use it whenever the choice is
    /// Automatic, so Apple keeps seeing the same anisette identity week after week.
    static let iloaderDefault = "https://mac-ani.jkcoxson.com"

    /// iloader 2.4.1's list (src/pages/Settings.tsx), in its order: Mac-ADI servers only.
    /// iloader leaves the Windows-ADI ones out because they "work ~50% of the time, and
    /// don't work with SMS 2FA". The Rust core sends the macOS 27 client info to all of them.
    static let builtIn: [AnisetteServer] = [
        AnisetteServer(name: "jkcoxson", address: iloaderDefault),
        AnisetteServer(name: "iloader", address: "https://ani.iloader.app"),
        AnisetteServer(name: "SideStore (.io)", address: "https://new.ani.sidestore.io"),
        AnisetteServer(name: "StikStore", address: "https://ani3.stikstore.app")
    ]

    @Published private(set) var servers: [AnisetteServer] = AnisetteServers.builtIn
    @Published private(set) var isLoading = false

    private struct Listing: Decodable {
        let servers: [AnisetteServer]
    }

    /// Merges the live list into the built-in one. HTTPS only, since sign-in headers pass
    /// through it, and Mac-ADI only, for the same reason the built-in list is.
    func refresh() async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let (data, _) = try await URLSession.shared.data(from: Self.listURL)
            let live = try JSONDecoder().decode(Listing.self, from: data).servers
                .filter { $0.address.lowercased().hasPrefix("https://") && $0.kind == 2 }
            var merged = Self.builtIn
            for server in live where !merged.contains(where: { $0.address == server.address }) {
                merged.append(server)
            }
            servers = merged
        } catch {
            servers = Self.builtIn
        }
    }

    func name(for address: String) -> String? {
        if address == Self.automatic { return "Automatic" }
        return servers.first { $0.address == address }?.name
    }

    /// The servers to sign in with, best first, joined by newlines for the Rust side,
    /// which moves on to the next one when Apple or a server rejects the anisette data.
    /// A server the user picked goes first; servers that don't answer are dropped.
    func signInList(preferred: String) async -> String {
        var order = servers.map(\.address)
        let pinned = preferred != Self.automatic && !preferred.isEmpty
        if pinned {
            order.removeAll { $0 == preferred }
            order.insert(preferred, at: 0)
        }
        let candidates = Array(order.prefix(8))
        let alive = await withTaskGroup(of: (String, Bool).self) { group in
            for address in candidates {
                group.addTask { (address, await Self.isAlive(address)) }
            }
            var results: [String: Bool] = [:]
            for await (address, ok) in group { results[address] = ok }
            return results
        }
        var picked = candidates.filter { alive[$0] == true }
        // A server the user chose is always tried, even if the check missed it.
        if pinned, !picked.contains(preferred) { picked.insert(preferred, at: 0) }
        if picked.isEmpty { picked = Array(candidates.prefix(3)) }
        return picked.prefix(4).joined(separator: "\n")
    }

    /// The one server a profile refresh signs in with: the one picked in Settings, or
    /// iloader's default when that's Automatic. Never a rotation: each server is its own
    /// anisette identity, and a new one tends to bring two-factor back, which an
    /// unattended weekly run can't answer.
    static func refreshServer(preferred: String) -> String {
        let chosen = preferred.trimmingCharacters(in: .whitespacesAndNewlines)
        return chosen.isEmpty || chosen == automatic ? iloaderDefault : chosen
    }

    /// Quick check that a v3 server answers with its client info.
    nonisolated static func isAlive(_ address: String) async -> Bool {
        guard let url = URL(string: address.trimmingCharacters(in: .whitespaces) + "/v3/client_info") else { return false }
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return json["client_info"] is String
    }

    /// Removes the anisette identities Reloader provisioned, so the next sign-in
    /// starts clean. Useful after Apple rejects one.
    nonisolated static func resetProvisioning() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        // The core keeps the identities made with the macOS 27 client info in
        // anisette-mac27/<server>; anisette/ is where older builds kept theirs.
        for folder in ["AltLoad/anisette-mac27", "AltLoad/anisette"] {
            try? FileManager.default.removeItem(at: support.appendingPathComponent(folder, isDirectory: true))
        }
    }
}
