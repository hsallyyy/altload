# Personal changes

What this fork (the app **Reloader**) changes compared with upstream AltLoad at `d2cf4f9`. Based on AltLoad by mirazbakis – https://github.com/mirazbakis/AltLoad.

None of it has been compiled or run yet. The two lists at the end are what the first CI build and the first run on a device have to confirm.

## Name and identity (LICENSE.md §6)

- The app is called Reloader everywhere users see it: `CFBundleDisplayName` and `CFBundleName` (isideload names App IDs after the latter), the pairing host name, notifications and texts. The widget's bundle name is "Reloader Widgets".
- Bundle IDs are `com.haris.reloader` and `com.haris.reloader.widgets`, the URL scheme is `reloader://`, and the Local Network probe type is `_reloaderprobe._tcp`. The icon has new artwork (`AltLoad.icon` now draws `Cycle.svg`).
- Internal names that users never see keep upstream's spelling so upstream changes still merge: the Xcode target and module `AltLoad`, `AltLoadFFI`, the `altload_*` C symbols, `Application Support/AltLoad`, `ALTLOAD_PRERELEASE`.
- About keeps the exact credit from §4 and shows `LICENSE.md` and `THIRD_PARTY_NOTICES.md`, which are now bundled in the app (§1) instead of being links to upstream's main branch.
- CI fails if a bundle still has a `com.mirazbakis` ID or a display or bundle name starting with AltLoad, or if the two notice files are missing from the IPA.

## Removed: everything that distributes

- `signing/` (the certificate packs), `site/` (install site, DNS profile, terms), `source.json`, `docs/releases/`, `docs/assets/`, the `sign-ipa.yml` and `sign-ota.yml` workflows, upstream's `.claude/` files, and `UpdateChecker` with its update alert. The packs are still in upstream's git history, which every fork shares.
- `README.md` and `SECURITY.md` are rewritten for a personal build. `docs/PERSONAL-SETUP.md` and this file are new.

## Signing only with iloader's certificate

- `core/src/install/identity.rs` (new): iloader's private key is imported once per Apple ID with `altload_import_signing_key`. It accepts a `.p12` (LiveContainer's, for example) or a raw RSA key (PKCS#8 or PKCS#1 DER, PEM, base64), and stores it in `Application Support/AltLoad/iloader-key`, excluded from backups. `existing_identity` then finds the unexpired, unrevoked iOS development certificate with that public key on the account. If there's none, installs and refreshes stop and say so.
- isideload's own signing flow isn't used, because it asks Apple for a new certificate whenever it finds no match. `sign_with_main_profile` signs with the certificate it's given and always signs extensions with the main app's profile (one App ID per app, like iloader 2.4.1's ReuseMain). LiveContainer gets Increased Memory Limit, as iloader asks for it.
- Nothing revokes. The revoke prompt (kind 2) and its sheet are gone, `altload_account_session_run` refuses `{"op":"revoke"}` before signing in, and Tools › Certificates marks iloader's certificate instead of offering Revoke.
- `core/build.rs` (new) fails every `cargo build` if anything under `core/src` names an isideload call that requests or revokes a certificate.
- Apple IDs are trimmed and lowercased everywhere, as iloader does, so the key's storage name matches.
- Swift: Tools › Signing Certificate (`SigningCertificateView`, `SigningKeyStore`). Inside LiveContainer, **Use LiveContainer's Certificate** reads `LCCertificateData` and `LCCertificatePassword` from LiveContainer's shared defaults; otherwise pick a file. An install refuses to start without an imported key.

## Sign-in like iloader 2.4.1

- isideload `=0.5.2` instead of 0.4.6, with iloader's macOS 27 client-info override and serial `0`.
- Anisette identities live in `anisette-mac27/<server>`. Settings › Anisette › Reset Anisette Data clears that folder and the old `anisette/` one.
- The built-in anisette list is iloader's Mac-ADI servers, `mac-ani.jkcoxson.com` first (also the Rust default), and the live list is filtered to Mac-ADI servers. Profile refreshes always use one server: the one picked, or `mac-ani.jkcoxson.com` for Automatic.
- A two-factor prompt gives up after 120 s.

## Profile-only refresh (new)

- `core/src/install/refresh.rs`, `altload_refresh_profiles_run`:
  1. Reads the device's apps and provisioning profiles over the tunnel, then closes it.
  2. Signs in and loads the team, iloader's certificate and the App IDs.
  3. For each target, re-registers a lapsed App ID (not in a dry run, and only with `registerMissingAppIds`), restoring its app groups (`group.com.SideStore.SideStore.<TEAMID>` for LiveContainer) and Increased Memory Limit. It downloads a new profile and checks that it lists this device, grants every entitlement the app is signed with, is for the same App ID and lists iloader's certificate.
  4. Installs each new profile with misagent and only then removes older copies, once iOS lists the new one. If the new one disappears afterwards, the newest old copy goes back.
- Targets when `only` is null: first the host LiveContainer (`hostBundleId`, or iloader's `com.kdt.livecontainer.<TEAMID>` when Reloader runs as a normal app), then Reloader itself when it's installed, then every other app of the team whose newest profile lists iloader's certificate. Each app is followed by its extensions' own profiles, but only those it still uses. That comes from the profiles inside its bundle when Reloader can read them (a guest can read LiveContainer's), otherwise from their expiry. Profiles left over from an iloader install before 2.4, which gave each extension an App ID, show as skipped until they run out and are never renewed.
- A dry run (Check Only) changes nothing on the account or the device.
- Swift: `ProfileRefresher` keeps Reloader awake (silent audio and a background task), waits for LocalDevVPN, shows 2FA wherever the refresh started, keeps the last report, moves tracked apps' expiry dates and reminders, reminds 2 days before the first renewed profile runs out, and posts results for Shortcut and link runs. `ProfileRefreshCard` on the Install tab has Refresh Profiles and Check Only, and a long-press on a row renews one app. Runs can also start from `reloader://refresh-profiles[?only=<bundle ID>]` and from the "Refresh App Profiles" App Intent (only when Reloader is a normal app). Installs, device ops and the certificate manager don't start while a refresh runs, and the other way round.

## Inside LiveContainer

- `Hosting.swift` (new) detects the guest (`LC_HOME_PATH`) and reads LiveContainer's bundle, team, URL scheme and imported certificate through its own class methods. Without the bundle, the host ID falls back to `com.kdt.livecontainer.<team>`.
- **Use iloader's Pairing File** imports the pairing file iloader placed in LiveContainer's SideStore folder.
- LocalDevVPN hands back through LiveContainer's scheme, and Reloader carries on when it comes to the front.
- The Local Network probe uses `_stikpairprobe._tcp`, which LiveContainer declares. A browse still waiting after 15 s counts as refused.
- There's no Live Activity, BGTaskScheduler task or AltServer Wi-Fi listener inside LiveContainer, since none of them can work there. The pairing code arrives as a notification.
- Installing an IPA over the LiveContainer Reloader runs in is refused, including when the IPA's bundle ID can't be read.

## AltServer and device ops

- AltServer and its keep-awake audio are off by default.
- `install_profiles` without an active list installs first and removes old copies afterwards. Upstream removed them first.
- The profiles of `protect` IDs, of their extensions and of any LiveContainer are never removed by AltStore's profile juggling, and `remove_app` refuses those apps. The cost: AltStore can't deactivate a LiveContainer it installed itself.

## Build

- One workflow, **Build Reloader (personal)**. It runs only by hand, with a read-only token. It runs `cargo test` (which also runs `build.rs`'s guard), builds the xcframework and an ad-hoc-signed IPA, checks the IPA, and uploads only `Reloader.ipa.enc` (AES-256-CBC, PBKDF2 with 600,000 iterations, secret `IPA_PASSPHRASE`). The plain IPA is uploaded only from a private repository. `tools/decrypt.html` decrypts the file in Safari.
- `.gitattributes` keeps every text file LF.

## C interface (`core/include/altload.h`)

- New: `altload_import_signing_key`, `altload_has_signing_key`, `altload_refresh_profiles_run`.
- Changed: prompt kind 2 is never sent, `altload_account_session_run` refuses `revoke`, `AltLoadInstallConfig.machine_name` is ignored, and `extensions_mode` 0 and 1 both sign extensions with the main profile.

## To confirm on the first CI build

- The runner label `runs-on: xcode-27` and `xcode-version: '27.1'`. Neither is verified. `macos-26` is the untested fallback.
- The first compile of the Rust changes, which were checked only against the crate sources. That covers isideload 0.5.2's builder and `sign::sign`, the `rsa`, `x509-cert`, `sha2 0.11` and `isideload-p12-keystore` calls in `identity.rs`, and all of `refresh.rs`. `Cargo.lock` is re-resolved (no `--locked`). `x509-cert` and `rsa` must resolve to the same versions isideload uses, or `CertificateIdentity` won't accept the types. isideload needs Rust 1.88 or later.
- `cargo test`: the new tests cover target order, leftover extension profiles, reading a bundle's extension profiles, the protect rules and the report shapes.
- The Swift build, including App Intents metadata extraction and Swift 6 concurrency warnings in Swift 5 mode. New strings aren't in the string catalogs yet, so they show in English.
- The **Check the IPA** step: the notice files are bundled and the CFBundleName check passes.

## To confirm on the first run on a device

- Sign-in: isideload 0.5.2 with the macOS 27 client info through `mac-ani.jkcoxson.com`, with trusted-device 2FA. Apple may change GrandSlam again.
- Signing Certificate: a guest can read LiveContainer's `.p12` and password, the `.p12` decodes, and the account lists iloader's certificate with a machine ID.
- installation_proxy's Lookup returns `Entitlements` and `Path`, and the guest can read LiveContainer's `PlugIns/*.appex/embedded.mobileprovision`. If it can't, extension profiles are judged by expiry.
- misagent through the RSD shim on iOS 26.5 installs a new profile for an installed app and removes the old ones, with LiveContainer still running. Test this first with **Check Only**, then long-press LiveContainer › **Refresh Only This App**.
- Lapsed free App IDs: whether `list_app_ids` drops them or still lists them with a past expiration date, whether `add_app_id` takes the same identifier again, and whether the restored groups and memory limit make the new profile grant everything LiveContainer is signed with (app groups, Increased Memory Limit, and the 128 keychain groups through `<TEAMID>.*`).
- Apple's new profile lists the device. If it doesn't, the refresh now stops for that app and keeps the current profile.
- Each device signs in with the Apple ID whose team ends LiveContainer's bundle ID. A mismatch shows as skipped.
- The Check Only report for LiveContainer's extensions (LiveProcess, ShareExtension, LaunchAppExtension) matches how iloader last signed it: planned for an install before 2.4, left over after a 2.4 install.
- Inside LiveContainer: the LocalDevVPN round trip, the 2FA sheet, notifications with Fix Local Notifications on, and silent audio keeping a refresh alive while switching apps.
- On iOS 27 only: on-device pairing inside LiveContainer with `_stikpairprobe._tcp` and the 15 s grace.
- As a normal app: it costs one App ID, the Shortcuts action appears, and the BGTask identifier `$(PRODUCT_BUNDLE_IDENTIFIER).pairing` may not match the team-suffixed bundle ID after signing.
- IPAs from Files inside LiveContainer: Reloader must read their bundle ID, or the install is refused. ZIP64 IPAs always are.
