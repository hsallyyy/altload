# Security

Reloader is a personal build of AltLoad for its owner's own devices, based on AltLoad by mirazbakis – https://github.com/mirazbakis/AltLoad. It isn't distributed, so there are no releases to support and no one else to report to.

- A problem in AltLoad's own code: report it privately to AltLoad through its [Security › Report a vulnerability](https://github.com/mirazbakis/AltLoad/security/advisories/new) page.
- A problem in this build's changes (see [docs/PERSONAL-CHANGES.md](docs/PERSONAL-CHANGES.md)): fix it in this fork.
- Problems in AltStore, LiveContainer, LocalDevVPN, idevice, isideload or an anisette server belong to those projects.

## How this build handles your data

- **Apple ID password:** sent only to Apple's sign-in servers (GrandSlam SRP, so the password itself isn't transmitted). It's saved only with *Remember password* on, and then only in the iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: readable only while the device is unlocked, never synced or backed up.
- **Apple session:** not kept. Every install and refresh signs in again.
- **Anisette server:** receives device-identity data needed for the sign-in, never the password. Its identities are kept in `Application Support/AltLoad/anisette-mac27/<server>`; *Settings › Anisette › Reset Anisette Data* deletes them.
- **iloader's private key:** imported once per Apple ID into `Application Support/AltLoad/iloader-key`, excluded from backups, and never sent anywhere, Apple included. Reloader signs only with the certificate iloader already made for that key and never creates, requests or revokes a certificate.
- **Pairing files:** kept in the app's Documents folder. Anyone with a pairing file can connect to the device, so share them only with apps you trust.
- **Connections to the device:** go through LocalDevVPN and an encrypted TLS-PSK tunnel that only a valid pairing file can open.
- **Inside LiveContainer:** guests aren't sandboxed from each other, and all of them share LiveContainer's keychain groups. Another guest could read Reloader's files, the key included, and its saved password. Only run guests you trust next to it.
- **No tracking:** no analytics or telemetry. Apple ID credentials, Apple's tokens and pairing data go to Apple and to this device only.
- **CI:** the workflow's one secret, `IPA_PASSPHRASE`, encrypts the IPA artifact so that only you can use it. `.gitignore` keeps certificates, keys, provisioning profiles and pairing files out of the repository.

## Tips

- Never share your pairing files, `.p12` files or Apple ID password, and never revoke iloader's certificate.
- Turn LocalDevVPN off when you're not installing or refreshing.
