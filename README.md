# Reloader

> Based on AltLoad by mirazbakis – https://github.com/mirazbakis/AltLoad

**Personal build — never distribute builds.** This branch exists so I can build the app for my own devices. It has no releases, no install site and no AltStore/SideStore source, and none may be added.

## What it is

Reloader keeps sideloaded apps alive on a free Apple ID without a computer. It renews the 7-day provisioning profiles of the apps already signed with the certificate iloader made, starting with the LiveContainer it runs in and that LiveContainer's extensions, and installs the new profiles on the device. Nothing is reinstalled.

- It runs mainly as a JIT-less guest inside LiveContainer, and also works as a normal app.
- It signs only with the certificate iloader already made, matched to the private key you import. It never creates, requests or revokes a certificate.
- It signs in to Apple the way iloader 2.4.1 does. Nothing sends Apple ID credentials, tokens or pairing data anywhere but Apple (LICENSE.md §7).

It is a modified copy of AltLoad, not the official app, and isn't endorsed by its author. It goes by Reloader, with its own bundle ID (`com.haris.reloader`) and URL scheme (`reloader://`), not AltLoad's.

## Docs

- [Personal setup](docs/PERSONAL-SETUP.md): building it on GitHub Actions, getting it onto the phone, and the weekly refresh.
- [How it works](docs/HOW-IT-WORKS.md): the upstream design, plus what this build changes.
- [Personal changes](docs/PERSONAL-CHANGES.md): every change from upstream, and what the first build and first run still have to confirm.
- [tools/decrypt.html](tools/decrypt.html): decrypts the encrypted build artifact on the phone.

## License

The code is under the [AltLoad License](LICENSE.md) (custom, MIT-based, non-commercial). It allows forking on GitHub to build for your own devices, and forbids publishing builds, releases or sources from a fork. Bundled third-party code keeps its own licenses: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
