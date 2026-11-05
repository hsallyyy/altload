# Personal setup

How to build Reloader for your own devices, get it into LiveContainer and keep LiveContainer's profiles fresh every week. Almost everything happens on the iPhone or iPad. The PC is needed once to push this branch, and in the cases listed at the end.

Personal build — never distribute builds: no releases, no sharing the IPA, no AltStore/SideStore sources.

**Before you start**, the device needs:

- the LiveContainer that iloader installed with your free Apple ID (bundle ID `com.kdt.livecontainer.<TEAMID>`), with iloader's certificate imported in LiveContainer's **Settings › Import Certificate**, so JIT-less guests open;
- the pairing file iloader placed in it (iloader › **Manage Pairing File** › **Place** on the LiveContainer row);
- [LocalDevVPN](https://apps.apple.com/app/id6755608044) from the App Store;
- a GitHub account.

## A. Build it in your fork (recommended)

LICENSE.md §3 allows a fork on GitHub "to build it for your own devices", but a fork must not publish builds. Forks of public repositories are public, and any signed-in GitHub user can download a public repository's Actions artifacts. So the workflow encrypts the IPA with a passphrase only you know, and uploads nothing else.

### 1. Fork (phone)

In Safari, open <https://github.com/mirazbakis/AltLoad>, tap **Fork**, then **Create fork**.

### 2. Push this branch (PC, once)

In Git Bash, from this clone (use your GitHub username, and the noreply address from github.com/settings/emails):

```sh
git config user.name "<username>"
git config user.email "<id>+<username>@users.noreply.github.com"
git add -A
git commit -m "Reloader: personal build based on AltLoad by mirazbakis"
git remote add fork https://github.com/<username>/AltLoad.git
git push -u fork personal:main
```

This puts the branch on the fork's `main`, the default branch, so the Run button uses this branch's workflow and upstream's publishing workflows are gone from it. `origin` is the upstream repository; never push there. Git Credential Manager opens a browser to sign in to GitHub the first time.

### 3. Set up the fork (phone)

In your fork on github.com:

1. **Actions:** tap **I understand my workflows, go ahead and enable them**.
2. **Settings › Secrets and variables › Actions › New repository secret:** name it `IPA_PASSPHRASE`, and use a long random passphrase (six or more random words). Keep it in the Passwords app; you type it on the phone after every build.

Without the secret, the workflow refuses to upload anything from a public repository.

### 4. Build (phone)

1. **Actions › Build Reloader (personal) › Run workflow**, branch `main`, **Run workflow**. If the button doesn't show, choose **Request Desktop Website** from Safari's page menu.
2. Wait for the green check. The first build takes about 10–15 minutes, later ones less.
3. Open the run. Under **Artifacts**, tap **Reloader.ipa.enc**. Safari saves it to **Files › Downloads**. Artifacts are deleted after 3 days.

The run's summary shows the SHA-256 of `Reloader.ipa`, so you can check the decrypted file.

### 5. Decrypt (phone)

`tools/decrypt.html` decrypts the file inside Safari. It loads nothing and sends nothing, and the passphrase never leaves the device. Safari has to open it over https, and GitHub shows HTML files as source code, so host your own copy once:

1. Create a new **public** repository (for example `decrypt`) containing only this page. From the PC: copy `tools/decrypt.html` into an empty folder, then `git init`, commit and push it there. From the phone: in your fork, open `tools/decrypt.html` and use **Download raw file** (in the **…** menu on a phone), then in the new repository use **Add file › Upload files**.
2. In that repository: **Settings › Pages**, **Deploy from a branch**, branch `main`, folder `/ (root)`, **Save**.
3. After a minute, open `https://<username>.github.io/decrypt/decrypt.html` and bookmark it.

Don't turn on Pages in the fork itself: that would re-host AltLoad's code on another website (LICENSE.md §2). The separate repository holds only your own page.

Then, after each build:

1. Choose `Reloader.ipa.enc`, enter the passphrase, tap **Decrypt**.
2. Tap **Save Reloader.ipa** and confirm the download. Optionally compare the SHA-256 with the run summary.

"Wrong passphrase" means it doesn't match the secret exactly. If you change the secret, build again.

On the PC instead: open `tools/decrypt.html` in a desktop browser, or in Git Bash run `openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in Reloader.ipa.enc -out Reloader.ipa`.

### 6. Add Reloader to LiveContainer (phone)

1. Open the LiveContainer that iloader installed with this Apple ID. If you have more than one LiveContainer, use that one; Reloader refreshes the copy it runs in.
2. **My Apps › + › Install IPA File**, and pick `Reloader.ipa` from Downloads. LiveContainer signs it on the device with the certificate you imported. This uses no App ID and no app slot.
3. Long-press **Reloader › Settings**. Under **Fixes**, turn on:
   - **Fix File Picker** (not the separate "(Legacy) Fix File Picker"),
   - **Fix Local Notifications**,
   - **Use LiveContainer's Bundle ID**.
4. Tap Reloader to run it. Use the normal launch, not **Multitask**.

To update Reloader later, install the new IPA the same way and pick the existing Reloader (the red option), not **Install as new**. Its data and settings stay.

### 7. Set up Reloader (phone, once)

1. **Tools › Signing Certificate:** type the Apple ID iloader used for this device (its team ID is the end of LiveContainer's bundle ID), then tap **Use LiveContainer's Certificate**; the button stays grey until an Apple ID is typed. Reloader takes iloader's key and certificate from LiveContainer's imported certificate. This happens on the device, offline. Reloader signs only with this certificate and never makes or revokes one.
2. On the Install tab, tap **Use iloader's Pairing File** (also in **Tools › Pair**). If it isn't offered, use **Tools › Pair › Import Pairing File** and pick **On My iPhone (or iPad) › LiveContainer › SideStore › Documents › ALTPairingFile.mobiledevicepairing**, the file iloader placed.
3. **Settings › Apple ID › Sign In** with the same Apple ID. Turn on **Remember password**, which unattended refreshes need. For two-factor, use the code shown on a trusted device; SMS codes have been unreliable. If no code is entered within 2 minutes, the sign-in stops and you can try again.
4. Turn **LocalDevVPN** on, then go back to LiveContainer and Reloader.
5. **Check Only** (a dry run), on the Install tab under Refresh Profiles. It lists LiveContainer first, then the other apps of this Apple ID's team whose profile lists iloader's certificate, and what a refresh would do: `planned`, `skipped` (with the reason) or `failed`. It registers no App IDs and installs nothing. LiveContainer itself should be `planned`.
6. **Refresh Profiles.** The new profiles are installed first and the old ones removed afterwards, so LiveContainer keeps a valid profile throughout and keeps running. The report shows each app's new expiry date, 7 days out.

A free Apple ID can register 10 App IDs per 7 days. Free App IDs expire weekly, so a refresh may register LiveContainer's App ID again, with its app groups and Increased Memory Limit, and each extension's if iloader before 2.4 gave them their own. The report shows how many are left. Extension profiles left over from such an older install are listed as skipped until they run out; they aren't renewed.

### 8. Every week

Refresh before the 7 days run out, for example every 5 or 6 days:

1. Turn LocalDevVPN on.
2. Open LiveContainer, then Reloader.
3. Tap **Refresh Profiles**.

**Shortcuts.** When Reloader is installed as a normal app, Shortcuts has its **Refresh App Profiles** action. Make a personal automation: **Automation › + › Time of Day**, for example Monday and Thursday at a time the phone is usually unlocked, **Run Immediately**, action **Refresh App Profiles**. The phone has to be unlocked (the saved password can only be read then), and LocalDevVPN on.

iOS doesn't see a LiveContainer guest's Shortcuts actions. For the guest, the same kind of automation can use **Open URLs** with Reloader's launch URL (in LiveContainer, long-press **Reloader › Add to Home Screen › Copy Launch URL**) to open it, and you tap **Refresh Profiles**. With more than one LiveContainer on the device, check that the URL opens the right one.

## B. A private repository instead

A private repository keeps the IPA out of other people's reach without encryption, but the license only allows it with the author's written permission: §2 forbids uploading or mirroring the code anywhere else, §3 only covers GitHub forks, and forks of public repositories can't be private. To ask, open an issue at <https://github.com/mirazbakis/AltLoad/issues>.

With permission, create an empty private repository (not a fork), push this branch to its `main` (step 2 with that repository's URL). You can skip the secret: in a private repository the workflow uploads the plain `Reloader.ipa`, and you skip step 5. Private repositories only get a limited number of macOS Actions minutes a month. Builds still must not be shared.

## C. When you still need the PC

- **LiveContainer lapsed** (more than 7 days without a refresh). LiveContainer won't open, and Reloader lives inside it. Install LiveContainer again with iloader using the same Apple ID (over the top, so your apps stay), place the pairing file again, then refresh weekly from Reloader as before.
- **iloader's certificate revoked or expired, or its key changed.** A new profile can't fix that, and Reloader never makes a certificate of its own, so it stops and says so. Run iloader once with this Apple ID: it gets a new certificate for the key it keeps. Rebuild LiveContainer's `.p12` with that certificate and import it in LiveContainer (**Settings › Import Certificate**). Reloader finds the new certificate by its key; only if iloader's private key itself changed, repeat step 7.1. Never revoke iloader's certificate, in iloader or anywhere else: LiveContainer and every guest are signed with it.
- **Pairing reset on iOS 26 or earlier**, for example after erasing or restoring the device, **Reset Location & Privacy**, or a pairing file that stops working. iOS 26 and earlier can't pair on the device itself, so let iloader place a new pairing file, then import it in Reloader (step 7.2). On iOS 27 and later you can pair again on the device in **Tools › Pair**.

A new Reloader build never needs the PC: build, decrypt and install it over the old one (steps 4–6).
