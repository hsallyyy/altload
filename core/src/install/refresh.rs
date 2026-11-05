// Profile-only refresh: new 7-day provisioning profiles for apps already on this
// device, installed with misagent over the LocalDevVPN tunnel. Nothing is re-signed
// or reinstalled, so the host LiveContainer keeps running, keeps its data and keeps
// the certificate its JIT-less .p12 holds. AltStore refreshes this way while the
// certificate is unchanged, and so does SideStore's refresh.
//
// Only apps signed with iloader's certificate are touched: by default the host
// LiveContainer first (and the profiles of its extensions that still use their own), then
// this app when it runs as a normal app, then the other apps of the team whose
// profile lists that certificate; otherwise the bundle IDs the request names.
// A dry run reads Apple's answers but changes nothing on the account or the device.

use super::*;
use std::collections::{BTreeSet, HashMap};

use idevice::installation_proxy::InstallationProxyClient;
use idevice::misagent::MisagentClient;
use idevice::RsdService;
use isideload::dev::app_groups::AppGroupsApi;
use isideload::dev::app_ids::AppId;
use x509_cert::der::Decode;
use x509_cert::Certificate;

const APP_GROUPS: &str = "com.apple.security.application-groups";
const MEMORY_LIMIT: &str = "com.apple.developer.kernel.increased-memory-limit";

/// An install or refresh renews an app's extension profiles along with its own, so
/// they run out within minutes of each other, never a day apart.
const RENEWED_TOGETHER: i64 = 24 * 60 * 60;

const LEFTOVER: &str = "Left over from an older install that gave each extension its own App ID. The app doesn't use it any more, so it isn't renewed.";

const NOT_FOR_THIS_DEVICE: &str = "Apple's new profile doesn't list this device, so the current one was left in place.";

// MARK: - FFI

/// Profile-only refresh. Blocking: call it from a background thread.
///
/// `config`: apple_id, password, anisette_url, pairing_file_path, host_name,
/// endpoints and device_name are used; the rest is ignored.
/// `request_json`:
///   {"dryRun":false,"registerMissingAppIds":true,"only":["com.x",…]|null,
///    "hostBundleId":"com.kdt.livecontainer.TEAMID"|null}
///
/// Returns 0 with {"team","udid","dryRun","appIdsAvailable","results":[…]} in
/// `*out_json`, or 1 with an error message. Free with `altload_string_free`.
/// 2FA prompts and cancellation use the same `AltLoadInstallSession` as installs.
#[no_mangle]
pub unsafe extern "C" fn altload_refresh_profiles_run(
    session: *mut AltLoadInstallSession,
    config: *const AltLoadInstallConfig,
    request_json: *const c_char,
    progress_cb: AltLoadProgressCb,
    prompt_cb: AltLoadPromptCb,
    ctx: *mut c_void,
    out_json: *mut *mut c_char,
) -> i32 {
    if session.is_null() || config.is_null() || out_json.is_null() {
        return 2;
    }
    *out_json = ptr::null_mut();
    init_once();

    let fail = |msg: String| -> i32 {
        *out_json = cstr(msg);
        1
    };
    let cfg = match RefreshConfig::from_raw(&*config) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let request: serde_json::Value = match serde_json::from_str(&opt(request_json, "{}")) {
        Ok(v) => v,
        Err(e) => return fail(err("Bad request", e)),
    };
    let opts = RefreshOptions::from_json(&request);

    let session = &*session;
    let (tx, rx) = mpsc::unbounded_channel();
    *session.responder.lock().unwrap() = Some(tx);
    session.cancelled.store(false, Ordering::SeqCst);
    let cbs = Callbacks { progress: progress_cb, prompt: prompt_cb, ctx };

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => return fail(format!("failed to start runtime: {e}")),
    };
    let result = rt.block_on(run_refresh(cfg, opts, cbs, Arc::new(AsyncMutex::new(rx)), &session.cancelled));
    *session.responder.lock().unwrap() = None;

    match result {
        Ok(json) => {
            *out_json = cstr(json.to_string());
            0
        }
        Err(e) => fail(e),
    }
}

// MARK: - Types

struct RefreshConfig {
    apple_id: String,
    password: String,
    anisette_url: String,
    pairing_file_path: String,
    host_name: String,
    endpoints: Vec<Endpoint>,
    device_name: String,
}

impl RefreshConfig {
    unsafe fn from_raw(c: &AltLoadInstallConfig) -> Result<Self, String> {
        Ok(Self {
            apple_id: req(c.apple_id, "Apple ID")?.trim().to_lowercase(),
            password: req(c.password, "password")?,
            anisette_url: opt(c.anisette_url, DEFAULT_ANISETTE),
            pairing_file_path: req(c.pairing_file_path, "pairing file")?,
            host_name: opt(c.host_name, "Reloader"),
            endpoints: endpoints_from_raw(c)?,
            device_name: opt(c.device_name, "iPhone"),
        })
    }
}

#[derive(Debug, PartialEq)]
struct RefreshOptions {
    dry_run: bool,
    register_missing: bool,
    only: Option<Vec<String>>,
    host_bundle_id: Option<String>,
}

impl RefreshOptions {
    fn from_json(request: &serde_json::Value) -> Self {
        let only: Option<Vec<String>> = request.get("only").and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|s| s.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        });
        Self {
            dry_run: request.get("dryRun").and_then(|v| v.as_bool()).unwrap_or(false),
            // On unless switched off: free App IDs lapse after 7 days, so the weekly
            // refresh needs it about every other run.
            register_missing: request.get("registerMissingAppIds").and_then(|v| v.as_bool()).unwrap_or(true),
            only: only.filter(|ids| !ids.is_empty()),
            host_bundle_id: request
                .get("hostBundleId")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        }
    }
}

/// A provisioning profile, from misagent or from Apple.
struct ProfileInfo {
    data: Vec<u8>,
    uuid: String,
    /// application-identifier without the team prefix ("com.kdt.livecontainer.ABCDE12345").
    identifier: String,
    team_id: String,
    expires: i64,
    /// DeveloperCertificates, DER.
    certs: Vec<Vec<u8>>,
    devices: Vec<String>,
    entitlements: plist::Dictionary,
}

impl ProfileInfo {
    fn parse(data: Vec<u8>) -> Option<Self> {
        let dict: plist::Dictionary = {
            let find = |needle: &[u8]| data.windows(needle.len()).position(|w| w == needle);
            let start = find(b"<?xml")?;
            let end = find(b"</plist>")? + b"</plist>".len();
            plist::from_bytes(&data[start..end]).ok()?
        };
        let entitlements = dict
            .get("Entitlements")
            .and_then(|v| v.as_dictionary())
            .cloned()
            .unwrap_or_default();
        let (prefix, identifier) = entitlements
            .get("application-identifier")
            .and_then(|v| v.as_string())?
            .split_once('.')?;
        let strings = |key: &str| -> Vec<String> {
            dict.get(key)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_string().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        Some(Self {
            uuid: dict.get("UUID")?.as_string()?.to_string(),
            identifier: identifier.to_string(),
            team_id: strings("TeamIdentifier").into_iter().next().unwrap_or_else(|| prefix.to_string()),
            expires: super::account::unix(dict.get("ExpirationDate").and_then(|v| v.as_date())),
            certs: dict
                .get("DeveloperCertificates")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|c| c.as_data().map(<[u8]>::to_vec)).collect())
                .unwrap_or_default(),
            devices: strings("ProvisionedDevices"),
            entitlements: entitlements.clone(),
            data,
        })
    }

    /// iOS runs an app only with a profile that lists the certificate it's signed with.
    fn lists_certificate(&self, cert: &Certificate) -> bool {
        self.certs.iter().any(|der| Certificate::from_der(der).is_ok_and(|c| &c == cert))
    }

    fn lists_device(&self, udid: &str) -> bool {
        self.devices.iter().any(|d| d.eq_ignore_ascii_case(udid))
    }
}

struct InstalledInfo {
    name: String,
    /// The app's signed entitlements, as installation_proxy reports them.
    entitlements: plist::Dictionary,
    /// Where its .app is on the device.
    path: Option<PathBuf>,
}

impl InstalledInfo {
    fn from_lookup(info: &plist::Value) -> Self {
        let d = info.as_dictionary().cloned().unwrap_or_default();
        let s = |k: &str| d.get(k).and_then(|v| v.as_string()).unwrap_or_default().to_string();
        let name = Some(s("CFBundleDisplayName")).filter(|n| !n.is_empty()).unwrap_or_else(|| s("CFBundleName"));
        let entitlements = d.get("Entitlements").and_then(|v| v.as_dictionary()).cloned().unwrap_or_default();
        let path = Some(s("Path")).filter(|p| !p.is_empty()).map(PathBuf::from);
        Self { name, entitlements, path }
    }

    /// The App ID it's signed for (without the team prefix) and the team that signed
    /// it, from its entitlements, or from its profile when iOS doesn't report them.
    fn signed_as(&self, bundle_id: &str, on_device: &[ProfileInfo]) -> (String, Option<String>) {
        let signed = &self.entitlements;
        let (prefix, identifier) = match signed.get("application-identifier").and_then(|v| v.as_string()).and_then(|a| a.split_once('.')) {
            Some((prefix, identifier)) => (Some(prefix.to_string()), identifier.to_string()),
            None => (None, bundle_id.to_string()),
        };
        let team = signed
            .get("com.apple.developer.team-identifier")
            .and_then(|v| v.as_string())
            .map(str::to_string)
            .or(prefix)
            .or_else(|| newest_profile(on_device, &identifier, None).map(|(_, p)| p.team_id.clone()));
        (identifier, team)
    }
}

/// One App ID whose profile gets renewed.
struct Target {
    /// application-identifier without the team prefix.
    identifier: String,
    name: String,
    /// What the new profile has to grant: the app's signed entitlements when iOS
    /// reports them, otherwise its current profile's.
    wanted: plist::Dictionary,
    /// Newest profile of this team for it on the device (index into the list).
    old: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Status {
    Refreshed,
    Planned,
    Skipped,
    Failed,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Refreshed => "refreshed",
            Status::Planned => "planned",
            Status::Skipped => "skipped",
            Status::Failed => "failed",
        }
    }
}

/// One line of the report.
struct Row {
    bundle_id: String,
    app: String,
    status: Status,
    reason: Option<String>,
    old_expires: Option<i64>,
    new_expires: Option<i64>,
}

impl Row {
    fn new(bundle_id: &str, app: &str, status: Status, reason: Option<String>) -> Self {
        Self {
            bundle_id: bundle_id.to_string(),
            app: app.to_string(),
            status,
            reason,
            old_expires: None,
            new_expires: None,
        }
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "bundleId": self.bundle_id,
            "app": self.app,
            "status": self.status.as_str(),
            "reason": self.reason,
            "oldExpires": self.old_expires,
            "newExpires": self.new_expires,
        })
    }
}

/// Why a target ends before an install. In a dry run, `Planned` with what a real
/// run would change on the account first.
struct Stop {
    status: Status,
    reason: String,
}

impl Stop {
    fn skipped(reason: impl Into<String>) -> Self {
        Self { status: Status::Skipped, reason: reason.into() }
    }

    fn failed(reason: impl Into<String>) -> Self {
        Self { status: Status::Failed, reason: reason.into() }
    }

    fn planned(reason: impl Into<String>) -> Self {
        Self { status: Status::Planned, reason: reason.into() }
    }
}

fn report(team_id: &str, udid: &str, dry_run: bool, app_ids_available: Option<i64>, rows: &[Row]) -> serde_json::Value {
    serde_json::json!({
        "team": team_id,
        "udid": udid,
        "dryRun": dry_run,
        "appIdsAvailable": app_ids_available,
        "results": rows.iter().map(Row::json).collect::<Vec<_>>(),
    })
}

// MARK: - Flow

async fn run_refresh(
    cfg: RefreshConfig,
    opts: RefreshOptions,
    cbs: Callbacks,
    replies: Replies,
    cancelled: &AtomicBool,
) -> Result<serde_json::Value, String> {
    let check = || if cancelled.load(Ordering::SeqCst) { Err("Cancelled.".to_string()) } else { Ok(()) };

    // The imported key decides which apps are ours. Checked before the device link
    // or a sign-in, as installs do.
    imported_key(&cfg.apple_id)?;

    // 1. The device first, so a VPN or pairing problem shows up before Apple is asked.
    //    The tunnel is closed again: signing in (and 2FA) can take a while.
    cbs.progress("Reading this device's apps and profiles…", -1.0);
    let (udid, installed, on_device) = read_device(&cfg).await?;
    check()?;

    // 2. Apple: the team, iloader's certificate, the App IDs.
    cbs.progress("Signing in to Apple…", -1.0);
    let mut dev = sign_in(&cfg.apple_id, &cfg.password, &cfg.anisette_url, cbs, replies).await?;
    check()?;
    cbs.progress("Loading your App IDs…", -1.0);
    let team = dev
        .list_teams()
        .await
        .map_err(|e| err("Couldn't load your developer team", e))?
        .into_iter()
        .next()
        .ok_or("This Apple ID has no developer team.")?;
    let cert = existing_identity(&mut dev, &team, &cfg.apple_id).await?.certificate;
    let listing = dev
        .list_app_ids(&team, None::<DeveloperDeviceType>)
        .await
        .map_err(|e| err("Couldn't list App IDs", e))?;
    let mut available = listing.available_quantity;
    let mut app_ids = listing.app_ids;
    check()?;

    // 3. New profiles from Apple, each checked before anything on the device changes.
    let picks = pick_targets(&opts, &team.team_id, &cert, &installed, &on_device);
    let total = picks.len().max(1) as f64;
    let mut rows: Vec<Row> = Vec::new();
    let mut pending: Vec<(usize, ProfileInfo)> = Vec::new();
    for (n, pick) in picks.into_iter().enumerate() {
        let target = match pick {
            Ok(target) => target,
            Err(row) => {
                rows.push(row);
                continue;
            }
        };
        check()?;
        cbs.progress(&format!("Getting a new profile for {}…", target.name), n as f64 / total);
        let old = target.old.map(|i| &on_device[i]);
        let mut row = Row::new(&target.identifier, &target.name, Status::Planned, None);
        row.old_expires = old.map(|o| o.expires).filter(|e| *e > 0);

        let renewed = renew(
            &mut dev,
            &team,
            &cert,
            &mut app_ids,
            &mut available,
            &udid,
            &cfg.device_name,
            &target,
            old,
            &opts,
        )
        .await;
        match renewed {
            Ok(new) => {
                row.new_expires = Some(new.expires).filter(|e| *e > 0);
                if !opts.dry_run {
                    pending.push((rows.len(), new));
                }
            }
            Err(stop) => {
                row.status = stop.status;
                row.reason = Some(stop.reason);
            }
        }
        rows.push(row);
    }

    // 4. Install, host first. A dry run stops before this.
    if !pending.is_empty() {
        check()?;
        cbs.progress("Installing the new profiles…", -1.0);
        if let Err(e) = install_all(&cfg, &pending, &mut rows).await {
            for (i, _) in &pending {
                if rows[*i].status == Status::Planned {
                    rows[*i].status = Status::Failed;
                    rows[*i].reason = Some(format!("The new profile wasn't installed: {e}"));
                }
            }
        }
    }
    Ok(report(&team.team_id, &udid, opts.dry_run, available, &rows))
}

async fn read_device(cfg: &RefreshConfig) -> Result<(String, HashMap<String, InstalledInfo>, Vec<ProfileInfo>), String> {
    let (mut adapter, mut handshake) = open_tunnel_to(&cfg.pairing_file_path, &cfg.host_name, &cfg.endpoints).await?;
    let udid = handshake
        .properties
        .get("UniqueDeviceID")
        .and_then(|v| v.as_string())
        .map(str::to_string)
        .ok_or("This device didn't report its UDID over RSD.")?;

    let apps = {
        let mut ip = InstallationProxyClient::connect_rsd(&mut adapter, &mut handshake)
            .await
            .map_err(|e| err("installation_proxy", e))?;
        ip.get_apps(Some("User"), None)
            .await
            .map_err(|e| err("Couldn't list apps", e))?
    };
    let installed: HashMap<String, InstalledInfo> = apps
        .into_iter()
        .map(|(bundle_id, info)| (bundle_id, InstalledInfo::from_lookup(&info)))
        .collect();

    let mut mis = MisagentClient::connect_rsd(&mut adapter, &mut handshake)
        .await
        .map_err(|e| err("Couldn't reach misagent", e))?;
    let profiles = profiles_on(&mut mis).await?;
    Ok((udid, installed, profiles))
}

async fn profiles_on(mis: &mut MisagentClient) -> Result<Vec<ProfileInfo>, String> {
    Ok(mis
        .copy_all()
        .await
        .map_err(|e| err("Couldn't list provisioning profiles", e))?
        .into_iter()
        .filter_map(ProfileInfo::parse)
        .collect())
}

/// The bundle this code runs from: this app when it's installed as a normal app.
/// As a guest it's this app's copy inside LiveContainer (LiveContainer points the
/// executable path there), which isn't installed on the device.
fn running_app_bundle_id() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let app = exe.ancestors().find(|p| p.extension().is_some_and(|x| x == "app"))?;
    Some(bundle_id_of(app)).filter(|id| !id.is_empty())
}

/// LiveContainer sets this for itself and every guest it runs.
fn inside_live_container() -> bool {
    std::env::var_os("LC_HOME_PATH").is_some()
}

fn is_live_container(identifier: &str) -> bool {
    identifier.starts_with("com.kdt.livecontainer")
}

/// The newest profile on the device for `identifier`, of `team_id` if given.
fn newest_profile<'a>(on_device: &'a [ProfileInfo], identifier: &str, team_id: Option<&str>) -> Option<(usize, &'a ProfileInfo)> {
    on_device
        .iter()
        .enumerate()
        .filter(|(_, p)| p.identifier.eq_ignore_ascii_case(identifier) && team_id.map_or(true, |t| p.team_id == t))
        .max_by_key(|(_, p)| p.expires)
}

/// What to renew, in order: the host LiveContainer first, then this app, then every
/// other app of this team whose profile lists iloader's certificate; or only the
/// bundle IDs in `only`. Each app is followed by its extensions' own profiles, if
/// any (apps signed with an App ID per extension). A bundle ID that can't be
/// renewed here comes back as its report row.
fn pick_targets(
    opts: &RefreshOptions,
    team_id: &str,
    cert: &Certificate,
    installed: &HashMap<String, InstalledInfo>,
    on_device: &[ProfileInfo],
) -> Vec<Result<Target, Row>> {
    let explicit = opts.only.is_some();
    // As a guest, the LiveContainer this app runs in. As a normal app, still the one
    // iloader installed for this team, which this build exists to keep alive, but then
    // it's left out quietly when it isn't installed.
    let expect_host = opts.host_bundle_id.is_some() || inside_live_container();
    let host = (!explicit).then(|| {
        opts.host_bundle_id.clone().unwrap_or_else(|| format!("com.kdt.livecontainer.{team_id}"))
    });
    let mut bundle_ids: Vec<String> = match &opts.only {
        Some(only) => only.clone(),
        None => {
            // Sorted, so every run goes through them in the same order.
            let mut others: Vec<String> = installed
                .iter()
                .filter(|(bundle_id, app)| {
                    let (identifier, app_team) = app.signed_as(bundle_id, on_device);
                    app_team.as_deref() == Some(team_id)
                        && newest_profile(on_device, &identifier, Some(team_id)).is_some_and(|(_, p)| p.lists_certificate(cert))
                })
                .map(|(bundle_id, _)| bundle_id.clone())
                .collect();
            others.sort();
            host.iter().cloned().chain(running_app_bundle_id()).chain(others).collect()
        }
    };
    let mut seen = BTreeSet::new();
    bundle_ids.retain(|id| seen.insert(id.to_lowercase()));

    let mut picks = Vec::new();
    for bundle_id in bundle_ids {
        let Some(app) = installed.get(&bundle_id) else {
            // As a guest this app isn't installed itself; only say so for IDs that were
            // asked for, and for the host when this app runs inside it.
            if explicit || (expect_host && host.as_deref() == Some(bundle_id.as_str())) {
                picks.push(Err(Row::new(&bundle_id, &bundle_id, Status::Skipped, Some("It isn't installed on this device.".to_string()))));
            }
            continue;
        };
        let name = if app.name.is_empty() { bundle_id.clone() } else { app.name.clone() };

        let signed = &app.entitlements;
        let (identifier, app_team) = app.signed_as(&bundle_id, on_device);
        if let Some(other) = app_team.filter(|t| t != team_id) {
            picks.push(Err(Row::new(
                &identifier,
                &name,
                Status::Skipped,
                Some(format!("It's signed by team {other}, not {team_id}. Refresh it with the Apple ID iloader used for it.")),
            )));
            continue;
        }

        let old = newest_profile(on_device, &identifier, Some(team_id));
        let wanted = if signed.is_empty() { old.map(|(_, p)| p.entitlements.clone()).unwrap_or_default() } else { signed.clone() };
        picks.push(Ok(Target { identifier: identifier.clone(), name: name.clone(), wanted, old: old.map(|(i, _)| i) }));

        // Extensions with an App ID of their own, as iloader signed every app before 2.4
        // (isideload 0.4.6). Since then extensions share the app's profile, so the ones
        // such an install left behind aren't used, and renewing one would register a
        // free App ID a week for nothing.
        let used = app.path.as_deref().and_then(extension_app_ids);
        let app_expires = old.map_or(0, |(_, p)| p.expires);
        let prefix = format!("{}.", identifier.to_lowercase());
        let extensions: BTreeSet<String> = on_device
            .iter()
            .filter(|p| p.team_id == team_id && p.identifier.to_lowercase().starts_with(&prefix))
            .filter(|p| !installed.contains_key(&p.identifier))
            .map(|p| p.identifier.clone())
            .collect();
        for extension in extensions {
            let Some((i, profile)) = newest_profile(on_device, &extension, Some(team_id)) else { continue };
            let suffix = extension.get(prefix.len()..).unwrap_or(&extension);
            let label = format!("{name} ({suffix})");
            // The bundle says which are used when this process can read it, as a guest
            // can read LiveContainer's. Otherwise their age does.
            let in_use = match &used {
                Some(used) => used.contains(&extension.to_lowercase()),
                None => profile.expires + RENEWED_TOGETHER >= app_expires,
            };
            if in_use {
                picks.push(Ok(Target {
                    identifier: extension.clone(),
                    name: label,
                    wanted: profile.entitlements.clone(),
                    old: Some(i),
                }));
            } else if profile.expires > unix_now() {
                // Listed until it runs out, then left out.
                picks.push(Err(Row::new(&extension, &label, Status::Skipped, Some(LEFTOVER.to_string()))));
            }
        }
    }
    picks
}

/// The App IDs an app's extensions are signed for (lowercased), from the profiles in
/// its bundle. None when this process can't tell: an app can only read its own
/// bundle, and a guest runs in LiveContainer's process.
fn extension_app_ids(app: &Path) -> Option<BTreeSet<String>> {
    std::fs::metadata(app.join("Info.plist")).ok()?;
    let mut ids = BTreeSet::new();
    for folder in ["PlugIns", "Extensions"] {
        let entries = match std::fs::read_dir(app.join(folder)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "appex") {
                let profile = std::fs::read(path.join("embedded.mobileprovision")).ok().and_then(ProfileInfo::parse)?;
                ids.insert(profile.identifier.to_lowercase());
            }
        }
    }
    Some(ids)
}

fn lapsed(app_id: &AppId, now: i64) -> bool {
    let expires = super::account::unix(app_id.expiration_date.clone());
    expires != 0 && expires <= now
}

/// A fresh profile for the target's App ID that keeps the installed app running:
/// same App ID, lists this device, grants everything the app is signed with, and
/// lists iloader's certificate. Only apps whose current profile lists that
/// certificate are touched.
#[allow(clippy::too_many_arguments)]
async fn renew(
    dev: &mut DeveloperSession,
    team: &DeveloperTeam,
    cert: &Certificate,
    app_ids: &mut Vec<AppId>,
    available: &mut Option<i64>,
    udid: &str,
    device_name: &str,
    target: &Target,
    old: Option<&ProfileInfo>,
    opts: &RefreshOptions,
) -> Result<ProfileInfo, Stop> {
    let Some(old) = old else {
        return Err(Stop::skipped(
            "There's no profile for it on this device, so Reloader can't tell which certificate it's signed with.",
        ));
    };
    if !old.lists_certificate(cert) {
        return Err(Stop::skipped("It isn't signed with your iloader certificate, so Reloader leaves it alone."));
    }
    let identifier = target.identifier.as_str();
    let name = target.name.as_str();

    // Free App IDs lapse 7 days after they're registered. Registering the same
    // identifier again (1 of the 10 a week) gives the installed app profiles again.
    let listed = app_ids.iter().position(|a| a.identifier.eq_ignore_ascii_case(identifier));
    let current = listed.map(|i| app_ids[i].clone()).filter(|a| !lapsed(a, unix_now()));
    let (mut app_id, fresh) = match current {
        Some(app_id) => (app_id, false),
        None if opts.dry_run => {
            let left = available.map(|n| format!(" ({n} left this week)")).unwrap_or_default();
            return Err(Stop::planned(format!(
                "Its App ID has lapsed. A refresh registers it again, using 1 of the 10 App IDs a week{left}, and restores its app groups and memory limit."
            )));
        }
        None if !opts.register_missing => {
            return Err(Stop::skipped(
                "Its App ID has lapsed. Allow re-registering App IDs to renew it (uses 1 of the 10 a week).",
            ));
        }
        None if available.is_some_and(|n| n <= 0) => {
            return Err(Stop::failed("Its App ID has lapsed and this Apple ID has no App IDs left this week."));
        }
        None => match dev.add_app_id(team, name, identifier, None::<DeveloperDeviceType>).await {
            Ok(app_id) => {
                if let Some(n) = available.as_mut() {
                    *n -= 1;
                }
                match listed {
                    Some(i) => app_ids[i] = app_id.clone(),
                    None => app_ids.push(app_id.clone()),
                }
                (app_id, true)
            }
            Err(e) => match listed {
                // Apple still has the lapsed one, so carry on with that.
                Some(i) => (app_ids[i].clone(), false),
                None => return Err(Stop::failed(err("Couldn't register its App ID again", e))),
            },
        },
    };
    if fresh {
        restore_capabilities(dev, team, &mut app_id, &target.wanted, name, identifier)
            .await
            .map_err(Stop::failed)?;
    }
    let mut new = download(dev, team, &app_id).await.map_err(Stop::failed)?;

    // The profile only works on the devices it lists.
    if !new.lists_device(udid) {
        if opts.dry_run {
            return Err(Stop::planned("This device isn't on its profile yet. A refresh registers it first."));
        }
        dev.ensure_device_registered(team, device_name, udid, None::<DeveloperDeviceType>)
            .await
            .map_err(|e| Stop::failed(err("Couldn't register this device", e)))?;
        new = download(dev, team, &app_id).await.map_err(Stop::failed)?;
        // Registered isn't enough: Apple can still leave a device off the profile.
        if !new.lists_device(udid) {
            return Err(Stop::failed(NOT_FOR_THIS_DEVICE));
        }
    }

    // An App ID that lost a capability (app group, memory limit): put it back once.
    let missing = missing_entitlements(&target.wanted, &new.entitlements);
    if !missing.is_empty() && !fresh {
        if opts.dry_run {
            return Err(Stop::planned(format!(
                "Its App ID lost {}. A refresh restores it first.",
                missing.join(", ")
            )));
        }
        restore_capabilities(dev, team, &mut app_id, &target.wanted, name, identifier)
            .await
            .map_err(Stop::failed)?;
        new = download(dev, team, &app_id).await.map_err(Stop::failed)?;
    }
    let missing = missing_entitlements(&target.wanted, &new.entitlements);
    if !missing.is_empty() {
        return Err(Stop::failed(format!(
            "The new profile wouldn't grant {}, which it's signed with, so it would need a full re-sign.",
            missing.join(", ")
        )));
    }
    if !new.identifier.eq_ignore_ascii_case(identifier) {
        return Err(Stop::failed(format!("Apple sent a profile for {} instead.", new.identifier)));
    }
    if !new.lists_certificate(cert) {
        return Err(Stop::failed("Apple's new profile doesn't list your iloader certificate."));
    }
    if !new.lists_device(udid) {
        return Err(Stop::failed(NOT_FOR_THIS_DEVICE));
    }
    Ok(new)
}

async fn download(dev: &mut DeveloperSession, team: &DeveloperTeam, app_id: &AppId) -> Result<ProfileInfo, String> {
    // Free profiles are made anew on every fetch, each valid for 7 days.
    let profile = dev
        .download_team_provisioning_profile(team, app_id, None::<DeveloperDeviceType>)
        .await
        .map_err(|e| err("Couldn't download the provisioning profile", e))?;
    let bytes: &[u8] = profile.encoded_profile.as_ref();
    ProfileInfo::parse(bytes.to_vec()).ok_or_else(|| "Apple sent a provisioning profile Reloader couldn't read.".to_string())
}

/// Puts back what iloader set up when it signed the app: the app groups it's signed
/// with (group.com.SideStore.SideStore.<team> for LiveContainer+SideStore) and
/// Increased Memory Limit, which iloader asks for on every install.
async fn restore_capabilities(
    dev: &mut DeveloperSession,
    team: &DeveloperTeam,
    app_id: &mut AppId,
    wanted: &plist::Dictionary,
    name: &str,
    identifier: &str,
) -> Result<(), String> {
    let groups: Vec<String> = wanted
        .get(APP_GROUPS)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|g| g.as_string().map(str::to_string)).collect())
        .unwrap_or_default();
    if !groups.is_empty() {
        app_id
            .ensure_group_feature(dev, team)
            .await
            .map_err(|e| err("Couldn't enable app groups", e))?;
        for group_identifier in &groups {
            let group = dev
                .ensure_app_group(team, name, group_identifier, None::<DeveloperDeviceType>)
                .await
                .map_err(|e| err("Couldn't register the app group", e))?;
            dev.assign_app_group(team, &group, app_id, None::<DeveloperDeviceType>)
                .await
                .map_err(|e| err("Couldn't assign the app group", e))?;
        }
    }
    if wanted.get(MEMORY_LIMIT).and_then(|v| v.as_boolean()) == Some(true) || is_live_container(identifier) {
        dev.add_increased_memory_limit(team, app_id)
            .await
            .map_err(|e| err("Couldn't enable Increased Memory Limit", e))?;
    }
    Ok(())
}

/// Whether the profile's entitlement value `have` allows the app's `want`
/// (arrays as sets, "TEAMID.*" style wildcards, a granted `true`).
fn covers(have: &plist::Value, want: &plist::Value) -> bool {
    match (have, want) {
        (plist::Value::Array(h), plist::Value::Array(w)) => w.iter().all(|x| h.iter().any(|y| covers(y, x))),
        (plist::Value::Array(h), w) => h.iter().any(|y| covers(y, w)),
        (h, plist::Value::Array(w)) => w.iter().all(|x| covers(h, x)),
        (plist::Value::String(h), plist::Value::String(w)) => {
            h == w || h.strip_suffix('*').is_some_and(|p| w.starts_with(p))
        }
        (plist::Value::Boolean(h), plist::Value::Boolean(w)) => *h || !*w,
        (h, w) => h == w,
    }
}

/// Entitlements in `want` that `profile` doesn't grant.
fn missing_entitlements(want: &plist::Dictionary, profile: &plist::Dictionary) -> Vec<String> {
    want.iter()
        .filter(|(key, value)| !profile.get(key.as_str()).is_some_and(|have| covers(have, value)))
        .map(|(key, _)| key.clone())
        .collect()
}

/// Installs every pending profile, host first, into its row.
async fn install_all(cfg: &RefreshConfig, pending: &[(usize, ProfileInfo)], rows: &mut [Row]) -> Result<(), String> {
    let (mut adapter, mut handshake) = open_tunnel_to(&cfg.pairing_file_path, &cfg.host_name, &cfg.endpoints).await?;
    let mut mis = MisagentClient::connect_rsd(&mut adapter, &mut handshake)
        .await
        .map_err(|e| err("Couldn't reach misagent", e))?;
    // Read again: the device may have changed while signing in.
    let current = profiles_on(&mut mis).await?;
    for (i, new) in pending {
        let olds: Vec<&ProfileInfo> = current
            .iter()
            .filter(|p| p.identifier.eq_ignore_ascii_case(&new.identifier) && p.team_id == new.team_id && p.uuid != new.uuid)
            .collect();
        let row = &mut rows[*i];
        match install_replacing(&mut mis, new, &olds).await {
            Ok(()) => row.status = Status::Refreshed,
            Err(e) => {
                row.status = Status::Failed;
                row.reason = Some(e);
            }
        }
    }
    Ok(())
}

/// Installs `new`, then takes off the copies it replaces. The current profile stays
/// until iOS lists the new one, so the app is never left without a valid profile;
/// if the new one is gone again after the old ones came off, the newest old one
/// goes back.
async fn install_replacing(mis: &mut MisagentClient, new: &ProfileInfo, olds: &[&ProfileInfo]) -> Result<(), String> {
    mis.install(new.data.clone())
        .await
        .map_err(|e| err("iOS didn't take the new profile; the current one is still in place", e))?;
    if !lists(mis, &new.uuid).await? {
        return Err("iOS accepted the new profile but doesn't list it, so the current one was left in place.".to_string());
    }

    let mut removed: Vec<&ProfileInfo> = Vec::new();
    for &old in olds {
        if mis.remove(&old.uuid).await.is_ok() {
            removed.push(old);
        }
    }
    // Couldn't check: it was listed a moment ago.
    if removed.is_empty() || lists(mis, &new.uuid).await.unwrap_or(true) {
        return Ok(());
    }
    if let Some(newest) = removed.iter().max_by_key(|o| o.expires) {
        let _ = mis.install(newest.data.clone()).await;
    }
    Err("iOS dropped the new profile once the old ones came off, so the newest old one was put back.".to_string())
}

async fn lists(mis: &mut MisagentClient, uuid: &str) -> Result<bool, String> {
    Ok(profiles_on(mis).await?.iter().any(|p| p.uuid.eq_ignore_ascii_case(uuid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(pairs: &[(&str, plist::Value)]) -> plist::Dictionary {
        let mut dict = plist::Dictionary::new();
        for (key, value) in pairs {
            dict.insert(key.to_string(), value.clone());
        }
        dict
    }

    fn s(v: &str) -> plist::Value {
        plist::Value::String(v.into())
    }

    #[test]
    fn wildcard_keychain_groups_and_app_groups_are_covered() {
        let profile = dict(&[
            ("keychain-access-groups", plist::Value::Array(vec![s("ABCDE12345.*")])),
            (APP_GROUPS, plist::Value::Array(vec![s("group.com.SideStore.SideStore.ABCDE12345")])),
            ("get-task-allow", plist::Value::Boolean(true)),
            (MEMORY_LIMIT, plist::Value::Boolean(true)),
        ]);
        // How isideload signs LiveContainer: 128 explicit keychain groups under the wildcard.
        let groups = (0..128)
            .map(|n| s(&format!("ABCDE12345.com.kdt.livecontainer.shared.{n}")))
            .collect();
        let app = dict(&[
            ("keychain-access-groups", plist::Value::Array(groups)),
            (APP_GROUPS, plist::Value::Array(vec![s("group.com.SideStore.SideStore.ABCDE12345")])),
            ("get-task-allow", plist::Value::Boolean(true)),
            (MEMORY_LIMIT, plist::Value::Boolean(true)),
        ]);
        assert!(missing_entitlements(&app, &profile).is_empty());

        let lapsed = dict(&[
            ("keychain-access-groups", plist::Value::Array(vec![s("ABCDE12345.*")])),
            ("get-task-allow", plist::Value::Boolean(true)),
        ]);
        let mut missing = missing_entitlements(&app, &lapsed);
        missing.sort();
        assert_eq!(missing, vec![MEMORY_LIMIT.to_string(), APP_GROUPS.to_string()]);
    }

    #[test]
    fn covering_is_exact_apart_from_wildcards() {
        assert!(covers(&s("ABCDE12345.*"), &s("ABCDE12345.com.x")));
        assert!(!covers(&s("ABCDE12345.*"), &s("FGHIJ67890.com.x")));
        assert!(!covers(&s("group.a"), &s("group.ab")));
        assert!(covers(&plist::Value::Boolean(true), &plist::Value::Boolean(false)));
        assert!(!covers(&plist::Value::Boolean(false), &plist::Value::Boolean(true)));
        assert!(covers(&s("ABCDE12345.*"), &plist::Value::Array(vec![s("ABCDE12345.a"), s("ABCDE12345.b")])));
        assert!(!covers(&plist::Value::Array(vec![s("group.a")]), &plist::Value::Array(vec![s("group.a"), s("group.b")])));
    }

    #[test]
    fn report_has_the_contracts_shape() {
        let mut refreshed = Row::new("com.kdt.livecontainer.ABCDE12345", "LiveContainer", Status::Refreshed, None);
        refreshed.old_expires = Some(1_700_000_000);
        refreshed.new_expires = Some(1_700_600_000);
        let skipped = Row::new("com.x", "com.x", Status::Skipped, Some("It isn't installed on this device.".into()));
        let json = report("ABCDE12345", "00008110-000", true, None, &[refreshed, skipped]);

        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["appIdsAvailable", "dryRun", "results", "team", "udid"]);
        assert!(json["appIdsAvailable"].is_null());
        assert_eq!(json["dryRun"], serde_json::json!(true));

        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let mut row_keys: Vec<&str> = results[0].as_object().unwrap().keys().map(String::as_str).collect();
        row_keys.sort();
        assert_eq!(row_keys, ["app", "bundleId", "newExpires", "oldExpires", "reason", "status"]);
        assert_eq!(results[0]["status"], "refreshed");
        assert!(results[0]["reason"].is_null());
        assert_eq!(results[0]["newExpires"].as_i64(), Some(1_700_600_000));
        assert_eq!(results[1]["status"], "skipped");
        assert!(results[1]["oldExpires"].is_null());
        assert_eq!(report("T", "U", false, Some(7), &[])["appIdsAvailable"].as_i64(), Some(7));
    }

    #[test]
    fn options_default_to_a_real_run_that_may_register_app_ids() {
        let defaults = RefreshOptions::from_json(&serde_json::json!({}));
        assert_eq!(
            defaults,
            RefreshOptions { dry_run: false, register_missing: true, only: None, host_bundle_id: None }
        );
        let asked = RefreshOptions::from_json(&serde_json::json!({
            "dryRun": true,
            "registerMissingAppIds": false,
            "only": [" com.kdt.livecontainer.ABCDE12345 ", ""],
            "hostBundleId": "com.kdt.livecontainer.ABCDE12345",
        }));
        assert!(asked.dry_run && !asked.register_missing);
        assert_eq!(asked.only, Some(vec!["com.kdt.livecontainer.ABCDE12345".to_string()]));
        assert_eq!(asked.host_bundle_id.as_deref(), Some("com.kdt.livecontainer.ABCDE12345"));
        assert_eq!(RefreshOptions::from_json(&serde_json::json!({ "only": [] })).only, None);
    }

    fn profile_xml(application_identifier: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>UUID</key><string>1234-ABCD</string>
	<key>TeamIdentifier</key><array><string>ABCDE12345</string></array>
	<key>ProvisionedDevices</key><array><string>00008110-000A</string></array>
	<key>DeveloperCertificates</key><array><data>AQID</data></array>
	<key>ExpirationDate</key><date>2026-11-12T10:00:00Z</date>
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key><string>{application_identifier}</string>
		<key>get-task-allow</key><true/>
	</dict>
</dict>
</plist>"#
        )
    }

    fn profile(identifier: &str, team_id: &str, expires: i64, cert: &[u8]) -> ProfileInfo {
        ProfileInfo {
            data: Vec::new(),
            uuid: format!("{identifier}-{expires}"),
            identifier: identifier.into(),
            team_id: team_id.into(),
            expires,
            certs: vec![cert.to_vec()],
            devices: Vec::new(),
            entitlements: plist::Dictionary::new(),
        }
    }

    fn app(identifier: &str, team_id: &str) -> InstalledInfo {
        InstalledInfo {
            name: String::new(),
            entitlements: dict(&[
                ("application-identifier", s(&format!("{team_id}.{identifier}"))),
                ("com.apple.developer.team-identifier", s(team_id)),
            ]),
            path: None,
        }
    }

    #[test]
    fn iloaders_live_container_goes_first_then_the_teams_other_apps() {
        use isideload::sideload::cert_identity::{APPLE_ROOT, APPLE_WWDR_G3_CERTIFICATE_DER as ILOADER};
        let cert = Certificate::from_der(ILOADER).unwrap();
        let (now, day) = (unix_now(), 24 * 60 * 60);
        let host = "com.kdt.livecontainer.ABCDE12345";
        let ext = |suffix: &str| format!("{host}.{suffix}");
        let installed: HashMap<String, InstalledInfo> = [
            (host, "ABCDE12345"),
            ("com.example.mine.ABCDE12345", "ABCDE12345"),
            ("com.example.theirs.FGHIJ67890", "FGHIJ67890"),
            ("com.example.othercert.ABCDE12345", "ABCDE12345"),
        ]
        .into_iter()
        .map(|(id, team)| (id.to_string(), app(id, team)))
        .collect();
        let on_device = vec![
            profile(host, "ABCDE12345", now + 7 * day, ILOADER),
            // Renewed with the app: still used.
            profile(&ext("LiveProcess"), "ABCDE12345", now + 7 * day - 60, ILOADER),
            // Days older than the app's: left by an install that gave it an App ID.
            profile(&ext("ShareExtension"), "ABCDE12345", now + 3 * day, ILOADER),
            // The same, run out: not listed at all.
            profile(&ext("LaunchAppExtension"), "ABCDE12345", now - day, ILOADER),
            profile("com.example.mine.ABCDE12345", "ABCDE12345", now + 7 * day, ILOADER),
            profile("com.example.theirs.FGHIJ67890", "FGHIJ67890", now + 7 * day, ILOADER),
            profile("com.example.othercert.ABCDE12345", "ABCDE12345", now + 7 * day, APPLE_ROOT),
        ];

        // No host from Swift, as for a normal app: still iloader's LiveContainer first.
        let opts = RefreshOptions { dry_run: false, register_missing: true, only: None, host_bundle_id: None };
        let picks: Vec<(String, bool)> = pick_targets(&opts, "ABCDE12345", &cert, &installed, &on_device)
            .iter()
            .map(|p| match p {
                Ok(target) => (target.identifier.clone(), true),
                Err(row) => (row.bundle_id.clone(), false),
            })
            .collect();
        assert_eq!(
            picks,
            vec![
                (host.to_string(), true),
                (ext("LiveProcess"), true),
                (ext("ShareExtension"), false),
                ("com.example.mine.ABCDE12345".to_string(), true),
            ]
        );

        // A normal app without iloader's LiveContainer doesn't report it missing.
        if !inside_live_container() {
            let without_host: HashMap<String, InstalledInfo> =
                installed.into_iter().filter(|(id, _)| id != host).collect();
            let picks = pick_targets(&opts, "ABCDE12345", &cert, &without_host, &on_device);
            assert_eq!(picks.len(), 1);
            assert!(picks[0].as_ref().is_ok_and(|t| t.identifier == "com.example.mine.ABCDE12345"));
        }
    }

    #[test]
    fn a_readable_bundle_says_which_extension_profiles_are_used() {
        let app = std::env::temp_dir().join(format!("reloader-test-{}/LiveContainer.app", std::process::id()));
        let appex = app.join("PlugIns/LiveProcess.appex");
        std::fs::create_dir_all(&appex).unwrap();
        std::fs::write(app.join("Info.plist"), b"").unwrap();
        // Signed with the app's own profile, as iloader 2.4 and Reloader sign extensions.
        std::fs::write(appex.join("embedded.mobileprovision"), profile_xml("ABCDE12345.com.kdt.livecontainer.ABCDE12345")).unwrap();
        let used = extension_app_ids(&app);
        assert_eq!(used, Some(BTreeSet::from(["com.kdt.livecontainer.abcde12345".to_string()])));

        // An extension without a readable profile leaves it open.
        std::fs::create_dir_all(app.join("PlugIns/ShareExtension.appex")).unwrap();
        assert_eq!(extension_app_ids(&app), None);
        let _ = std::fs::remove_dir_all(app.parent().unwrap());
        assert_eq!(extension_app_ids(&app), None);
    }

    #[test]
    fn a_profile_is_read_from_its_cms_wrapper() {
        let xml = profile_xml("ABCDE12345.com.kdt.livecontainer.ABCDE12345");
        // CMS around the plist, as misagent and Apple send it.
        let mut data = b"\x30\x80\x06\x09junk before".to_vec();
        data.extend_from_slice(xml.as_bytes());
        data.extend_from_slice(b"\x00\x00junk after");

        let profile = ProfileInfo::parse(data).expect("parses");
        assert_eq!(profile.uuid, "1234-ABCD");
        assert_eq!(profile.identifier, "com.kdt.livecontainer.ABCDE12345");
        assert_eq!(profile.team_id, "ABCDE12345");
        assert!(profile.lists_device("00008110-000a"));
        assert!(!profile.lists_device("00008110-000B"));
        assert_eq!(profile.certs, vec![vec![1, 2, 3]]);
        assert_eq!(profile.expires, 1_794_477_600);
        assert_eq!(profile.entitlements.get("get-task-allow").and_then(|v| v.as_boolean()), Some(true));
        assert!(is_live_container(&profile.identifier));
        assert!(ProfileInfo::parse(b"no plist here".to_vec()).is_none());
    }

    #[test]
    fn only_the_exact_certificate_counts() {
        use isideload::sideload::cert_identity::{APPLE_ROOT, APPLE_WWDR_G3_CERTIFICATE_DER};
        let wwdr = Certificate::from_der(APPLE_WWDR_G3_CERTIFICATE_DER).unwrap();
        let root = Certificate::from_der(APPLE_ROOT).unwrap();
        let profile = ProfileInfo {
            data: Vec::new(),
            uuid: "1234-ABCD".into(),
            identifier: "com.kdt.livecontainer.ABCDE12345".into(),
            team_id: "ABCDE12345".into(),
            expires: 0,
            certs: vec![vec![1, 2, 3], APPLE_WWDR_G3_CERTIFICATE_DER.to_vec()],
            devices: Vec::new(),
            entitlements: plist::Dictionary::new(),
        };
        assert!(profile.lists_certificate(&wwdr));
        assert!(!profile.lists_certificate(&root));
    }
}
