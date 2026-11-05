// Pairing host forked from idevice's ffi/src/pairable_host.rs with the mDNS advertising moved
// to the Swift side (NetService) to avoid the iOS multicast entitlement.
#ifndef ALTLOAD_H
#define ALTLOAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*AltLoadReadyCb)(void *ctx,
                                const char *service_id,
                                uint16_t port,
                                const char *const *txt_keys,
                                const char *const *txt_vals,
                                size_t txt_count);

typedef void (*AltLoadPinCb)(const char *pin, void *ctx);

typedef struct {
    char *error;
    char *device_name;
    char *device_model;
    char *device_udid;
    char *pairing_file_path;
    char *host_alt_irk_hex;
} AltLoadResult;

int32_t altload_run_host(const char *bind_addr,
                          uint16_t port,
                          const char *name,
                          const char *model,
                          const char *out_path,
                          AltLoadReadyCb ready_cb,
                          AltLoadPinCb pin_cb,
                          void *ctx,
                          AltLoadResult *out);

void altload_result_free(AltLoadResult *r);


/* ---- On-device sideloading (core/src/install/mod.rs) ---- */

/* Installs sign only with the certificate iloader made, found on the account by
   the imported key (altload_import_signing_key below); nothing creates or revokes
   a certificate, and an install without an imported key fails before sign-in. */

typedef void (*AltLoadProgressCb)(void *ctx, const char *stage, double fraction); /* fraction < 0: indeterminate */
/* kind 1 = two-factor: answer with altload_install_session_respond within 120 s,
   or it counts as "abort". Kind 2 (revoke certificates) is never sent any more. */
typedef void (*AltLoadPromptCb)(void *ctx, int32_t kind, const char *json);

typedef struct {
    const char *host;
    uint16_t port;
    const char *identifier; /* TXT "identifier" of _remotepairing._tcp */
    const char *auth_tag;   /* TXT "authTag" */
} AltLoadEndpoint;

typedef struct {
    const char *apple_id;
    const char *password;
    const char *anisette_url;
    const char *pairing_file_path;
    const char *host_name;
    const AltLoadEndpoint *endpoints;
    size_t endpoint_count;
    const char *ipa_path;
    const char *device_name;
    const char *machine_name;
    const char *server_id;
    /* Comma-separated App Store Connect capability IDs to enable on the app's
       App ID before signing (e.g. "INCREASED_MEMORY_LIMIT,PUSH_NOTIFICATIONS").
       NULL or "" for none. */
    const char *capabilities;
    /* App extensions: 0 keep, 1 keep and sign with the main profile, 2 remove.
       0 and 1 both sign extensions with the main app's profile (one App ID). */
    int32_t extensions_mode;
} AltLoadInstallConfig;

typedef struct {
    char *error;
    char *bundle_id;
    char *app_name;
    char *app_version;
    char *udid;
    char *team_id;
    int64_t expiration_unix;
} AltLoadInstallResult;

typedef struct AltLoadInstallSession AltLoadInstallSession;

AltLoadInstallSession *altload_install_session_new(void);
int32_t altload_install_session_run(AltLoadInstallSession *session,
                                    const AltLoadInstallConfig *config,
                                    AltLoadProgressCb progress_cb,
                                    AltLoadPromptCb prompt_cb,
                                    void *ctx,
                                    AltLoadInstallResult *out);
int32_t altload_install_session_respond(AltLoadInstallSession *session, const char *response);
void altload_install_session_cancel(AltLoadInstallSession *session);
void altload_install_session_free(AltLoadInstallSession *session);
void altload_install_result_free(AltLoadInstallResult *r);


/* ---- Certificate manager: your own Apple ID (core/src/install/account.rs) ---- */

/* Runs {"op":"overview"} against the Apple ID's own team. {"op":"revoke",...}
   is refused (returns 1) before signing in: this build never revokes a
   certificate. Reuses an AltLoadInstallSession for 2FA prompts and cancel.
   Returns 0 with overview JSON in *out_json, or 1 with an error message.
   Free *out_json with altload_string_free. Blocking. */
int32_t altload_account_session_run(AltLoadInstallSession *session,
                                    const char *apple_id,
                                    const char *password,
                                    const char *anisette_url,
                                    const char *request_json,
                                    AltLoadProgressCb progress_cb,
                                    AltLoadPromptCb prompt_cb,
                                    void *ctx,
                                    char **out_json);
void altload_string_free(char *s);


/* ---- iloader's signing key (core/src/install/identity.rs) ---- */

/* Saves iloader's private key for apple_id (trimmed, lowercased), stored under
   sha256(apple_id)/key. data is a .p12 (password required) or a raw RSA key:
   PKCS#8/PKCS#1 DER, PEM or base64 (password NULL). Offline. Returns 0 with
   {"fingerprint":String,"certificateSerial":String|null,"certificateExpires":Int|null}
   (unix seconds) in *out_json, or 1 with an error message; 2 if out_json is NULL.
   Free *out_json with altload_string_free. Installs and refreshes then use only
   the certificate on the account whose public key is this key's. */
int32_t altload_import_signing_key(const char *apple_id,
                                   const uint8_t *data,
                                   size_t len,
                                   const char *password,
                                   char **out_json);

/* 1 if a key is imported for apple_id (any case), else 0. */
int32_t altload_has_signing_key(const char *apple_id);


/* ---- Profile-only refresh (core/src/install/refresh.rs) ---- */

/* Renews the 7-day profiles of installed apps signed with iloader's certificate
   and installs them with misagent; nothing is re-signed or reinstalled. Targets:
   hostBundleId (the LiveContainer this runs in; when null, iloader's
   com.kdt.livecontainer.<team>) and its extensions' profiles, then this app if
   it's installed itself, then the team's other apps whose profile lists that
   certificate; or only the bundle IDs in "only". A new profile goes in before
   older copies of it come off, and must list this device. Lapsed App IDs are
   registered again (with their app groups and Increased Memory Limit) when
   registerMissingAppIds is true, never in a dry run, which changes nothing on
   the account or the device.
   config: apple_id, password, anisette_url, pairing_file_path, host_name,
   endpoints/endpoint_count and device_name are used; the rest is ignored.
   request_json: {"dryRun":Bool,"registerMissingAppIds":Bool,"only":[String]|null,
   "hostBundleId":String|null}. Prompts: kind 1 (two-factor), as for installs.
   Returns 0 with
   {"team":String,"udid":String,"dryRun":Bool,"appIdsAvailable":Int|null,
    "results":[{"bundleId":String,"app":String,
                "status":"refreshed"|"planned"|"skipped"|"failed",
                "reason":String|null,"oldExpires":Int|null,"newExpires":Int|null}]}
   in *out_json, or 1 with an error message. Free *out_json with
   altload_string_free. Blocking. */
int32_t altload_refresh_profiles_run(AltLoadInstallSession *session,
                                     const AltLoadInstallConfig *config,
                                     const char *request_json,
                                     AltLoadProgressCb progress_cb,
                                     AltLoadPromptCb prompt_cb,
                                     void *ctx,
                                     char **out_json);


/* ---- Device ops: on-device AltServer + files into apps (core/src/install/device.rs) ---- */

/* Opens the tunnel from config (pairing_file_path, host_name, endpoints; the
   Apple ID fields are ignored) and runs one op from request_json:
   install_app, install_profiles, remove_profiles, remove_app, list_apps, place_file.
   Profiles of bundle IDs in "protect", of their extensions and of any
   LiveContainer are never removed, and remove_app refuses those apps.
   Returns 0 with result JSON in *out_json, or 1 with an error message.
   Free *out_json with altload_string_free. Blocking. */
int32_t altload_device_run(const AltLoadInstallConfig *config,
                           const char *request_json,
                           AltLoadProgressCb progress_cb,
                           void *ctx,
                           char **out_json);

/* Move / end a running {"op":"simulate_location"} (which blocks until stopped). */
void altload_location_update(double latitude, double longitude);
void altload_location_stop(void);

#ifdef __cplusplus
}
#endif

#endif // ALTLOAD_H
