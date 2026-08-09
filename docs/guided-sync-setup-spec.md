# kclip Guided Synchronization Setup Specification

- Status: Draft 0.1
- Audience: `dev_clipboard` maintainers
- Server: PyPasteServer `kclip-setup-v1`
- Compatibility policy: the former `auth`, `key`, bearer-token, and raw
  `kclip-pair-v1` user workflows do not need to remain compatible

## 1. Purpose

This document specifies the `dev_clipboard` work required to consume the
guided device setup produced by PyPasteServer. The target operator journey is:

```text
PyPasteServer host                 kclip client device
------------------                -------------------
./admin.sh device add   ------->  kclip sync setup
     one setup code                 hidden paste
                                      key choice
                                      config update
                                      daemon restart
                                      live verification
```

A user performing this task infrequently should not need to edit TOML, know
the distinction between a pairing credential and an account encryption key
before beginning, remember command ordering, or interpret a low-level daemon
state. Setup is successful only after `kclipd` receives a valid `/sync/v1`
`ready` response over an authenticated Noise connection.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Authoritative references

The server implementation is authoritative for the setup-code wire format:

- `/home/hoff/swdev/PyPasteServer/server_app/pairing.py`
  - `DeviceSetupCode.encode`
  - `DeviceSetupCode.parse`
  - `validate_relay_url`
- `/home/hoff/swdev/PyPasteServer/server_app/admin.py`
  - `_add_device`
- `/home/hoff/swdev/PyPasteServer/admin.sh`
  - `connect_device`
  - `show_client_handoff`
- `/home/hoff/swdev/PyPasteServer/docs/kclip-sync-server-spec.md`
  - section 5.1.1, “Administrative device setup code”

Relevant current client implementation points are:

- `crates/kclip-cli/src/lib.rs` — current `auth`, `key`, status, and secret
  prompting commands
- `crates/kclip-config/src/lib.rs` — XDG paths, sync resolution, private config
  updates, and backups
- `crates/kclip-sync/src/lib.rs` — `PairingCredential`, pairing-file
  persistence, Noise connection, and `RuntimeStatus`
- `crates/kclip-daemon/src/lib.rs` — daemon status exposed over local IPC
- `crates/kclip-protocol/src/lib.rs` — `DaemonStatus`

This focused specification supersedes the user-facing requirements in sections
6, 7, 15, and 17 of `docs/pypasteserver-sync-client-spec.md` where they describe
manual configuration, separate auth/key commands, status, or legacy migration.
That document remains authoritative for the sync transport, encrypted envelope,
durability, storage, and conflict-resolution design.

If this document and the server encoder disagree, the server encoder takes
precedence until both are corrected. Once the required cross-repository fixture
is added, any mismatch is a test failure.

## 3. Goals

1. Provide one primary setup command: `kclip sync setup`.
2. Consume one hidden `kclip-setup-v1` code from the server.
3. Configure the relay and device credential without manual file editing.
4. Clearly distinguish creating the first account key from joining an existing
   account.
5. Preserve existing local configuration and custom slots.
6. Restart the installed daemon once, wait for authentication, and report a
   verified result.
7. Turn sync status into an actionable checklist.
8. Never expose the setup code, pairing secret, raw sync key, or recovery words
   through arguments, logs, ordinary status output, or JSON errors.
9. Remove the obsolete user-facing bearer authentication and raw pairing-code
   workflows instead of maintaining aliases.

## 4. Non-goals

- Changing the `/sync/v1` Noise or encrypted event protocol.
- Sending the account encryption key to PyPasteServer.
- Supporting multiple synchronization accounts in one local kclip profile.
- Account-key rotation or recovery escrow.
- Automatically revoking a server credential; PyPasteServer currently exposes
  revocation only through its host-local administration interface.
- A GUI or QR-code reader.
- Migrating legacy Python-client bearer tokens or keys.
- Hot configuration reload in the first implementation. A controlled daemon
  restart is acceptable for this infrequent operation.

## 5. User-facing command surface

The supported synchronization surface SHOULD be:

```text
kclip sync setup
kclip sync status [--json]
kclip sync recovery-code
kclip sync disconnect
```

The existing top-level `kclip status` MAY remain as a compact overall daemon
status. `kclip sync status` owns detailed, actionable synchronization status.

Because backward compatibility is not required, remove these user commands
rather than retaining aliases:

```text
kclip auth pair|register|login|logout|status
kclip key generate|import|export
kclip migrate-legacy
```

Also remove bearer-token fallback from the daemon and its supporting client
configuration. A sync-enabled client MUST require a valid pairing credential.
An invalid or missing pairing file MUST be a hard credential error.

### 5.1 Expected successful interaction

```text
$ kclip sync setup

Client setup code: [hidden]

Server:  wss://clipboard.example.test/sync/v1
Account: alice
Device:  office-laptop

How should this device get the shared encryption key?
  1) This is the first device for this account
  2) Join devices that are already synchronized
Choice [1-2]: 1

Recovery words protect access to synchronized clipboard history.
Store them somewhere private. They will be shown once during setup.

<24 recovery words>

Have you saved the recovery words? [y/N] y

✓ Device credential stored
✓ Synchronization configuration updated
✓ kclipd restarted
✓ Authenticated with PyPasteServer

Synchronization is ready.
```

For option 2, the CLI MUST request the existing 24-word recovery mnemonic
through hidden input and MUST NOT echo it.

## 6. Device setup code contract

### 6.1 Outer encoding

The setup code is one line:

```text
kclip-setup-v1:BASE64URL(JSON_UTF8)
```

Requirements:

- The prefix MUST be exactly `kclip-setup-v1`.
- The prefix and payload MUST be separated at the first `:` only.
- The payload MUST use unpadded RFC 4648 base64url.
- The encoded input MUST be bounded before allocation. A 16 KiB maximum is
  sufficient for version 1.
- The decoded bytes MUST be valid UTF-8 JSON.
- The JSON object MUST reject unknown and duplicate fields. Future incompatible
  setup formats use a new outer prefix.

### 6.2 JSON payload

The decoded object contains exactly:

```json
{
  "version": 1,
  "relay_url": "wss://clipboard.example.test/sync/v1",
  "username": "alice",
  "device_name": "office-laptop",
  "pairing_id": "eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5",
  "pairing_secret": "unpadded-base64url-32-bytes"
}
```

Validation requirements:

- `version` MUST be the integer `1`.
- `relay_url` MUST use `ws` or `wss`, include a host, have the exact path
  `/sync/v1`, and contain no username, password, query, or fragment. Use a real
  URL parser rather than string-prefix validation.
- `username` MUST be a non-empty string. It is display context, not an
  authorization input.
- `device_name` MUST be a non-empty string. It is display context and should be
  stored for status output.
- `pairing_id` MUST be a canonical lowercase UUID. Parsing and serializing the
  UUID MUST reproduce the input exactly.
- `pairing_secret` MUST be canonical unpadded base64url decoding to exactly 32
  bytes.

JSON key order is not significant. The current Python encoder sorts keys only
to make its own output deterministic.

### 6.3 Secret handling

The setup code contains the long-lived device PSK. “Shown once” describes the
server UI; the credential itself remains valid until revoked.

The client MUST:

- read it with hidden terminal input;
- refuse a command-line `--code` value;
- never include it in process arguments, environment variables, shell history,
  logs, tracing fields, panic text, or JSON output;
- avoid printing the pairing secret after decoding;
- persist only the existing private `PairingCredential` representation;
- use mode `0600` for the file and mode `0700` for its directory; and
- discard the complete setup-code string after validated fields have been
  staged.

`username`, `device_name`, `relay_url`, and `pairing_id` are safe to show in
diagnostic output. The pairing secret and account key are not.

## 7. Guided setup state machine

### 7.1 Preflight and validation

Before mutating disk, `kclip sync setup` MUST:

1. Require an interactive terminal for secret prompts and recovery-word output.
2. Load the current configuration and resolve its XDG paths.
3. Read and validate the setup code completely.
4. Display the relay, account, and device labels for confirmation.
5. Validate any existing config, pairing credential, and sync key.
6. Determine whether the operation is a fresh setup or an idempotent retry.

Malformed setup input or unsafe existing secret files MUST leave every file
unchanged.

### 7.2 Existing setup rules

The initial implementation supports one account per local profile.

- Add display-only `account_name` to `[sync]`; use the existing `device_name`
  field for the server-provided device label.
- If sync is already configured for a different relay or account, abort without
  mutation. Replacing accounts and reconciling existing inbox/outbox data is a
  separate design problem.
- If a valid sync key already exists and the stored relay/account metadata
  matches, reuse it. Never replace or regenerate it silently.
- If a key exists but the account cannot be matched, abort with an explanation
  rather than guessing.
- A new setup code for the same account MAY replace the local pairing
  credential. After success, display the previous pairing ID and advise the
  operator to revoke that old device entry on the server.
- Re-running setup after a transient verification failure MUST be safe and
  idempotent.

### 7.3 Account encryption key choice

The setup code deliberately does not contain the 32-byte account key.

If no key exists, setup MUST ask one question with no default:

```text
1) This is the first device for this account
2) Join devices that are already synchronized
```

For the first device:

1. Generate a new 32-byte key in memory.
2. Derive its 24-word recovery mnemonic using the existing crypto crate.
3. Explain that every additional device needs these words and that losing all
   copies loses access to synchronized history.
4. Print the mnemonic only to an interactive terminal.
5. Require explicit confirmation that it was saved before committing setup.
6. If confirmation is declined or input closes, write nothing.

For an additional device:

1. Prompt for the existing 24 words through hidden input.
2. Validate the mnemonic and derive the 32-byte key in memory.
3. Never generate a fallback key after invalid input.
4. Permit retry or cancellation without disk mutation.

The UI MUST explain that the setup code authenticates this device while the
recovery words encrypt clipboard contents shared by all devices.

### 7.4 Atomic local commit

After all input is valid, stage the complete change before enabling sync.

Required order:

1. Create private parent directories.
2. Stage a new sync key, if one is needed.
3. Stage the pairing credential derived from the setup payload.
4. Stage an updated config containing at least:

   ```toml
   [sync]
   enabled = true
   relay_url = "wss://clipboard.example.test/sync/v1"
   account_name = "alice"
   device_name = "office-laptop"
   ```

5. Validate the fully rendered config with `Config` before replacement.
6. Commit the key and pairing file first and the enabling config last, using
   same-filesystem atomic renames and directory synchronization.

The config updater MUST preserve unrelated values and custom slot tables. It
MUST create a private timestamped backup before replacing an existing config.
Any secret backup MUST also remain mode `0600` in a mode `0700` directory.

If a local write fails before the config commit, restore prior files or remove
new staged files. Never leave sync enabled with only some prerequisites.

Once a complete setup has been committed, a network verification failure MUST
NOT delete it. The server shows the credential only once, and connectivity may
be temporarily unavailable. Report “configured but not connected,” return a
nonzero exit status, and direct the user to `kclip sync status`.

### 7.5 Daemon restart

The installed service currently loads configuration at process start. The
initial implementation SHOULD:

1. Detect the installed `kclipd.service` in the current user's systemd manager.
2. Run `systemctl --user restart kclipd.service` without privilege escalation.
3. Wait for the Unix socket to reappear.
4. If systemd is unavailable but a daemon is running manually, leave the
   complete setup committed and print the exact manual restart instruction.
5. Never report verified success until a restarted daemon has loaded the new
   files.

A future daemon IPC reload operation may replace this restart, but setup MUST
still validate the whole new configuration before swapping workers.

### 7.6 Live verification

After restart, poll daemon status for up to 20 seconds. Success requires all of:

```text
synchronization_enabled == true
synchronization_configured == true
synchronization_state == "connected"
authenticated == true
credential_error == false
```

This state is reached only after the client validates the server's `ready`
message in `kclip-sync`. A local pairing file being present is not success.

The setup command SHOULD show progress without printing retry noise. On timeout,
it MUST print the most actionable known cause and preserve the committed setup.

## 8. Actionable synchronization status

`kclip sync status` MUST combine local checks with daemon runtime status. It
should work partially even when `kclipd` is unavailable.

Human output should be a checklist:

```text
Synchronization: setup incomplete

✓ configuration: enabled
✓ relay: wss://clipboard.example.test/sync/v1
✓ account: alice
✓ device credential: present
✗ account encryption key: missing
✓ daemon: running
✗ server connection: waiting for credentials

Next: run `kclip sync setup`
```

Connected output should include the account and device labels, relay URL, last
successful connection, pending outbox count, processed server cursor, and
quarantined event count. It MUST NOT print secret paths unless `--verbose` is
added in a later design.

At minimum, map runtime failures to these actions:

| Condition | User-facing action |
| --- | --- |
| Sync disabled or config missing | Run `kclip sync setup` |
| Invalid config | Name the invalid field and config path |
| Pairing file missing or unsafe | Run setup again; do not fall back to bearer auth |
| Server authentication rejected | Ask the server operator to add this device again |
| Connectivity or TLS failure | Show the relay URL and suggest checking reachability/TLS |
| Account key missing | Run setup and choose first/additional device correctly |
| Cryptography/quarantined events | Import the correct account recovery words; do not generate a new key |
| Daemon unavailable | Start or inspect `kclipd.service` |

`kclip sync status --json` MAY expose stable non-secret fields and MUST use a
nonzero exit status when setup is incomplete or unhealthy.

## 9. Recovery code and disconnect

### 9.1 `kclip sync recovery-code`

This command replaces `kclip key export --show`.

It MUST require an interactive terminal, warn that anyone with the words can
decrypt synchronized history, request confirmation, and print the 24 words. It
MUST never support ordinary JSON output or include the mnemonic in an error.

### 9.2 `kclip sync disconnect`

This command MUST:

1. Explain that local disconnection does not revoke the server credential.
2. Show the non-secret pairing ID and the server-side instruction:
   `./admin.sh device revoke PAIRING_ID`.
3. Disable sync in config and remove the local pairing credential.
4. Restart the daemon so it stops reconnecting.
5. Retain the account sync key by default to prevent accidental data loss.

Deleting the account key requires a separately designed destructive operation;
it MUST NOT be an incidental part of disconnect.

## 10. Removal of legacy client paths

Because compatibility is explicitly out of scope, the implementation should
remove rather than hide:

- `AuthCommand`, `KeyCommand`, and `MigrateLegacy` from `kclip-cli`;
- `AuthClient`, `TokenFile`, token reads/writes, and bearer selection from
  `kclip-sync`;
- `token_path` and `allow_insecure_transport` from `SyncConfig` and
  `ResolvedSyncConfig`;
- the `kclip-pair-v1` prompt/parser as a user-facing setup path;
- legacy token-related tests and README instructions.

Existing legacy files on disk should be ignored. Do not delete them silently
during setup.

A Noise-paired client MAY continue to use `ws://` on a trusted LAN. The
pairing credential is mandatory in that case. `wss://` remains recommended for
Internet exposure.

## 11. Suggested code ownership

### `kclip-sync`

- Add the strict `DeviceSetupCodeV1` parser.
- Convert its pairing fields into `PairingCredential` and persist them with the
  existing atomic secret writer.
- Remove bearer fallback and token/account HTTP code.
- Keep connection verification authoritative: `connected` and `authenticated`
  are set only after a valid server `ready` response.

### `kclip-config`

- Add optional `sync.account_name` display metadata.
- Use existing `sync.device_name` for the server-provided label.
- Add a targeted, private config update that sets setup-owned fields while
  preserving other sections and creating a backup.
- Remove token and insecure-bearer fields.

### `kclip-cli`

- Add the `Sync` command tree and guided orchestration.
- Keep secret prompting and recovery confirmation at the CLI boundary.
- Abstract daemon restart/status polling so it can be tested without invoking a
  real user service.
- Render human and JSON status from one non-secret status model.

### `kclip-daemon` and `kclip-protocol`

- Existing `DaemonStatus` fields are sufficient for setup verification.
- Preserve `connected`/`authenticated` semantics.
- Improve error categories only where required to distinguish local credential,
  authentication, connectivity/TLS, protocol, and cryptography failures.

## 12. Test requirements

### 12.1 Shared setup fixture

Add a deterministic `kclip-setup-v1` fixture to both repositories. It should use:

- pairing ID `eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5`;
- pairing secret bytes `0..31`;
- relay `wss://clipboard.example.test/sync/v1`;
- username `alice`; and
- device name `office-laptop`.

The Rust decoder MUST consume the exact line emitted by the Python encoder.
The Python decoder SHOULD consume any fixture emitted by the Rust test encoder
if a Rust encoder is implemented.

### 12.2 Parser tests

Reject:

- wrong prefix or version;
- padded, standard-base64, malformed, oversized, or non-UTF-8 payloads;
- non-object JSON, duplicate, missing, or extra fields;
- invalid relay scheme, authority, path, user information, query, or fragment;
- noncanonical UUIDs; and
- pairing secrets not exactly 32 bytes.

### 12.3 Setup transaction tests

Cover:

- fresh first-device setup;
- fresh additional-device mnemonic import;
- existing valid key reuse for the same account;
- refusal to replace a different configured account;
- cancellation before recovery confirmation;
- invalid/unsafe existing secret files;
- config preservation and backup permissions;
- rollback after each staged local write failure;
- committed setup retained after network verification failure;
- daemon restart failure and manual fallback; and
- idempotent retry after a transient failure.

Test harnesses MUST inject input/output, service control, time, and status
polling. Tests must assert that setup codes, pairing secrets, keys, and
mnemonics never appear in logs or ordinary error output.

### 12.4 Status tests

Cover disabled, invalid config, missing credential, missing key, daemon down,
connecting, authentication rejected, connectivity failure, connected, pending
outbox, and cryptography quarantine states. Every unhealthy human-readable
state MUST include a concrete next action.

### 12.5 End-to-end acceptance

Against a test PyPasteServer:

1. Create an account and device setup code through the new server admin path.
2. Run client setup using an injected hidden-input source.
3. Restart `kclipd` and wait for `connected` plus `authenticated`.
4. Confirm the server marks that pairing as used.
5. Confirm a second device using the imported mnemonic decrypts synchronized
   clipboard data.
6. Revoke the device on the server and confirm client status reports an
   authentication failure with the correct next action.

## 13. Implementation sequence

1. Add the setup-code model, strict decoder, and shared fixture in `kclip-sync`.
2. Add targeted sync configuration updates and `account_name` in
   `kclip-config`.
3. Implement `kclip sync setup`, key branching, staged writes, restart, and
   verification in `kclip-cli`.
4. Implement actionable `kclip sync status`.
5. Add recovery-code and disconnect lifecycle commands.
6. Remove legacy auth, key, migration, token, and bearer paths.
7. Update the installer completion message and README to document only the new
   flow.
8. Run unit, integration, fixture parity, and two-device end-to-end tests.

## 14. Acceptance criteria

The work is complete when:

1. A fresh user runs one server command and one client command without editing
   TOML.
2. Setup never asks the user to understand or invoke separate auth/key commands.
3. The first/additional-device key choice is explicit and safe.
4. No success message appears before an authenticated server `ready` response.
5. Every common incomplete or failed state names the next action.
6. Existing custom slots and unrelated config survive setup.
7. Secrets never appear in arguments, logs, normal status, or JSON errors.
8. A server-generated setup fixture decodes identically in Rust.
9. The obsolete bearer and raw pairing-code user surfaces are absent.
10. Two devices configured through the guided flow synchronize and decrypt the
    same clipboard history.
