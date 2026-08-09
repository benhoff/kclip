# kclip

`kclip` is an offline-first command-line clipboard for Linux. A Rust CLI talks
only to a local per-user daemon. The daemon optionally synchronizes encrypted
revisions through PyPasteServer, while local commands continue to work without
a graphical session, account, server, or network connection.

```text
kclip CLI -> length-prefixed CBOR -> Unix socket -> kclipd -> SQLite + blobs
                                                    |
                                             encrypted outbox
                                                    |
                                      PyPasteServer /sync/v1
```

The previous kernel prototype remains isolated under `kernel/`; it is not used
by the Rust implementation and is not built by default.

## Build and run

Rust 1.88 or newer is required.

```bash
make
make test

# Terminal 1 (XDG_RUNTIME_DIR must be set)
cargo run -p kclip-daemon --bin kclipd

# Terminal 2
printf 'hello' | cargo run -q -p kclip-cli --bin kclip -- copy
cargo run -q -p kclip-cli --bin kclip -- paste
```

The second command writes exactly `hello`; paste never adds a newline.

For the lowest-interaction installation, run:

```bash
./install.sh
```

Run it as your normal user, not through `sudo`; the script prompts for
administrator authentication itself only if it needs to update system binaries.

The installer builds the release, installs `kclip` and `kclipd` under
`/usr/local/bin`, creates or updates the current user's configuration, installs
the systemd user service, and starts it. It requests administrator credentials
only when the binaries actually need to be written. Running it again performs
an update. Existing configuration values and custom slots are preserved; newly
introduced defaults are merged, and the pre-migration file is retained as a
timestamped backup.

Useful non-interactive overrides:

```bash
./install.sh --user             # use ~/.local/bin without sudo
./install.sh --prefix /opt/kclip # use a custom installation prefix
./install.sh --no-start         # install without starting the service
```

If `sudo` is unavailable, the default installation automatically falls back to
`~/.local`. If the selected binary directory is not already on `PATH`, the
installer adds it to the current user's Bash, Zsh, Fish, or POSIX shell profile;
open a new shell afterward to use `kclip` by name. `make install` remains
available and installs below the Makefile's `PREFIX`, which defaults to
`~/.local`.

## Commands

```bash
kclip copy [--slot NAME] [--file PATH] [--content-type TYPE] [--local]
kclip paste [--slot NAME] [--file PATH]
kclip list
kclip clear [--slot NAME] [--local]
kclip status
kclip sync setup
kclip sync status [--json]
kclip sync recovery-code
kclip sync disconnect
```

Global options:

```text
--socket PATH   Override $XDG_RUNTIME_DIR/kclip/kclipd.sock
--json          Emit JSON for copy, list, clear, and paste used with --file
```

Examples:

```bash
kclip copy < archive.tar
kclip paste > archive-copy.tar
kclip copy --slot build-log --file build.log
kclip paste --slot build-log --file restored.log
kclip list
kclip clear --slot build-log
```

Copy has no success output by default. Paste to stdout always returns raw stored
bytes. `paste --json` therefore requires `--file`, ensuring JSON formatting can
never corrupt piped clipboard data.

## Encrypted synchronization

Synchronization is opt-in. On the PyPasteServer host, add a device and copy the
one setup handoff shown by the administrator command. Then run the guided setup
on the client device:

```bash
./admin.sh device add              # on the PyPasteServer host
kclip sync setup                   # on this client; setup code input is hidden
```

Setup configures the relay and device label, asks whether this is the first
device or an additional device, stores the private credential and account key,
restarts `kclipd`, and does not report success until the daemon authenticates a
live Noise connection. First-device setup displays 24 recovery words once;
additional devices enter those same words through hidden input. Use
`kclip sync status` for an actionable local-and-live checklist.

Use `kclip copy --local` for values that must never enter the durable outbox.
`[slots.NAME] sync = false` enforces the same policy for a whole slot. A normal
copy succeeds after the local SQLite transaction commits; it never waits for
the relay. The outbox retries with the same message ID after daemon, network,
or server restarts.

The relay receives routing identifiers and XChaCha20-Poly1305 ciphertext only.
Slot names, content types, hashes, bytes, tombstones, and revision clocks are
inside a canonical-CBOR encrypted envelope. A paired client uses
`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`: both peers contribute ephemeral keys,
all post-handshake application frames are encrypted and authenticated, and
Noise counters reject replay or reordering. This permits `ws://` on a trusted
LAN without sending passwords or bearer tokens. TLS remains recommended for
Internet exposure because it also hides more metadata and integrates with
network-edge controls.

The setup credential only protects and authenticates this device's network
session. The account sync key remains separate and provides end-to-end
clipboard encryption across devices. `kclip sync disconnect` disables local
sync and removes the device credential while retaining the account key. It also
prints the pairing ID and the server-side revocation command; local disconnect
alone cannot revoke the server copy. `kclip sync recovery-code` is the only
command that prints recovery material and requires an interactive warning and
confirmation.

## Storage and durability

Defaults follow the XDG base-directory specification:

- Socket: `$XDG_RUNTIME_DIR/kclip/kclipd.sock`
- Database: `$XDG_DATA_HOME/kclip/kclip.db`, falling back to
  `~/.local/share/kclip/kclip.db`
- Blobs: `$XDG_DATA_HOME/kclip/blobs`
- Configuration: `$XDG_CONFIG_HOME/kclip/config.toml`, falling back to
  `~/.config/kclip/config.toml`
- Noise pairing credential: `$XDG_CONFIG_HOME/kclip/pairing.json`
- Account sync key: `$XDG_DATA_HOME/kclip/sync.key`

The daemon refuses to use an implicit socket when `XDG_RUNTIME_DIR` is missing.
Its runtime directory must be owned by the current user and inaccessible to
other users. Socket clients are authenticated with Linux peer credentials.

SQLite runs with WAL, foreign keys, and `synchronous=FULL`. Every content blob is
named by its SHA-256 digest, written to a private temporary file, flushed, and
atomically renamed before the revision transaction commits. Identical content is
deduplicated. The default maximum value is 10 MiB and can be changed in the
configuration; see [`config/kclip.toml.example`](config/kclip.toml.example).

## JSON schema

`copy` and `clear` return one revision metadata object. `list` returns an array of
the same objects. These fields are stable for protocol version 1:

```json
{
  "revision_id": "device-…:1",
  "slot": "default",
  "origin_device_id": "device-…",
  "origin_sequence": 1,
  "hlc_physical": 0,
  "hlc_logical": 0,
  "content_hash": "sha256-hex-or-null",
  "content_size": 5,
  "content_type": "text/plain; charset=utf-8",
  "created_at": 0,
  "expires_at": null,
  "is_deleted": false,
  "is_local_only": false,
  "source_adapter": "cli",
  "synchronization_state": "local"
}
```

Times are Unix milliseconds. Human-readable `list` output is tab-separated and
contains slot, revision, size, content type, origin device, update time,
expiration, and synchronization state.

## Workspace

- `crates/kclip-cli` — argument parsing, stdin/file handling, and IPC client
- `crates/kclip-daemon` — secure Unix listener and concurrent request dispatch
- `crates/kclip-protocol` — versioned CBOR messages and structured errors
- `crates/kclip-storage` — SQLite revisions and content-addressed blobs
- `crates/kclip-config` — XDG paths and validated TOML configuration
- `crates/kclip-crypto` — canonical CBOR and XChaCha20-Poly1305 envelopes
- `crates/kclip-sync` — setup-code parsing, Noise authentication, and durable WebSocket replay
- `packaging/systemd` — hardened headless user service
- `kernel` — unsupported experimental kernel prototype

Pairing/key rotation, history/TTL commands, watch subscriptions, and KDE Plasma
integration remain later phases. Protocol version 1 deliberately uses one
shared 32-byte account key and retains every accepted relay event.
