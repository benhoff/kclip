# PyPasteServer Sync Client Specification for kclipd

- Status: Draft 0.1
- Audience: kclip and PyPasteServer maintainers
- Companion specification: `PyPasteServer/docs/kclip-sync-server-spec.md`

## 1. Purpose

This document specifies how the Rust `kclipd` daemon synchronizes its local
revision store through PyPasteServer. All supported end-user client behavior,
including authentication, encryption, offline queues, synchronization, and
desktop adapters, belongs in this repository. PyPasteServer remains a remote
authenticated relay and opaque encrypted event store.

The Python desktop daemon in PyPasteServer is a migration source, not part of
the target architecture.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Goals

- Keep `kclipd` as the only authority for local clipboard state.
- Continue working normally with no network connection or server account.
- Synchronize slots, arbitrary bytes, content types, and tombstones.
- Preserve revision origin and hybrid logical clock metadata across devices.
- Encrypt all clipboard semantics before they leave the device.
- Deliver local revisions after process and network restarts.
- Apply remote revisions idempotently and without feedback loops.
- Replace the PyPasteServer Python daemon and end-user CLI functionality.
- Use a versioned client/server contract with cross-repository test fixtures.

## 3. Non-goals

- Making the local Unix-socket IPC protocol available over the network.
- Giving the server plaintext, slot names, content hashes, or conflict logic.
- Requiring connectivity for `copy`, `paste`, `list`, or `clear`.
- Synchronizing revisions marked local-only or slots configured not to sync.
- Rotating the shared account encryption key in sync protocol version 1.
- Supporting the experimental `/dev/kclip` kernel interface.

## 4. Target architecture

```text
kclip CLI ----\
               \
Plasma adapter ---> kclipd storage ---> durable outbox ---> sync worker
               /          ^                                  |
other adapters /          |                                  v
                    durable inbox <--- encrypted events <--- PyPasteServer
```

All adapters submit mutations to the same storage service. A committed local
revision is the unit of synchronization. Network code MUST NOT bypass storage
or maintain a second clipboard value.

The sync worker SHOULD live in a dedicated crate such as `kclip-sync`, with
`kclip-daemon` responsible for lifecycle and configuration. The exact crate
boundary is not normative, but storage, protocol encoding, transport, and UI
adapters should remain independently testable.

## 5. Local operation must not depend on sync

When sync is disabled, misconfigured, unauthenticated, offline, or rejected by
the server:

- local mutations MUST still commit;
- CLI reads and writes MUST still work;
- desktop integration MUST still work;
- pending synchronized revisions MUST remain in the outbox; and
- daemon status MUST expose the sync problem without failing daemon startup.

The network worker MUST use bounded retries with jittered exponential backoff.
Authentication and non-retryable configuration failures SHOULD pause retries
until credentials or configuration change. Connectivity failures MUST NOT spam
logs or block local storage locks.

## 6. Configuration

The existing reserved configuration sections should become functional. A
representative configuration is:

```toml
[sync]
enabled = false
relay_url = "ws://192.168.1.50:8001/sync/v1"
reconnect_min_delay = "1s"
reconnect_max_delay = "5m"
device_name = "workstation"
token_path = "/home/example/.config/kclip/token.json"
pairing_path = "/home/example/.config/kclip/pairing.json"

[security]
require_encrypted_sync = true
sync_key_path = "/home/example/.local/share/kclip/sync.key"

[slots.default]
sync = true
```

Requirements:

- `enabled` defaults to false.
- A Noise-paired client MAY use a `ws://` relay on a trusted LAN. Legacy bearer
  authentication MUST require `wss://` unless an explicit development-only
  insecure override is set.
- `pairing_path`, `token_path`, and `sync_key_path` MUST resolve through normal
  XDG defaults when omitted.
- Secret files MUST be owned by the user, MUST be regular non-symlink files,
  and MUST not be accessible by group or other users.
- The 32-byte sync key MUST NOT be written to logs or status output.
- Slot-level `sync = false` and `is_local_only = true` MUST override the global
  setting.
- Configuration reload MAY be implemented without daemon restart; if it is,
  credentials and keys must be swapped atomically.

Enabling sync MUST no longer be rejected by phase-one validation once all
security prerequisites are satisfied.

## 7. Authentication and credential ownership

The Rust `kclip` CLI should provide the end-user account commands needed to
replace the Python CLI:

```text
kclip auth pair
kclip auth logout
kclip auth status
kclip key generate
kclip key import
kclip key export
```

`kclip auth pair` MUST read the one-time code through hidden input, validate its
version, canonical pairing ID, and 32-byte base64url secret, and atomically
write it with mode `0600` inside a mode `0700` directory. It MUST remove a local
bearer token after pairing so a handshake failure cannot trigger downgrade.
Local logout removes the credential but does not revoke the server copy; the
administrator MUST revoke that pairing ID separately.

Legacy password login and registration may remain for migration, but they MUST
require TLS. Passwords MUST never appear in command-line options or cross a
plaintext HTTP connection.

Version 1 uses one 32-byte account synchronization key shared by the user's
devices. For compatibility, migration MUST support the existing files:

```text
~/.config/clipboard_app/token.json
~/.config/clipboard_app/key
```

The old key file contains the 32 bytes of entropy represented by the existing
24-word BIP-39 mnemonic. Import MUST copy the value into the kclip-owned path
using safe permissions; the daemon MUST NOT keep reading a mutable legacy file
after successful migration.

Generating an unrelated key during login would isolate that device from
existing ciphertext. The CLI MUST clearly distinguish creating a new account
key from importing the mnemonic for an existing account.

Recovery escrow and account-key rotation require a later specification.

## 8. Server transport

`kclipd` connects to the `/sync/v1` WebSocket protocol defined by the companion
server specification.

Client requirements:

- Prefer the pairing file whenever it exists; an invalid pairing file is a hard
  credential error and MUST NOT cause bearer fallback.
- Send `X-Kclip-Transport: noise-psk-v1` and the public pairing ID, then initiate
  `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` with the device PSK.
- Encrypt every post-handshake application message as binary chunks matching
  the companion server specification. Noise transport counters provide strict
  ordering and replay rejection.
- Send `hello` before any other message.
- Persist the server replay cursor locally.
- Reuse a durable outbox `message_id` on every retry.
- Accept replay and live `event` messages through one processing path.
- Tolerate receiving its own uploaded event.
- Enforce local frame and decoded-field limits even if the server does not.
- Validate TLS certificates using the platform trust store whenever `wss` is
  configured.
- Never fall back silently from `wss://` to plaintext WebSocket.

The systemd user service must allow `AF_INET` and `AF_INET6` when sync is
supported; its current `AF_UNIX`-only sandbox is incompatible with network sync.
Network availability SHOULD order or trigger retries, but `kclipd` startup MUST
not wait indefinitely for `network-online.target`.

## 9. Encrypted revision envelope

### 9.1 Cryptography

Protocol version 1 uses:

- a 32-byte account synchronization key;
- XChaCha20-Poly1305;
- a new cryptographically random 24-byte nonce per message; and
- a 16-byte authentication tag.

The authenticated additional data is:

```text
UTF8("kclip-sync-v1") || 0x00 || UTF8(message_id)
```

Nonce reuse with the same key is forbidden. Encryption failure MUST leave the
outbox item pending and MUST NOT emit a partial push.

### 9.2 Canonical plaintext

The encrypted plaintext is canonical CBOR with this logical schema:

```text
SyncEnvelopeV1 {
    envelope_version: 1,
    message_id: string,
    revision: RevisionV1,
    content: bytes | null
}

RevisionV1 {
    revision_id: string,
    slot: string,
    origin_device_id: string,
    origin_sequence: unsigned integer,
    hlc_physical: signed integer,
    hlc_logical: unsigned integer,
    content_hash: string | null,
    content_size: unsigned integer,
    content_type: string | null,
    created_at: signed integer,
    expires_at: signed integer | null,
    is_deleted: boolean,
    source_adapter: string,
    parent_revision_id: string | null
}
```

Canonical CBOR means deterministic map-key ordering, shortest integer encoding,
definite lengths, and byte strings for `content`. The committed cross-repository
fixture is authoritative if a library's default differs.

For a live revision, `content` MUST be present, its length MUST equal
`content_size`, and its SHA-256 digest as 64 lowercase hexadecimal characters
MUST equal `content_hash`. `revision_id` MUST equal
`origin_device_id + ":" + decimal(origin_sequence)`. For a tombstone, `content`
and `content_hash` MUST be null and `content_size` MUST be zero.

`is_local_only` and `synchronization_state` are local policy/state and are not
accepted from a remote envelope. A local-only revision MUST never be encrypted
for upload.

The envelope `message_id` MUST equal the authenticated outer message ID.

## 10. Local revision and outbox flow

For every local `copy` or `clear` on a sync-enabled slot:

1. Validate the mutation and write any content blob.
2. Create the local revision and advance the local HLC.
3. Insert an outbox row referencing that revision and a newly generated UUID.
4. Commit the revision, slot head, HLC metadata, and outbox row atomically.
5. Notify in-process adapters after commit.
6. Wake the sync worker.

If the process crashes before step 4, neither revision nor outbox item exists.
If it crashes after step 4, startup scanning finds the pending outbox item.

The worker loads the referenced immutable revision and blob, constructs and
encrypts the envelope, and sends `push`. A successful `push_ack` records the
assigned server sequence and acknowledgement time. It MUST NOT delete revision
history or its content blob merely because delivery succeeded.

Multiple pending revisions MAY be uploaded concurrently, but per-device origin
sequence order SHOULD be preserved. Concurrency MUST be bounded.

## 11. Remote event and inbox flow

For every replayed or live event, the daemon performs these steps:

1. Validate outer fields, sizes, algorithm, and server sequence.
2. Persist or find an inbox record keyed by `message_id`.
3. Decrypt with the exact additional data.
4. Decode the canonical CBOR envelope.
5. Validate message ID, slot, revision ID, content size, content hash, and
   tombstone invariants.
6. Apply the revision idempotently while preserving its origin metadata.
7. Mark the inbox record processed and advance the highest contiguous local
   server cursor in the same transaction.
8. Notify local adapters if the revision becomes the slot head.
9. Send a checkpoint for the new contiguous cursor.

An existing `(origin_device_id, origin_sequence)` or `revision_id` with exactly
the same immutable fields is a successful duplicate. Conflicting data under an
existing identity is a permanent protocol/security error and MUST NOT overwrite
the original revision.

A permanently invalid or undecryptable event MUST be durably quarantined with
a safe error category. To avoid blocking all later events forever, it MAY count
as processed for cursor continuity only after quarantine is committed. The
daemon MUST surface a degraded synchronization status so the user knows that an
event was skipped. Error logs MUST not contain decrypted content or keys.

Remote application MUST NOT create an outbox item for the received revision.
That rule, plus identity deduplication, prevents feedback loops.

## 12. Storage changes

The existing revision, inbox, outbox, acknowledgement, and device tables should
be extended rather than replaced. Versioned migrations are required.

At minimum, storage needs:

- atomic local revision plus outbox insertion;
- retrieval of pending outbox items in deterministic order;
- retry time, attempt count, last error, server sequence, and acknowledgement;
- raw encrypted-event or safe quarantine information in the inbox;
- inbox processing state and error category;
- a durable highest contiguous server cursor;
- idempotent insertion of remote revisions without assigning a new local origin;
- deterministic slot-head conflict resolution; and
- garbage collection that treats pending outbox and inbox data as live roots.

The current `source_adapter = "cli"` constant must become an input from the
trusted daemon adapter layer. Suggested values for locally created revisions
include `cli` and `plasma`. A remote import MUST preserve the origin
`source_adapter` from its encrypted envelope. Transport provenance such as
`pypasteserver` belongs on the inbox record and MUST NOT mutate the immutable
revision. `source_adapter` is diagnostic provenance; it is not the primary
loop-prevention mechanism.

The database and blob store MUST remain usable while the network worker is
blocked or reconnecting. No network operation may execute while holding the
SQLite mutex or an open write transaction.

## 13. Conflict resolution and clocks

Every accepted revision is retained as history. The current slot head is chosen
deterministically using this ordering key:

```text
(hlc_physical, hlc_logical, origin_device_id, origin_sequence, revision_id)
```

The lexicographically greatest valid key wins. Tombstones use the same ordering
and receive no unconditional priority. This ensures every device presented with
the same revision set selects the same head.

When receiving a valid remote HLC, the daemon MUST advance its stored HLC using
the standard receive rule so that the next local event sorts after observed
causal state. Wall-clock rollback MUST increase the logical component rather
than producing a lower local clock.

If an incoming revision loses, it remains in history but MUST NOT trigger a
desktop clipboard replacement. If it wins, adapters are notified only after the
storage transaction commits.

## 14. Internal event routing and desktop adapters

The daemon needs an in-process revision notification channel emitted after
successful commits. Durable work MUST always be recoverable by scanning storage;
the notification channel is only a wake-up and UI mechanism.

Expected routing is:

- CLI or Plasma mutation -> storage -> optional outbox -> committed event.
- Remote event -> inbox -> storage without outbox -> committed event.
- Committed winning event -> eligible desktop adapters.

Adapters MUST NOT send a value directly to the server. They submit local
mutations to storage and let the outbox perform synchronization.

A public Unix-socket `watch` operation is useful for third-party adapters but is
not required for server synchronization when the sync worker runs inside
`kclipd`. If added, it must deliver revision identities and tombstones rather
than only clipboard text.

## 15. Status and CLI behavior

Daemon status should report at least:

- sync configured/enabled state;
- connection state;
- authenticated or credential-error state;
- pending outbox count;
- oldest pending age;
- last successful connection and acknowledgement times;
- local processed server cursor;
- last safe error category; and
- number of quarantined events.

It MUST NOT return tokens, key material, ciphertext, or decrypted previews.

`kclip copy`, `paste`, `list`, and `clear` retain their offline semantics.
Network delivery is asynchronous. A successful `copy` means the local revision
is durable, not that the server acknowledged it. An optional explicit sync-wait
command may be added later without changing normal clipboard commands.

## 16. Shutdown and startup

On startup, `kclipd` should:

1. Open and migrate storage.
2. Start local IPC immediately.
3. Recover temporary blobs and incomplete inbox/outbox state.
4. Start adapters.
5. Start the sync worker if enabled and validly configured.

On shutdown, it should stop accepting new network work, finish or cancel
in-flight requests safely, persist retry state, close the WebSocket, and then
close storage. Aborted pushes remain pending with the same message IDs.

## 17. Migration from the Python client

Migration should be explicit and reversible until validation succeeds:

1. Install the Rust release with sync disabled.
2. Import or reference the existing server URL, access token, and 32-byte key.
3. Copy secrets atomically into kclip-owned paths with strict permissions.
4. Verify authentication and decrypt a committed compatibility fixture.
5. Enable Rust sync and verify bidirectional delivery with another device.
6. Disable the Python desktop daemon.
7. Retain a timestamped backup of migrated configuration and secrets according
   to an explicit user-facing retention policy.

The migration tool MUST NOT print the mnemonic, raw key, or token unless the
user invokes a dedicated export operation with an interactive warning.

The first Rust release MAY support only the `default` text slot against the
legacy endpoint as a temporary compatibility stage. Such a mode must be clearly
labeled legacy and must not silently discard binary content, other slots, or
tombstones. The target `/sync/v1` implementation is the acceptance target.

## 18. Required tests

### 18.1 Cryptographic contract

- Known XChaCha20-Poly1305 vector shared with the server repository.
- Exact additional-data and base64url encoding.
- Canonical CBOR fixture round trip.
- Wrong key, nonce, tag, message ID, and altered ciphertext rejection.
- Nonce generation does not repeat in deterministic stress tests using an
  injectable test RNG.

### 18.2 Outbox durability

- Local revision and outbox creation are atomic.
- Restart retries the same message ID.
- Disconnect after server commit deduplicates on retry.
- Authentication and quota errors preserve pending revisions.
- Network work never blocks local copy/paste operations.

### 18.3 Inbox and replay

- Replay from zero and from a nonzero cursor.
- Duplicate self-echo and cross-connection events are idempotent.
- Cursor advances only over a contiguous processed prefix.
- Crash at each inbox processing stage recovers correctly.
- Invalid events are quarantined without exposing plaintext.

### 18.4 Revision semantics

- Text, binary, empty content, maximum-size content, and tombstones.
- Multiple slots and no-sync slots.
- Deterministic concurrent conflict resolution on two devices.
- Remote loser remains history without changing the slot head.
- Remote winner notifies adapters but creates no outbox echo.
- HLC behavior under equal clocks and wall-clock rollback.

### 18.5 Operational behavior

- Missing server, invalid TLS, revoked token, wrong key, and offline startup.
- Bounded retry, queue, and memory behavior.
- Clean shutdown with pending and in-flight work.
- Secret-file ownership, permissions, regular-file, and symlink checks.
- The systemd sandbox permits required network families without weakening
  unrelated filesystem protections.

### 18.6 End-to-end

Run two temporary daemons and one real PyPasteServer test instance:

1. Create a revision while device B is offline.
2. Restart device A and the server before acknowledgement.
3. Confirm the outbox retries without a duplicate server event.
4. Start device B and replay the revision.
5. Create a concurrent conflicting revision and confirm convergence.
6. Clear the slot and confirm both devices converge on the tombstone.
7. Confirm the server database and logs contain no plaintext or slot names.

## 19. Acceptance criteria

The client portion is complete when:

1. Local clipboard operations remain available with the server offline.
2. Two Rust daemons synchronize text, binary data, slots, and tombstones.
3. Local changes survive daemon restart before upload acknowledgement.
4. Remote events survive crashes during inbox processing and apply once.
5. Concurrent revisions converge deterministically.
6. The server receives only opaque authenticated ciphertext and routing data.
7. Existing token and mnemonic-derived key material can be migrated safely.
8. No Python desktop daemon or client CLI is required.
