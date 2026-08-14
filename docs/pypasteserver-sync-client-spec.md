# PyPasteServer Sync Client Specification for kclipd

- Status: Draft 0.5
- Audience: kclip and PyPasteServer maintainers
- Companion specification: `PyPasteServer/docs/kclip-sync-server-spec.md`

## 1. Purpose

This document specifies how the Rust `kclipd` daemon synchronizes its local
revision store through PyPasteServer. All supported end-user client behavior,
including authentication, encryption, offline queues, synchronization, and
desktop adapters, belongs in this repository. PyPasteServer remains a bounded,
lossy, authenticated relay for opaque encrypted events. It is not a permanent
clipboard history or a complete-state backup.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

## 2. Goals

- Keep `kclipd` as the only authority for local clipboard state.
- Continue working normally with no network connection or server account.
- Synchronize slots, arbitrary bytes, content types, and tombstones.
- Preserve revision origin and hybrid logical clock metadata across devices.
- Encrypt all clipboard semantics before they leave the device.
- Deliver local revisions after process and network restarts.
- Apply remote revisions idempotently and without feedback loops.
- Recover automatically from a server-retained suffix after an older event
  prefix expires.
- Make relay-history loss visible to operators without requiring end users to
  manage history or repair cursors.
- Replace the PyPasteServer Python daemon and end-user CLI functionality.
- Use a versioned client/server contract with cross-repository test fixtures.

## 3. Non-goals

- Making the local Unix-socket IPC protocol available over the network.
- Giving the server plaintext, slot names, content hashes, or conflict logic.
- Requiring connectivity for `copy`, `paste`, `list`, or `clear`.
- Synchronizing revisions marked local-only or slots configured not to sync.
- Rotating the shared account encryption key in sync protocol version 1.
- Supporting the experimental `/dev/kclip` kernel interface.
- Reconstructing revisions, slot values, or tombstones that expired before the
  client received them.
- Server-side snapshots, per-slot compaction, or state transfer. Slot identity
  is encrypted and unavailable to the relay.
- Pruning the client's local revision database. Local retention is a separate
  concern from relay retention.
- Backward compatibility with the pre-retention sync-v1 wire contract. This
  specification replaces that contract rather than negotiating with it.
- Importing legacy bearer tokens, Python-client configuration, or the retired
  server endpoints.

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
Authentication and credential failures use the same capped backoff so replacing
a credential can recover without restarting the daemon. Invalid configuration
disables the network worker until the configuration is corrected and the daemon
is restarted. Failures MUST NOT spam logs or block local storage locks.

### 5.1 Local IPC

Local IPC carries exactly one request and one response per Unix-socket
connection, so neither frame contains a request ID. A response contains its
protocol version and one explicit `result`, which is either a success payload
or an error. Copy and clear share one revision-metadata payload variant. IPC
errors contain only a stable code and safe message; retry policy and diagnostic
categories remain internal to the daemon. Status does not repeat facts implied
by a successful connection, such as `daemon_available`, or by adapter state,
such as `plasma_enabled`. Pre-clean-break IPC shapes are unsupported.

## 6. Configuration

The supported synchronization configuration has this representative form:

```toml
[sync]
enabled = false
relay_url = "ws://192.168.1.50:8001/sync/v1"
account_name = "alice"
reconnect_min_delay = "1s"
reconnect_max_delay = "5m"
device_name = "workstation"
pairing_path = "/home/example/.config/kclip/pairing.json"
sync_key_path = "/home/example/.local/share/kclip/sync.key"

[slots.default]
sync = true
```

Requirements:

- `enabled` defaults to false.
- A Noise-paired client MAY use a `ws://` relay on a trusted LAN.
- `relay_url` and `account_name` are required when synchronization is enabled.
- `pairing_path` and `sync_key_path` MUST resolve through normal XDG defaults
  when omitted.
- `sync_key_path` belongs to `[sync]`; there is no `[security]` compatibility
  table.
- Secret files MUST be owned by the user, MUST be regular non-symlink files,
  and MUST not be accessible by group or other users.
- The 32-byte sync key MUST NOT be written to logs or status output.
- Slot-level `sync = false` and a mutation marked `is_local_only = true` MUST
  each prevent that revision from entering the outbox.
- Configuration reload MAY be implemented without daemon restart; if it is,
  credentials and keys must be swapped atomically.

An invalid sync configuration MUST NOT prevent local daemon startup. Status MUST
report the configuration error while leaving synchronization disabled.
Obsolete history fields, `plasma.text_only`, and per-slot `plasma_mirror`
aliases are rejected rather than ignored or migrated.

## 7. Authentication and credential ownership

The Rust `kclip` CLI provides these synchronization commands:

```text
kclip sync setup [--recovery-file PATH]
kclip sync status
kclip sync recovery-code [--output PATH]
kclip sync disconnect
```

`kclip sync setup` MUST read the server-generated setup code through hidden
input and strictly validate its version, relay URL, account and device labels,
canonical pairing ID, and 32-byte base64url secret. It then guides the user to
either generate the first account synchronization key or join an existing
account by entering its 24 recovery words through hidden input or supplying a
private recovery file. Configuration, the pairing credential, and any newly
supplied key MUST be committed as one recoverable setup operation. Secret files
use mode `0600` inside mode `0700` directories.

Version 1 uses one 32-byte account synchronization key shared by the user's
devices. Generating an unrelated key would isolate that device from existing
ciphertext, so setup MUST clearly distinguish the first device from a device
joining an existing account. It MUST NOT discover or import Python-client files
automatically.

`kclip sync recovery-code` reveals the current account recovery words after an
interactive warning and confirmation, or writes them to an explicitly requested
mode-`0600` file. `kclip sync setup --recovery-file PATH` lets another client
import that private file without exposing the words in process arguments.
`kclip sync disconnect` disables sync and removes the local pairing credential
while retaining the account key; it MUST explain that server-side revocation is
a separate administrator action.

Recovery escrow and account-key rotation require a later specification.

## 8. Server transport and rolling retention

`kclipd` connects to the `/sync/v1` WebSocket protocol defined by the companion
server specification.

Client requirements:

- Require a valid pairing file. A missing or invalid pairing is a hard
  credential error; no alternate sync authentication method exists.
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

### 8.1 Initial replay contract

The client sends its durable local cursor as `resume_after` in `hello`. The
server's `ready` response has this required shape:

```json
{
  "type": "ready",
  "protocol_version": 1,
  "connection_id": "5c3f...",
  "latest_sequence": 57,
  "earliest_sequence": 50,
  "replay_from": 50,
  "history_truncated": true
}
```

All fields shown above are required. The client MUST reject a `ready` that
omits `earliest_sequence` or `history_truncated`; it MUST NOT infer the old,
unbounded replay behavior.

The fields obey these invariants:

```text
1 <= earliest_sequence <= latest_sequence + 1
replay_from = max(resume_after + 1, earliest_sequence)
history_truncated = (resume_after + 1 < earliest_sequence)
```

When no events are retained, `earliest_sequence` equals
`latest_sequence + 1`. A `resume_after` greater than `latest_sequence` means
the server sequence history was reset or replaced; the server returns the
terminal `replay_unavailable` error and the client MUST NOT silently move its
cursor backward.

When `history_truncated` is false, normal contiguous replay begins at
`resume_after + 1`. When it is true, the client MUST:

1. Validate the complete `ready` message and its invariants.
2. Durably advance its processed cursor through `earliest_sequence - 1`.
3. Process retained `event` messages beginning at `replay_from` through the
   normal inbox path.

Advancing across the expired prefix creates no inbox rows, revisions,
tombstones, HLC updates, outbox entries, or adapter notifications. Existing
local slot heads remain unchanged unless a retained event later replaces them.
This intentionally permits stale slots and missed clears on a device that was
offline beyond the rolling buffer.

### 8.2 Truncation on an active connection

If retention passes an already-connected client's next deliverable sequence,
the server sends this message before sending more events:

```json
{
  "type": "history_truncated",
  "protocol_version": 1,
  "earliest_sequence": 50,
  "latest_sequence": 57,
  "replay_from": 50
}
```

All fields are required. The client MUST recognize this as a normal control
message, validate `replay_from == earliest_sequence` and
`1 <= earliest_sequence <= latest_sequence + 1`, durably advance through
`earliest_sequence - 1`, and continue consuming the same connection. It MUST
NOT deserialize the message as an error, disconnect
solely because history expired, or require user intervention.

Receiving the same or an older retention floor is an idempotent no-op. A floor
beyond the current cursor MUST be committed before any event at or after that
floor is applied. Locally persisted inbox entries below the floor remain real
data: the daemon MUST finish or quarantine them before advancing the cursor
past them.

### 8.3 Compatibility policy

The rolling-retention messages above are the only supported sync-v1 contract.
The client and server will be deployed as a matched pair. There is no feature
bit, optional-field interpretation, old-`ready` fallback, dual decoder, or
migration window for clients implementing the earlier unbounded contract.
Shared wire fixtures MUST be replaced with the required-field form. The
protocol version remains 1 because this specification replaces the prior draft
before it became a supported contract; it does not preserve the draft behavior.

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

`parent_revision_id` is an immutable weak causal reference. Its referenced
revision MAY be absent locally because synchronization began after the parent
was created, the parent is local-only, or relay retention removed it. Clients
MUST preserve the identifier but MUST NOT require the parent revision to exist,
backfill ancestors, or block application of an otherwise valid revision.

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
encrypts the envelope, and sends `push`. A successful `push_ack` deletes the
pending outbox row and records the latest acknowledgement time in local state.
It MUST NOT delete revision history or its content blob merely because delivery
succeeded.

The client MUST reuse the outbox `message_id`, but server deduplication is
guaranteed only while the original event remains in the rolling buffer. If an
unacknowledged event expires before retry, the server may accept the same
`message_id` again under a new server sequence. The client MUST accept that
acknowledgement and rely on immutable revision identity to make the resulting
self-echo and remote delivery idempotent.

Multiple pending revisions MAY be uploaded concurrently, but per-device origin
sequence order SHOULD be preserved. Concurrency MUST be bounded.

## 11. Remote event and inbox flow

For every replayed or live event, the daemon performs these steps:

1. Validate outer fields, sizes, algorithm, and server sequence.
2. Persist or find a pending inbox record keyed by `message_id`.
3. Decrypt with the exact additional data.
4. Decode the canonical CBOR envelope.
5. Validate message ID, slot, revision ID, content size, content hash, and
   tombstone invariants.
6. Apply the revision idempotently while preserving its origin metadata.
7. Delete the pending inbox record and advance the local server cursor in the
   same transaction.
8. Notify local adapters if the revision becomes the slot head.

An existing `(origin_device_id, origin_sequence)` or `revision_id` with exactly
the same immutable fields is a successful duplicate. Conflicting data under an
existing identity is a permanent protocol/security error and MUST NOT overwrite
the original revision.

A permanently invalid or undecryptable event MUST be durably quarantined with
a safe error category. To avoid blocking all later events forever, its pending
inbox row is deleted and the cursor advances only in the same transaction that
commits the quarantine record. The
daemon MUST surface a degraded synchronization status so the user knows that an
event was skipped. Error logs MUST not contain decrypted content or keys.

Remote application MUST NOT create an outbox item for the received revision.
That rule, plus identity deduplication, prevents feedback loops.

Retention-floor advancement and event processing share one cursor namespace.
After committing a floor, the next accepted event sequence MUST equal the new
cursor plus one. A later gap without a preceding validated `ready` or
`history_truncated` message remains a protocol error.

## 12. Storage responsibilities

This release establishes client storage schema version 5. Schema version 4 is
upgraded explicitly by rebuilding the `revisions` table without a foreign-key
constraint on `parent_revision_id`; all revision metadata and queue state are
preserved. Versions 1 through 3 are unsupported: the client MUST fail without
modifying, replacing, or importing such a database. An operator may archive or
remove those old database and blob directories before starting this release.

The baseline contains only a singleton typed `local_state` row, `slots`,
`revisions`, pending-only `outbox` and `inbox` queues, and
`quarantined_events`. It has no key/value metadata, device registry,
acknowledgement history, or audit-event placeholders. An acknowledged outbox
row is deleted; an applied or quarantined inbox row is deleted atomically with
the corresponding cursor advance.

Storage MUST provide:

- atomic local revision plus outbox insertion;
- retrieval of pending outbox items in deterministic order;
- one optional retry time and one cached encrypted envelope per pending outbox
  item;
- raw encrypted data only for pending inbox events;
- compact, durable safe-category records for quarantined events;
- a durable highest contiguous server cursor;
- an atomic retention-floor operation that advances the cursor without
  synthesizing inbox rows;
- durable truncation diagnostics including the most recent accepted floor and
  time, plus a cumulative count of cursor-floor advances;
- idempotent insertion of remote revisions without assigning a new local origin;
- deterministic slot-head conflict resolution; and
- garbage collection that treats every retained revision as a live root.

The trusted daemon adapter layer supplies `source_adapter`; locally created
revisions use values including `cli` and `plasma`. A remote import MUST preserve
the origin `source_adapter` from its encrypted envelope. Transport provenance
such as `pypasteserver` belongs on the inbox record and MUST NOT mutate the
immutable revision. `source_adapter` is diagnostic provenance; it is not the
primary loop-prevention mechanism.

The database and blob store MUST remain usable while the network worker is
blocked or reconnecting. No network operation may execute while holding the
SQLite mutex or an open write transaction.

The retention-floor operation MUST validate the advertised range, refuse to
move the cursor backward, and persist both the new cursor and truncation
diagnostics in one transaction. It MUST first account for any already-persisted
inbox rows at or below the target. A crash before commit leaves the old cursor;
a crash after commit resumes from the new one. Restart MUST therefore never
request or wait for an expired prefix again.

## 13. Conflict resolution and clocks

Every accepted local or received revision is retained in the client's local
history unless a separately specified local-retention policy removes it. Relay
expiration does not itself delete local revisions. The current slot head is
chosen deterministically using this ordering key:

```text
(hlc_physical, hlc_logical, origin_device_id, origin_sequence, revision_id)
```

The lexicographically greatest valid key wins. Tombstones use the same ordering
and receive no unconditional priority. This ensures every device presented with
the same revision set selects the same head. Devices that received different
retained subsets are not guaranteed to converge until a later revision for the
affected slot reaches all of them.

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

### 14.1 Plasma behavior with lossy replay

A retention-floor advance is not a clipboard revision. The Plasma adapter MUST
NOT clear, write, or re-import the desktop clipboard merely because history was
truncated. A retained remote revision that becomes the slot head follows the
normal post-commit notification path and is mirrored to Plasma when
`slot_to_desktop` is enabled.

If no retained event changes the mirrored slot, the existing local slot and
desktop value may remain stale. In particular, an expired tombstone cannot be
reconstructed and MUST NOT be guessed.

When sync and Plasma `desktop_to_slot` are both enabled, the adapter MUST defer
its one-time startup import until either:

- the initial sync replay reaches the `latest_sequence` advertised by `ready`;
  or
- the first connection attempt reaches a stable offline, authentication, or
  configuration failure state.

This prevents an arbitrary startup clipboard value from defeating a reachable
retained remote winner, while preserving offline-first behavior. Later desktop
changes are ordinary local mutations and may legitimately win by HLC order.
`desktop_to_slot` remains disabled by default.

## 15. Status and CLI behavior

Daemon status MUST report at least:

- sync configured/enabled state;
- connection state;
- authenticated or credential-error state;
- pending outbox count;
- oldest pending age;
- last successful connection and acknowledgement times;
- local processed server cursor;
- whether the most recent connection reported truncated history;
- the most recent accepted retention floor and time;
- cumulative count of durable retention-floor advances;
- last safe error category; and
- number of quarantined events.

It MUST NOT return pairing secrets, key material, ciphertext, or decrypted
previews.

History truncation is informational, not a degraded-health error and not an
action item for the end user.

`kclip copy`, `paste`, `list`, and `clear` retain their offline semantics.
Network delivery is asynchronous. A successful `copy` means the local revision
is durable, not that the server acknowledged it. An optional explicit sync-wait
command may be added later without changing normal clipboard commands.

## 16. Shutdown and startup

On startup, `kclipd` should:

1. Open schema-version-5 storage, explicitly migrate schema version 4, or
   create a fresh database; reject every other existing schema version without
   modifying it.
2. Start local IPC immediately.
3. Recover temporary blobs and incomplete inbox/outbox state.
4. Start adapters and the sync worker if enabled and validly configured.
5. Gate only Plasma's one-time `desktop_to_slot` import as specified in
   section 14.1; local IPC and all other adapter behavior remain available.

On shutdown, it should stop accepting new network work, finish or cancel
in-flight requests safely, persist retry state, close the WebSocket, and then
close storage. Aborted pushes remain pending with the same message IDs.

## 17. Clean-break deployment

The Rust client and PyPasteServer are deployed as a matching sync-v1 pair:

1. Install versions containing the required rolling-retention contract.
2. Provision a new Noise pairing through the server administrator.
3. Run `kclip sync setup` with the hidden setup code.
4. Choose first-device key generation or enter the existing account's recovery
   words when prompted.
5. Let setup enable sync, restart the daemon when managed by systemd, and verify
   authenticated connectivity.
6. Confirm bidirectional delivery with another device.

There is no import of Python-client configuration or bearer tokens, no legacy
endpoint, and no pre-retention `ready` shape. Existing unsupported clients must
be removed or independently archived rather than migrated through sync-v1.

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
- Disconnect after server commit deduplicates on retry while the event remains
  retained.
- A retry after the original event expires may receive a new server sequence
  without applying the immutable revision twice.
- Authentication and quota errors preserve pending revisions.
- Network work never blocks local copy/paste operations.

### 18.3 Inbox and replay

- Replay from zero and from a nonzero cursor.
- Truncated `ready` durably skips the expired prefix and begins at the retained
  floor.
- An empty retained buffer advances locally through `latest_sequence`.
- Active `history_truncated` advances atomically and continues on the same
  connection.
- Duplicate and older retention floors are idempotent.
- Missing fields, inconsistent booleans, invalid ranges, unexpected event gaps,
  and a cursor ahead of `latest_sequence` are rejected.
- Restart after accepting a retention floor resumes from the advanced cursor.
- A gap creates no fake inbox row, revision, HLC change, outbox item, or adapter
  notification.
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

- Missing server, invalid TLS, revoked pairing, wrong key, and offline startup.
- Bounded retry, queue, and memory behavior.
- Clean shutdown with pending and in-flight work.
- Secret-file ownership, permissions, regular-file, and symlink checks.
- The systemd sandbox permits required network families without weakening
  unrelated filesystem protections.
- Status reports truncation diagnostics without presenting them as a user
  repair task.
- Plasma does not react to a bare retention floor, does react to a retained
  winning revision, and defers its initial desktop import while reachable
  replay is incomplete.

### 18.6 End-to-end

Run two temporary daemons and one real PyPasteServer test instance:

1. Create a revision while device B is offline.
2. Restart device A and the server before acknowledgement.
3. Confirm the outbox retries without a duplicate server event.
4. Start device B and replay the revision.
5. Create a concurrent conflicting revision and confirm convergence.
6. Clear the slot and confirm both devices converge on the tombstone.
7. Leave device B offline until the events for a different slot and its
   tombstone expire from the relay.
8. Reconnect device B, confirm its cursor skips durably to the advertised floor,
   retained events apply, and the expired slot remains stale without prompting
   the user.
9. Advance retention past a connected slow consumer and confirm the active
   control message is handled without reconnecting.
10. Confirm the server database and logs contain no plaintext or slot names.

## 19. Acceptance criteria

The client portion is complete when:

1. Local clipboard operations remain available with the server offline.
2. Two Rust daemons synchronize text, binary data, slots, and tombstones.
3. Local changes survive daemon restart before upload acknowledgement.
4. Remote events survive crashes during inbox processing and apply once.
5. Concurrent revisions converge deterministically.
6. The server receives only opaque authenticated ciphertext and routing data.
7. No Python desktop daemon or Python CLI is required.
8. Initial and active retention gaps advance the durable cursor automatically,
   replay the available suffix, and survive restart.
9. Expired history never synthesizes clipboard state or triggers Plasma, and
   no backward-compatible wire path remains.

## 20. Implementation map

The clean-break rolling-retention implementation is divided as follows:

1. `kclip-sync` owns required `ready` and `history_truncated` decoding,
   invariant validation, local cursor advancement, and retained-suffix processing.
2. `kclip-storage` owns the durable server cursor, inbox recovery, truncation
   metadata, and atomic retention-floor advancement without placeholder rows.
3. `kclip-daemon` exposes the status diagnostics in section 15 and carries the
   internal initial-replay-complete/offline signal used by Plasma.
4. The Plasma adapter gates only its initial `desktop_to_slot` reconciliation;
   post-commit revision notifications drive `slot_to_desktop` updates.
5. `kclip-cli` owns guided setup, recovery-word display, disconnect behavior,
   and actionable synchronization status.
6. The shared wire fixture contains the required `ready` shape and active
   `history_truncated` message. Unit, restart, Plasma, and two-daemon tests cover
   the behaviors in section 18; no old-shape compatibility fixture is retained.
