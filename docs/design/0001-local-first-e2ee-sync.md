# Local-First E2EE Sync — Design Document

Nov 2, 2026 · @Marc

## Overview and goals

We build a local-first system where clients hold all data and share it end-to-end encrypted within an organization, through a relay server that stores nothing. Clients sync from each other; the server only routes messages between clients that are online.

**Requirements**

- Multiple clients (phones, desktops, optional always-on devices) per organization.
- Only clients hold data. Each client keeps a full local store of its organization's data.
- All messages are end-to-end encrypted. The server never has keys.
- The server routes messages only. It persists nothing, not even encrypted data.
- New clients join an organization by invitation.
- Any kind of data can be shared: the payload is opaque bytes with a type tag.
- Data can be edited without locks (optimistic concurrency).
- Every data object has its own change history.
- Returning or new clients catch up by syncing from another online client.
- A permission layer controls who may read and who may change which data.

**Non-goals**

- Hiding metadata from the server (who is in which organization, when, how much).
- Recovering data from clients that have already received it after their access is removed.
- Server-side search, backup or processing of content.

## Architecture

The system has three parts: clients that hold all data, a relay that forwards encrypted messages to online devices and stores nothing, and an optional always-on client per organization.

&#91;embedded content: system architecture · clients, relay, push\]

Every client is equal in the protocol; the always-on client is just a member that rarely goes offline.

- **Clients** (phones, desktops, web): Hold the full data of each organization they belong to, create and sign changes, encrypt and decrypt, validate incoming changes, and answer sync requests from peers.
- **Relay server**: Authenticates devices, keeps an in-memory table of who is online in which organization, and forwards opaque encrypted messages. It writes nothing to disk.
- **Always-on client**: A headless client (desktop app, home server, Raspberry Pi) run by the organization. It holds all data and is the preferred sync partner, so returning devices can almost always catch up.
- **Push services**: The relay can send empty pushes to wake phones; no content goes through them.

## Identity and encryption

Each organization is one MLS group (RFC 9420); each device has its own signing key, and that key is its identity everywhere in the system.

**Keys**

- **Device key**: An Ed25519 key pair created on first launch. It signs every change and every MLS operation. Its public key is the device ID.
- **User identity**: A user may own several devices. The policy object (see Permissions) maps device keys to users and users to roles.
- **Organization root key**: The creator's device key is the first admin and the root of trust. Every member learns it through the invitation.

**MLS group per organization**

- MLS handles group key agreement, encryption, forward secrecy and post-compromise security.
- Group changes (add, remove, key update) are *commits*. Each commit moves the group to a new *epoch*, and every member must apply all commits in order.
- Every client stores the recent commit log locally, so returning clients can fetch commits they missed from a peer (see Sync protocol).
- Members rotate their own keys periodically (MLS update), for example weekly or on app start after a long pause.
- Separate MLS groups are used for data with restricted read access (see Permissions).

**Encryption layers**

1. A change is created and signed by the device key.
2. The signed change is encrypted as an MLS application message for the organization (or subgroup).
3. The relay sees only the encrypted message plus routing information.

## Data model

Every object is a chain of signed, hash-linked changes, like git commits; its current state is computed from that chain, and the chain is its history.

**Change envelope**

| Field | Purpose |
| --- | --- |
| `change_id` | Hash of the envelope contents |
| `object_id` | Random ID of the object, fixed at creation |
| `object_type` | Type tag, e.g. `note`, `config`, `file-ref` |
| `parents` | Change IDs this change builds on (empty for creation) |
| `author` | Device public key |
| `timestamp` | Author's wall clock, informational only |
| `payload` | Opaque bytes: a CRDT change or an application-defined operation |
| `signature` | Device signature over all fields above |

**Concurrency**

Edits never wait for a lock. Each change names the version it was based on (`parents`), so concurrent edits are detected when two changes share a parent.

- **Default: CRDT payloads (Automerge).** Concurrent edits merge automatically and deterministically on every client. Automerge also keeps the full per-object history.
- **Alternative for simple types: detect and resolve.** When the history forks, apply a per-type rule: last writer wins by (timestamp, author), field-level merge, or mark the object as conflicted and ask the user.
- Classic reject-and-retry optimistic concurrency is not used, because no authority sees all changes in order while clients are offline.

**Local storage (per client)**

- SQLite database with two main tables: `changes` (append-only, every envelope received and validated) and `objects` (materialized current state per object, rebuildable from `changes`).
- Indexes by `object_id`, `author` and arrival order, for sync and history views.
- Rejected changes (see Permissions) are not stored, or stored in a separate quarantine table for debugging.

**History**

An object's history is the graph of its changes, with author, time and content of each step. Restoring an old version is a new change that sets the state back, so history is never rewritten.

## Relay server protocol

The relay keeps only in-memory routing state and forwards encrypted messages to devices that are online at that moment; nothing is written to disk.

**State (RAM only)**

- Connected devices: device ID → open connection (WebSocket or QUIC).
- Organization routing: organization ID → set of currently connected device IDs, rebuilt as devices connect and announce their organizations.
- Optional short buffer: messages for a device that disconnected in the last few seconds (for example 30 s), to bridge cell-tower handovers. Dropped after the timeout.

**Connection**

1. Device connects and proves it owns its device key by signing a server challenge.
2. Device announces the organization IDs it belongs to, each with a membership proof the relay can check without decrypting anything (for example a token signed by the organization root key).
3. The relay adds the device to the routing table for those organizations.

**Message types**

| Type | Routing | Purpose |
| --- | --- | --- |
| `broadcast` | All online devices in the organization except the sender | New changes, MLS commits |
| `direct` | One device ID | Sync replies, Welcome messages, bulk transfer |
| `sync-request` | One online device chosen by the relay | Catch-up and joining |
| `presence` | Organization members | Who is online, used to pick sync partners |
| `invite-claim` | The inviting device, by invite token | Joining (see Invitations) |

All payloads are opaque to the relay. Messages to offline devices are dropped, and the sender is told which devices received them.

**Push notifications**

The relay may send an empty push (APNs/FCM) to a member's phone to ask it to come online and sync. Push tokens are registered in RAM while the device is connected, so a relay restart forgets them until devices reconnect. Whether that is acceptable is an open question.

**Abuse limits**

Rate limits per device and per organization, and a maximum message size (e.g. 1 MB; larger data goes through Large files).

## Sync protocol

A returning client and a new client use the same path: ask one online peer, compare what each has, and exchange only the missing changes.

**Live updates**

While online, a client broadcasts each new change to its organization. Receivers validate it and store it. Anything missed while offline is recovered by catch-up.

**Catch-up**

1. Client connects and sends `sync-request` to the organization.
2. The relay forwards it to one online member, preferring always-on clients.
3. **MLS first**: The client sends its current epoch. The peer returns all commits since that epoch from its commit log. The client applies them in order.
4. **Data next**: Both sides reconcile their sets of change IDs, using the Automerge sync protocol or range-based set reconciliation (e.g. Negentropy) for non-Automerge data. Only missing changes are sent, in both directions.
5. Every received change is validated (signature, hash, permissions) before it is stored.
6. The client sends its own unsent offline changes to the peer and broadcasts them.

**Fallbacks**

- **Too far behind on MLS**: If the peer no longer has the needed commits, or the client was removed and re-added, an online member re-adds the client with a fresh MLS Welcome. Data sync then continues as normal.
- **No peer online**: The client keeps working locally and retries when presence shows another member online.
- **Withholding peer**: A peer cannot forge or alter changes, only omit them. Optionally sync with a second peer and merge.

**Joining**

A new device runs the same catch-up starting from an empty store. MLS prevents new members from decrypting old messages, so the full history arrives through this peer transfer.

**Large syncs**

Initial syncs can be large. Send them in chunks with resumable progress, and prefer a direct peer-to-peer connection (WebRTC or Iroh) to keep load off the relay. Through the relay, chunks are streamed and never stored.

## Invitations and onboarding

An invitation is a one-time link or QR code from an admin; joining requires the inviting device (or another admin device) to be online, because the relay stores nothing.

1. **Create invite**: An admin device creates an invite containing the organization ID, the root public key, the relay address, a random one-time secret and an expiry. It records the invite and its intended role in the policy object.
2. **Share invite**: As a link or QR code, through any channel. In person by QR is the safest.
3. **Claim**: The new device creates its device key and an MLS KeyPackage, then sends `invite-claim` with a proof derived from the secret. The relay routes it to online admin devices of that organization.
4. **Verify**: The admin device checks the proof and expiry. Optionally both screens show a short code to compare, which stops a malicious relay from substituting its own device.
5. **Add**: The admin device adds the new device to the MLS group (commit) and records it in the policy object with its role. The new device receives an MLS Welcome.
6. **Sync**: The new device runs catch-up from an empty store (see Sync protocol).

**Adding another device of an existing user**

Same flow, but the user's existing device approves the new one by QR scan. It is then linked to the same user and role.

**Removing a device or user**

An admin removes the device from the MLS group (commit with key rotation) and revokes it in the policy object. Future changes signed by that key are rejected. Data it already received cannot be taken back.

## Permissions

Write access is enforced by signatures that every client checks; read access is enforced by who holds the decryption keys. A client can always change its own copy, but honest clients reject any change its author was not allowed to make, so it never spreads.

**Policy object**

A special object, created by the root key, that every client syncs and validates like any other object. Only admins may change it. It contains:

- Members: device key → user; user → role.
- Roles, e.g. `admin`, `editor`, `viewer`.
- Rules per object type, e.g. `config`: write = `admin`; `note`: write = `editor`.
- Optional per-object rules: an `owners` or `writers` list inside the object itself.
- Revocations, with the change ID at which they take effect.

**Validation on every incoming change (live or during sync)**

1. Signature valid and author key known?
2. Under the policy *as of this change's parents*, was the author allowed to make it?
3. Valid → store, apply, pass on in sync. Invalid → reject, do not store, do not pass on.

With Automerge, validation runs before the change is handed to the merge; the CRDT itself knows nothing about permissions.

**Read-only configuration**

Configuration is a set of objects of type `config` whose write rule is `admin`. Everyone can read them; only admin-signed changes are accepted. A separate "configuration organization" is optional: it is useful for organizing data, but the signature check is what protects it, since every member who can read an MLS group can also send into it.

**Restricted read access**

Data that only some members may read lives in a separate MLS group (e.g. `finance`) with only those members. Revoking read access removes the member from that group, which rotates its keys. Objects reference their group so clients know where they belong.

**Concurrent permission changes**

Without a central authority, an admin can revoke Bob while Bob edits offline, or two admins can remove each other. Every client must apply the same deterministic rules:

- **Revocation wins**: Changes by a revoked author that are not causally before the revocation are rejected.
- **Dependent changes**: Changes by others that build only on rejected changes are rebased: their content is reapplied on the last valid state, or the object is marked conflicted.
- **Admin conflicts**: The admin with seniority (added earlier) wins. The root key always wins.
- **Practical simplification**: Keep admin operations rare and perform them from one or a few always-on admin devices.

This is the least-solved area of the design. Study Matrix's state resolution and Ink & Switch's Keyhive before implementing.

**Limits**

A modified client can leak anything it is allowed to read. Permissions control what spreads, not what a member already has.

## Large files

Files travel outside MLS as encrypted blobs between clients; only a small reference object goes through the normal change flow.

1. Encrypt the file with a random key (e.g. XChaCha20-Poly1305), split into chunks (e.g. 256 KB), hash each chunk.
2. Create a `file-ref` object with the file key, chunk hashes, size and MIME type, and send it as a normal change.
3. Other clients fetch chunks from any peer that has them, directly peer-to-peer where possible, otherwise streamed through the relay without storing.
4. Each chunk is verified against its hash, so any peer can serve it.
5. Clients may fetch files lazily (on open) or eagerly, configurable per device; phones may keep only metadata and fetch on demand.

## Limitations and risks

| Risk | Consequence | Mitigation |
| --- | --- | --- |
| No other member online | Returning clients cannot sync | Always-on client per organization |
| Edits made offline, then device leaves quickly | Changes stranded on one device | Sync before going idle; always-on client |
| Phones sleep in background | Phones are unreliable sync partners | Push wake-ups; prefer desktops and always-on clients |
| All devices lose data | Organization data is gone | Encrypted backups readable only by members (e.g. always-on client exports) |
| Relay sees metadata | Membership, timing and sizes visible to operator | Accepted non-goal; padding later if needed |
| Malicious relay | Can drop or delay messages, try to insert fake devices | Signatures, invite short-code verification |
| Concurrent permission changes | Diverging views if rules are not deterministic | Fixed resolution rules; rare admin operations |
| Removed member | Keeps data received earlier | Accepted; rotate keys for future data |
| History grows forever | Storage and sync cost rises | Compaction: snapshots plus pruning of old changes, agreed policy per type |

## Technology stack and implementation phases

A shared Rust core used by all clients keeps protocol logic identical everywhere, which matters because every client must validate and merge the same way.

| Layer | Choice | Notes |
| --- | --- | --- |
| Core | Rust library | Called from Swift/Kotlin via UniFFI, from desktop/web via native or WASM |
| Group encryption | OpenMLS | RFC 9420 implementation |
| Signatures | Ed25519 | Device keys |
| Data and history | Automerge | CRDT merge, sync protocol, change history |
| Set reconciliation | Negentropy | For non-Automerge data, if any |
| Local storage | SQLite | Changes plus materialized objects |
| Relay transport | WebSocket (QUIC later) | Stateless, RAM-only server |
| Peer-to-peer transfer | Iroh or WebRTC | Large syncs and files |
| Push | APNs / FCM | Empty wake-up pushes only |

**Phases**

1. **Local core**: Change envelope, signing, SQLite store, Automerge objects, history view. One device, no network.
2. **Relay and live sync**: RAM-only relay, device authentication, broadcast between online devices, without encryption.
3. **Catch-up sync**: `sync-request`, reconciliation, joining from empty.
4. **Encryption**: OpenMLS groups, commit log on clients, catch-up of missed commits, re-add fallback.
5. **Invitations**: Invite links/QR, claim flow, short-code verification, device removal.
6. **Permissions**: Policy object, validation on every change, read-restricted subgroups, conflict rules.
7. **Files and always-on client**: Encrypted blobs, peer-to-peer transfer, headless always-on client, push wake-ups.
8. **Hardening**: History compaction, encrypted backups, rate limits, security review.

## Open questions

- [x] Are all data types Automerge documents, or do some use detect-and-resolve? Automerge by default, pluggable per type: [ADR 0003](../adr/0003-merge-automerge-default-pluggable.md)
- [ ] Is a 30-second RAM buffer on the relay acceptable under "no persistence"?
- [ ] Are push tokens allowed to persist on the relay, or re-registered on every connect?
- [ ] Which exact rule applies to changes concurrent with a revocation?
- [ ] Is an always-on client required per organization, or optional?
- [ ] How is a lost root key recovered (multiple root admins, recovery key)?
- [ ] Compaction policy: how much history is kept per object type?
- [ ] Should membership proofs to the relay hide which device is which (privacy vs. simplicity)?
