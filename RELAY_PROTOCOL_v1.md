# Relay Protocol v1.0 Specification

**Status:** Draft  
**Version:** 1.0.0  
**Date:** January 31, 2026  
**Authors:** Relay Foundation

---

## Abstract

The Relay Protocol is a specification for privacy-preserving, identity-centric messaging. It defines how identities, handles, edges (contact surfaces), conversations, and messages are represented, secured, and exchanged across implementations.

Relay is not an application—it is a protocol. Applications implementing this specification are Relay-compatible.

**Core invariant:**
> Stable identity. Disposable reachability. Unified inbox. Honest security labeling.

---

## 1. Design Principles

### 1.1 Stable Identity
A Relay **Identity** is:
- Cryptographically owned (keypair-based)
- Persistent across time
- Independent from any platform, alias, or contact surface
- Never replaced due to spam, abuse, or edge compromise

### 1.2 Disposable Reachability (Edges)
**Edges** are contact surfaces through which messages arrive:
- Email aliases
- Contact links
- Platform bridges (Discord, Slack, SMS, etc.)
- Native (direct Relay-to-Relay)

Edges are:
- Cheap to create
- Instantly revocable
- Rotatable without affecting identity
- Individually configurable (policies, rate limits)

### 1.3 Unified Inbox
All message origins appear in a single inbox:
- Same data model for all origins
- Same UI treatment (with origin indicators)
- Consistent conversation threading

### 1.4 Honest Security Labeling
Every message carries an explicit security level:
- `e2ee` — End-to-end encrypted, server cannot read
- `gateway_secured` — Bridged through gateway, server may read

Security levels are never inferred, upgraded, or hidden. Users always know the true security posture.

### 1.5 Privacy by Design
- Metadata minimization is a protocol requirement
- Gateway behavior has defined minimums
- No tracking, analytics, or behavioral profiling

---

## 2. Identity Layer

### 2.1 Identity Object

```
Identity {
  identity_id:    string      # = pubkey_fingerprint (hex, 32 chars)
  public_key:     bytes       # Ed25519 public key
  home_server:    string      # e.g., "userelay.org"
  status:         enum        # active | locked | hidden
  created_at:     timestamp
  device_keys:    DeviceKey[] # optional, for multi-device
}
```

**Rules:**
- `identity_id` is the SHA-256 fingerprint of the public key (first 32 hex chars)
- `home_server` is the authoritative server for this identity
- Private keys NEVER leave the client unencrypted
- Identity is immutable except for status changes

### 2.2 Identity Status

| Status | Meaning |
|--------|---------|
| `active` | Normal operation, reachable via native and edges |
| `locked` | Frozen due to compromise or user action, no operations allowed |
| `hidden` | Dark mode — unreachable via native, only edges work |

### 2.3 Key Generation

**Required algorithms:**
- Signing: Ed25519
- Key exchange: X25519 (derived from Ed25519)
- Symmetric encryption: XSalsa20-Poly1305 (NaCl secretbox)
- Fingerprint: SHA-256, truncated to 32 hex characters

**Key derivation:**
```
# Identity keys (for authentication)
signing_keypair     = Ed25519.generate()
fingerprint         = SHA256(signing_keypair.public_key)[0:32].hex()

# Edge keys (for encryption) - RANDOM, not derived!
edge_keypair        = X25519.generate()  # Unique per edge
```

**IMPORTANT:** Edge X25519 keys are randomly generated, NOT derived from identity keys. This provides cryptographic unlinkability between edges.

### 2.4 Key Rotation

Identities MAY rotate keys while preserving handles and history.

**Rotation procedure:**
1. Generate new keypair
2. Create rotation proof: `sign(old_key, "rotate-to:" + new_pubkey + timestamp)`
3. Submit rotation to home server with both signatures
4. Server updates `identity_id` → new fingerprint
5. Old key is marked as `rotated`, new key is `active`

**Rotation proof object:**
```
KeyRotation {
  old_pubkey:       bytes
  new_pubkey:       bytes
  old_signature:    bytes     # old key signs the rotation
  new_signature:    bytes     # new key signs acceptance
  timestamp:        timestamp
}
```

### 2.5 Device Keys (Multi-Device)

Identities MAY have multiple device keys for multi-device support.

```
DeviceKey {
  device_id:        string    # unique per device
  device_pubkey:    bytes     # Ed25519 public key
  device_name:      string    # user-friendly name
  registered_at:    timestamp
  last_seen_at:     timestamp
  status:           enum      # active | revoked
  registration_sig: bytes     # master key signs device key
}
```

**Rules:**
- Device keys are signed by the master identity key
- Messages are encrypted to ALL active device keys
- Revoking a device key is instant and unilateral
- Master key should be stored securely, used rarely

### 2.6 Identity Recovery

**There is no server-side recovery mechanism.**

If a user loses:
- Their device AND
- Their backup passphrase

The identity is **permanently irrecoverable**. This is by design.

**Recommended backup methods:**
- Encrypted backup file (JSON with encrypted private key)
- Paper backup of passphrase
- Hardware security key (future)

---

## 3. Handle Layer

### 3.1 Handle Format

Handles follow the format: `&name@server`

```
Full form:    &taylor@userelay.org
Short form:   &taylor              # implies @{user's home_server}
```

**Validation rules:**
- 3-24 characters (excluding & and @server)
- Must start with a letter
- Lowercase alphanumeric and underscores only
- Server portion is a valid domain

### 3.2 Handle ↔ Identity Binding

```
Handle {
  name:           string      # without & prefix, lowercase
  server:         string      # e.g., "userelay.org"
  identity_id:    string      # owner's fingerprint
  is_primary:     boolean     # primary handle for this identity on this server
  status:         enum        # active | disabled | reserved
  claimed_at:     timestamp
}
```

**Rules:**
- One identity MAY have multiple handles (on same or different servers)
- One handle belongs to exactly one identity (at a time)
- Handles can be released and re-claimed by others
- Handles are scoped to their server (not globally unique)

### 3.3 Handle Lifecycle

| Operation | Description |
|-----------|-------------|
| Claim | Prove identity ownership via signature, register handle |
| Release | Voluntarily give up handle, can be claimed by others |
| Transfer | Release + claim in atomic operation (future) |

**Claim protocol:**
1. Client requests nonce from server
2. Client signs: `"relay-claim:" + handle + ":" + nonce`
3. Server verifies signature against provided pubkey
4. Server registers handle → identity binding

### 3.4 Handle Discoverability

Handles are discoverable by default via server lookup.

**Lookup endpoint:** `GET /v1/handle/resolve?handle={handle}`

**Privacy option:** Handles MAY be marked as `unlisted`:
- Not returned in directory searches
- Still resolvable if you know the exact handle
- Only contactable via edges

---

## 4. Edge Layer

### 4.1 Edge Object

```
Edge {
  edge_id:              string      # unique identifier (ULID)
  identity_id:          string      # owner's fingerprint
  type:                 EdgeType    # native | email | contact_link | ...
  address:              string      # type-specific address
  label:                string?     # user-friendly name
  status:               enum        # active | disabled | rotated
  security_level:       enum        # e2ee | gateway_secured
  created_at:           timestamp
  disabled_at:          timestamp?
  rotated_from_edge_id: string?     # if this is a rotation
  policy:               EdgePolicy
  message_count:        integer
  last_activity_at:     timestamp?
}
```

### 4.2 Edge Types

Core types (MUST be supported):

| Type | Address Format | Security Level | Description |
|------|---------------|----------------|-------------|
| `native` | `{identity_id}` | `e2ee` | Direct Relay-to-Relay |
| `email` | `alias@domain` | `gateway_secured` | Email alias |
| `contact_link` | `{slug}` | `gateway_secured`* | Public contact form |

Extended types (MAY be supported):

| Type | Description |
|------|-------------|
| `discord` | Discord bridge |
| `slack` | Slack bridge |
| `sms` | SMS bridge |
| `github` | GitHub notifications bridge |
| `matrix` | Matrix protocol bridge |
| `custom` | Implementation-defined |

*Contact links MAY upgrade to `e2ee` if visitor uses Relay client.

**Custom types:** Implementations MAY define custom edge types using the format `x-{vendor}-{type}` (e.g., `x-acme-webhook`).

### 4.3 Edge Lifecycle

| Operation | Description |
|-----------|-------------|
| Create | Generate new edge with unique address |
| Disable | Stop accepting messages, preserve history |
| Rotate | Disable old → create new, link via `rotated_from_edge_id` |

**Disable behavior:**
- Immediate effect (no grace period)
- All history preserved
- Conversations show "edge disabled" indicator
- Cannot be re-enabled (create new instead)

**Rotate behavior:**
- Old edge disabled
- New edge created with same type
- Existing conversations visually transfer to new edge
- `rotated_from_edge_id` links the chain

### 4.4 Edge Policy

```
EdgePolicy {
  rate_limit:           integer?    # messages per hour
  first_contact: {
    mode:               enum        # open | pow | allowlist | mutual
    pow_difficulty:     integer?    # if mode = pow
    allowlist:          string[]?   # if mode = allowlist
  }
  denylist:             string[]?   # blocked senders
}
```

### 4.5 Native Edge

Every identity has an implicit native edge:
- Created automatically with identity
- Cannot be deleted (but CAN be disabled if status = hidden)
- Security level is always `e2ee`
- Address is the `identity_id`

When identity status = `hidden`:
- Native edge rejects incoming messages
- Other edges continue to function
- Useful for "dark mode" operation

### 4.6 Edge-to-Edge Encryption

**IMPORTANT:** As of v1.1, all messaging uses edge-to-edge encryption. Each edge has its own unique X25519 keypair.

```
Edge Keypair {
  edge_id:              string      # unique identifier (ULID)
  x25519_public_key:    bytes       # unique X25519 public key for this edge
  x25519_secret_key:    bytes       # stored encrypted on client only
}
```

**Security Model:**
- Each edge generates a **random** X25519 keypair (not derived from identity)
- Edges owned by the same identity have **different** public keys
- This provides **cryptographic unlinkability** between edges
- External observers cannot determine if two edges belong to the same identity

**Edge Resolution:**
- `POST /v1/edge/resolve` returns edge encryption key (no identity data)
- Response contains ONLY: `edgeId`, `x25519PublicKey`, `displayName`, `type`, `status`
- Identity public key is **never** included in public API responses

**Messaging Flow:**
```
Sender Edge                                    Recipient Edge
    │                                               │
    │ 1. Resolve recipient edge                     │
    │    POST /v1/edge/resolve                      │
    │    → { edgeId, x25519PublicKey }              │
    │                                               │
    │ 2. Encrypt to recipient's x25519 key          │
    │    (Double Ratchet or static X25519)          │
    │                                               │
    │ 3. POST /v1/messages                          │
    │    { edge_id: sender, payload: encrypted }    │
    │─────────────────────────────────────────────▶│
    │                                               │
```

### 4.7 Bridge Edges

Bridges (email gateway, Discord bot, etc.) operate as special edges.

```
Bridge Edge {
  edge_id:              "RELAY_EMAIL_BRIDGE"  # well-known ID
  type:                 "bridge"
  address:              "email"               # bridge identifier
  x25519_public_key:    bytes                 # bridge's encryption key
}
```

**Bridge Resolution:**
- Bridges are resolved via the same `POST /v1/edge/resolve` endpoint
- Request: `{ type: "bridge", address: "email" }`
- Response: `{ edgeId, x25519PublicKey, ... }`

**Security Level:**
- Bridge communications are `gateway_secured`
- Bridge sees plaintext for protocol translation (e.g., email ↔ Relay)
- Content is encrypted between client and bridge
- Bridge encrypts/decrypts at the boundary

---

## 5. Conversation & Message Layer

### 5.1 Conversation Object

```
Conversation {
  conversation_id:      string      # unique identifier (ULID)
  identity_id:          string      # owner's fingerprint
  edge_id:              string?     # edge this came through (null for native)
  origin:               EdgeType    # native | email | discord | ...
  security_level:       enum        # e2ee | gateway_secured | mixed
  channel_label:        string?     # "Relayed via Email", etc.
  participants:         Participant[]
  created_at:           timestamp
  last_activity_at:     timestamp
}
```

**Security level rules:**
- If all messages are `e2ee` → conversation is `e2ee`
- If all messages are `gateway_secured` → conversation is `gateway_secured`
- If mixed → conversation is `mixed`

### 5.2 Participant Object

```
Participant {
  identity_id:          string?     # if Relay user
  external_id:          string?     # if external (hashed identifier)
  display_name:         string?
  is_owner:             boolean
  joined_at:            timestamp
}
```

### 5.3 Message Envelope

Every message conforms to this envelope:

```
Message {
  # Required fields
  message_id:           string      # unique identifier (ULID)
  protocol_version:     string      # e.g., "1.0"
  conversation_id:      string
  edge_id:              string?     # edge message arrived through
  origin:               EdgeType
  security_level:       enum        # e2ee | gateway_secured
  created_at:           timestamp
  
  # Sender identification (one of)
  sender_identity_id:   string?     # if Relay user
  sender_external_id:   string?     # if external (hashed)
  
  # Payload (varies by security_level)
  payload:              Payload
  
  # Integrity
  signature:            bytes?      # required for e2ee
}
```

### 5.4 Payload Structure

```
Payload {
  content_type:         string      # MIME-like type
  data:                 varies      # depends on content_type and security_level
}
```

**For `e2ee` messages:**
```
Payload {
  content_type:         string
  ciphertext:           bytes       # encrypted content
  nonce:                bytes       # encryption nonce
  ephemeral_pubkey:     bytes       # sender's ephemeral key
}
```

**For `gateway_secured` messages:**
```
Payload {
  content_type:         string
  plaintext:            string      # readable by gateway
}
```

### 5.5 Content Type Registry

Core types:

| Content Type | Description |
|--------------|-------------|
| `text/plain` | Plain text message |
| `text/markdown` | Markdown-formatted text |
| `image/png`, `image/jpeg`, etc. | Image attachment |
| `application/octet-stream` | Binary file |
| `relay/reaction` | Reaction to another message |
| `relay/edit` | Edit of a previous message |
| `relay/delete` | Deletion marker |

Extended types follow standard MIME conventions.

### 5.6 Signature Requirements

**For `e2ee` messages:**
- Signature MUST cover: `message_id + conversation_id + ciphertext + nonce + created_at`
- Signature algorithm: Ed25519
- Recipient MUST verify signature before decryption

**For `gateway_secured` messages:**
- Gateway MAY sign to attest delivery
- Signature is optional but recommended

---

## 6. Transport Layer

### 6.1 Client ↔ Server Protocol

**Base URL:** `https://{server}/v1/`

**Authentication:**
- Challenge-response with identity signature
- Session tokens for subsequent requests
- Token format: JWT with `identity_id` claim

**Required endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/identity/register` | Register new identity |
| GET | `/identity/:id` | Get identity info |
| POST | `/auth/nonce` | Request auth nonce |
| POST | `/auth/verify` | Verify signature, get token |
| POST | `/handle/claim` | Claim a handle |
| GET | `/handle/resolve` | Resolve handle to identity |
| DELETE | `/handle/:name` | Release a handle |
| POST | `/edge` | Create new edge |
| GET | `/edges` | List user's edges |
| DELETE | `/edge/:id` | Disable edge |
| GET | `/conversations` | List conversations |
| GET | `/conversations/:id/messages` | Get messages |
| POST | `/conversations/:id/messages` | Send message |

### 6.2 Server ↔ Server Protocol (Federation)

**Discovery:**
- Well-known endpoint: `https://{server}/.well-known/relay-server`
- Returns: server pubkey, protocol version, federation endpoints

**Message routing:**
```
Alice@server-a.com → Server A → Server B → Bob@server-b.com
```

**Cross-server verification:**
- All identity claims verified via signature
- Never trust server attestation alone
- Recipient server fetches sender's pubkey from sender's home server

**Federation endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/federation/deliver` | Deliver message to local user |
| GET | `/federation/identity/:id` | Fetch identity info |
| GET | `/federation/key/:id` | Fetch public key |

### 6.3 Encryption Requirements

**In transit:**
- All connections MUST use TLS 1.3+
- Certificate validation MUST be enforced

**At rest (server):**
- `e2ee` content: Server stores ciphertext only
- `gateway_secured` content: Server SHOULD encrypt at rest
- Metadata: Server SHOULD minimize and encrypt

**At rest (client):**
- Private keys MUST be encrypted with user passphrase
- Message cache MAY be encrypted

---

## 7. Gateway Requirements

Servers acting as gateways for bridged content MUST adhere to these minimums.

### 7.1 Minimum Behavior

| Requirement | Description |
|-------------|-------------|
| No plaintext logging | Gateway MUST NOT log message content |
| Prompt delivery | Gateway MUST attempt delivery within reasonable time |
| Failure notification | Gateway SHOULD notify sender of delivery failures |
| No modification | Gateway MUST NOT modify message content |
| No injection | Gateway MUST NOT inject content into messages |

### 7.2 Metadata Handling

| Metadata | Handling |
|----------|----------|
| Sender identity | MAY be logged for abuse prevention |
| Recipient identity | MAY be logged for routing |
| Timestamps | MAY be logged |
| Message size | SHOULD NOT be logged |
| Content | MUST NOT be logged |

### 7.3 Retention Policies

| Data | Maximum Retention |
|------|-------------------|
| Delivery logs | 30 days |
| Failed message queue | 7 days |
| Plaintext content | 0 (never stored beyond delivery) |
| Encrypted content | User-controlled (or until deleted) |

---

## 8. Versioning

### 8.1 Protocol Version

Every message includes `protocol_version` field.

Format: `MAJOR.MINOR` (e.g., "1.0")

| Change Type | Version Bump |
|-------------|--------------|
| Breaking change | MAJOR |
| New optional field | MINOR |
| Clarification | MINOR |

### 8.2 Compatibility Rules

**Forward compatibility:**
- Clients MUST ignore unknown fields
- Clients MUST NOT reject messages with unknown fields

**Backward compatibility:**
- Servers SHOULD support previous MAJOR version for 12 months
- Deprecation MUST be announced 6 months in advance

### 8.3 Extension Mechanism

Custom extensions use the `x-` prefix:
- Custom edge types: `x-vendor-type`
- Custom content types: `x-vendor/type`
- Custom message fields: `x_vendor_field`

---

## Appendix A: Cryptographic Primitives

| Purpose | Algorithm | Library Reference |
|---------|-----------|-------------------|
| Signing | Ed25519 | NaCl `sign` |
| Key exchange | X25519 | NaCl `box` |
| Symmetric encryption | XSalsa20-Poly1305 | NaCl `secretbox` |
| Hashing | SHA-256 | Standard |
| Key derivation | Argon2id | For passphrase → key |
| Random | CSPRNG | Platform-provided |

## Appendix B: Security Level Labels

| Level | Badge | Tooltip |
|-------|-------|---------|
| `e2ee` | 🔒 E2EE | "End-to-end encrypted. Only you and the recipient can read this." |
| `gateway_secured` | 🔁 Relayed | "Relayed via [origin]. Protected in transit, but bridged through gateway." |
| `mixed` | ⚠️ Mixed | "This conversation contains messages with different security levels." |

## Appendix C: Canonical Edge Types

| Type | Origin | Default Security |
|------|--------|-----------------|
| `native` | Relay | `e2ee` |
| `email` | Email | `gateway_secured` |
| `contact_link` | Web form | `gateway_secured` |
| `discord` | Discord | `gateway_secured` |
| `slack` | Slack | `gateway_secured` |
| `sms` | SMS | `gateway_secured` |
| `github` | GitHub | `gateway_secured` |
| `matrix` | Matrix | `gateway_secured` |

## Appendix D: Reference Implementation

The reference implementation is maintained at:
- **Extension:** `userelay.org` Chrome extension
- **Server:** `api.userelay.org`
- **Source:** [TBD - GitHub repository]

---

## Document History

| Version | Date | Changes |
|---------|------|---------|| 1.1.0 | 2026-02-02 | Edge-to-edge encryption model, unique edge keypairs, bridge edge pattern || 1.0.0 | 2026-01-31 | Initial specification |

---

**End of Specification**
