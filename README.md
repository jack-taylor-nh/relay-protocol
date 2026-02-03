# Relay Protocol Specification v1.0

<p align="center">
  <strong>Privacy-Preserving, Identity-Centric Messaging</strong><br/>
  <em>Stable identity. Disposable reachability. Zero-knowledge architecture.</em>
</p>

---

**Status:** Draft  
**Version:** 1.1.0  
**Date:** February 2, 2026  
**Authors:** Relay Foundation  
**License:** MIT

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Philosophy](#2-design-philosophy)
3. [Architecture Overview](#3-architecture-overview)
4. [Identity Layer](#4-identity-layer)
5. [Edge Layer](#5-edge-layer)
6. [Handle Layer](#6-handle-layer)
7. [Messaging Layer](#7-messaging-layer)
8. [Cryptographic Specification](#8-cryptographic-specification)
9. [Transport & API](#9-transport--api)
10. [Bridge Architecture](#10-bridge-architecture)
11. [Security Model & Threat Analysis](#11-security-model--threat-analysis)
12. [Privacy Guarantees](#12-privacy-guarantees)
13. [Implementation Requirements](#13-implementation-requirements)
14. [Future Roadmap](#14-future-roadmap)
15. [Appendices](#appendices)

---

## 1. Introduction

### 1.1 What is Relay?

Relay is an **open protocol** for privacy-preserving, identity-centric messaging. It is not an application—it is a specification that any application can implement to achieve interoperability with the Relay ecosystem.

Traditional messaging systems conflate your identity with your reachability. Your phone number, email address, or username is both who you are AND how people contact you. This creates fundamental privacy problems:

- **Spam forces identity changes** — When your email gets flooded, you must abandon it
- **Platform lock-in** — Your contacts are held hostage by the platform
- **No compartmentalization** — Everyone reaches you the same way
- **Metadata exposure** — Service providers see your entire social graph

Relay solves these problems with a simple architectural insight:

> **Your identity should be permanent. Your contact points should be disposable.**

### 1.2 Core Innovation: The Edge Model

Relay introduces **Edges**—disposable contact surfaces that route messages to a stable identity:

```
┌─────────────────────────────────────────────────────────────┐
│                      YOUR IDENTITY                          │
│              (Ed25519 keypair, permanent)                   │
└─────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │  @taylor │        │ Email    │        │ Contact  │
   │ (handle) │        │ Edge     │        │ Link     │
   │  native  │        │xyz@rly...│        │ /c/abc   │
   └──────────┘        └──────────┘        └──────────┘
        │                    │                    │
        ▼                    ▼                    ▼
   ┌─────────────────────────────────────────────────────┐
   │              UNIFIED INBOX                          │
   │         All messages, one view                      │
   └─────────────────────────────────────────────────────┘
```

**Think of it like P.O. Boxes:**
- Your **Identity** is your permanent home address (never shared publicly)
- Your **Edges** are P.O. Boxes you rent around town (publicly shareable)
- If a P.O. Box gets spam, you close it and open a new one
- Your home address (identity) never changes

### 1.3 Design Goals

| Goal | Description |
|------|-------------|
| **Zero-Knowledge** | Servers cannot decrypt user data, even with full database access |
| **Cryptographic Unlinkability** | Edges cannot be correlated to identities by external observers |
| **Forward Secrecy** | Compromise of current keys doesn't expose past messages |
| **Honest Security Labeling** | Users always know the true security level of their communications |
| **Platform Bridging** | Receive messages from email, SMS, Discord, etc. in one inbox |
| **User Sovereignty** | Users control their keys, their data, and their identity |

### 1.4 Protocol Invariant

Every design decision in Relay serves this invariant:

> **Stable identity. Disposable reachability. Unified inbox. Honest security labeling.**

---

## 2. Design Philosophy

### 2.1 Privacy by Architecture

Relay doesn't rely on server operators being trustworthy. Instead, the architecture **mathematically prevents** servers from accessing sensitive data.

**Traditional model:** "Please don't read my messages" (policy-based)  
**Relay model:** "You cannot read my messages" (cryptography-based)

This is achieved through:
- **Client-side encryption** — All encryption/decryption happens on user devices
- **Zero-knowledge storage** — Servers store only ciphertext
- **Architectural isolation** — Even database administrators cannot correlate identities to edges

### 2.2 Defense in Depth

Relay assumes every component can fail:

| Layer | Protection |
|-------|------------|
| **Network** | TLS 1.3+ encryption (assume network is hostile) |
| **Server** | Zero-knowledge (assume server is compromised) |
| **Database** | Ciphertext only (assume database is breached) |
| **Transport** | Signatures (assume man-in-the-middle attacks) |
| **Storage** | Passphrase encryption (assume device is stolen) |

### 2.3 Security Level Transparency

Relay never hides or inflates security levels. Every message carries an explicit label:

| Level | Badge | Meaning |
|-------|-------|---------|
| `e2ee` | 🔒 | End-to-end encrypted. Only sender and recipient can read. |
| `gateway_secured` | 🔁 | Bridged through gateway. Protected in transit, but gateway processes content. |

Users always know exactly what protections apply to their communications.

### 2.4 Metadata Minimization

Even encrypted messaging leaks metadata (who talks to whom, when, how often). Relay actively minimizes metadata:

| Metadata | Relay's Approach |
|----------|------------------|
| **IP addresses** | Never logged |
| **Timestamps** | Rounded to 5-minute intervals |
| **Social graph** | Architecturally fragmented (edges not linkable to identities) |
| **Message sizes** | Future: padding for normalization |
| **Communication patterns** | Future: mixnet integration |

---

## 3. Architecture Overview

### 3.1 System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                               │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │  Extension  │  │  Mobile App │  │   Web App   │                  │
│  │  (Chrome)   │  │  (Future)   │  │  (Future)   │                  │
│  └─────────────┘  └─────────────┘  └─────────────┘                  │
│         │                │                │                          │
│         └────────────────┼────────────────┘                          │
│                          ▼                                           │
│              ┌───────────────────────┐                              │
│              │     Core Library      │                              │
│              │  • Crypto (NaCl)      │                              │
│              │  • Double Ratchet     │                              │
│              │  • Key Management     │                              │
│              └───────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ TLS 1.3+
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           SERVER LAYER                               │
├──────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                     Home Server                              │    │
│  │  • Identity registration           • Message routing         │    │
│  │  • Edge management                 • Encrypted blob storage  │    │
│  │  • Handle resolution               • Rate limiting           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│         │                                                            │
│         │                                                            │
│  ┌──────┴──────────────────────────────────────────────────────┐    │
│  │                     Bridge Workers                           │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │    │
│  │  │  Email  │  │ Discord │  │  Slack  │  │   SMS   │        │    │
│  │  │ Bridge  │  │ Bridge  │  │ Bridge  │  │ Bridge  │        │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL SYSTEMS                              │
│        Email Servers, Discord, Slack, Telegram, SMS Carriers         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow Summary

1. **User creates Identity** → Generates Ed25519 keypair (never leaves device)
2. **User creates Edges** → Each edge gets unique X25519 keypair (unlinkable)
3. **Sender resolves Edge** → Gets recipient's edge public key (no identity info)
4. **Sender encrypts** → Client-side encryption with Double Ratchet
5. **Server stores** → Ciphertext only (cannot decrypt)
6. **Recipient fetches** → Decrypts locally with edge private key

---

## 4. Identity Layer

### 4.1 Identity Object

An Identity is the persistent cryptographic root of a Relay user.

```typescript
interface Identity {
  identity_id: string;        // = fingerprint of public key (32 hex chars)
  public_key: Uint8Array;     // Ed25519 public key (32 bytes)
  home_server: string;        // e.g., "userelay.org"
  status: IdentityStatus;     // "active" | "locked" | "hidden"
  created_at: timestamp;
}

type IdentityStatus = "active" | "locked" | "hidden";
```

### 4.2 Key Generation

```
┌──────────────────────────────────────────────────────────────┐
│                    IDENTITY CREATION                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   1. Generate Ed25519 Keypair                                 │
│      ┌────────────────────────────────────────────────────┐  │
│      │  keypair = nacl.sign.keyPair()                     │  │
│      │  publicKey  = 32 bytes                             │  │
│      │  secretKey  = 64 bytes (includes seed)             │  │
│      └────────────────────────────────────────────────────┘  │
│                                                               │
│   2. Compute Identity ID (Fingerprint)                        │
│      ┌────────────────────────────────────────────────────┐  │
│      │  hash = SHA-256(publicKey)                         │  │
│      │  fingerprint = hash[0:16].toHex()  // 32 chars     │  │
│      └────────────────────────────────────────────────────┘  │
│                                                               │
│   3. Encrypt Secret Key for Storage                           │
│      ┌────────────────────────────────────────────────────┐  │
│      │  salt = randomBytes(32)                            │  │
│      │  derivedKey = PBKDF2(passphrase, salt, 100000)     │  │
│      │  nonce = randomBytes(24)                           │  │
│      │  encrypted = secretbox(secretKey, nonce, derived)  │  │
│      └────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

**Rules:**
- `identity_id` is deterministically derived from the public key
- Private keys NEVER leave the client unencrypted
- Private keys NEVER touch the server in any form
- Identity is immutable except for status changes

### 4.3 Identity Status

| Status | Meaning | Behavior |
|--------|---------|----------|
| `active` | Normal operation | Reachable via native and all edges |
| `locked` | Frozen (compromise or user choice) | No operations allowed |
| `hidden` | Dark mode | Native edge disabled, only other edges work |

### 4.4 Identity Recovery

**There is no server-side recovery mechanism.** This is a deliberate security choice.

If a user loses:
- Their device AND
- Their backup passphrase

The identity is **permanently irrecoverable**. This is the trade-off for true zero-knowledge architecture.

**Recommended backup methods:**
- Encrypted backup file (JSON with passphrase-encrypted private key)
- Paper backup of recovery passphrase
- Hardware security key (future)

---

## 5. Edge Layer

### 5.1 The Edge Concept

Edges are the core innovation of Relay. They provide **disposable, unlinkable contact surfaces** that route to a stable identity.

```
┌─────────────────────────────────────────────────────────────────┐
│                         EDGE MODEL                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   TRADITIONAL MODEL:                                             │
│   ┌─────────────────────┐                                       │
│   │  taylor@gmail.com   │ ◄── Identity = Contact Point          │
│   │  (permanent)        │     (spam it → lose it forever)       │
│   └─────────────────────┘                                       │
│                                                                  │
│   RELAY MODEL:                                                   │
│   ┌─────────────────────┐                                       │
│   │      IDENTITY       │ ◄── Permanent, private                │
│   │   (cryptographic)   │                                       │
│   └──────────┬──────────┘                                       │
│              │                                                   │
│     ┌────────┼────────┐                                         │
│     ▼        ▼        ▼                                         │
│   ┌───┐   ┌───┐   ┌───┐                                        │
│   │ E │   │ E │   │ E │ ◄── Edges: disposable, unlinkable      │
│   │ 1 │   │ 2 │   │ 3 │     (spam one → burn it, keep others)  │
│   └───┘   └───┘   └───┘                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Edge Object

```typescript
interface Edge {
  edge_id: string;                    // Unique identifier (ULID)
  identity_id: string;                // Owner's fingerprint (never exposed publicly)
  type: EdgeType;                     // "native" | "email" | "contact_link" | ...
  address: string;                    // Type-specific address
  x25519_public_key: Uint8Array;      // Unique encryption key for THIS edge
  label?: string;                     // User-friendly name
  status: EdgeStatus;                 // "active" | "disabled"
  security_level: SecurityLevel;      // "e2ee" | "gateway_secured"
  created_at: timestamp;
  policy: EdgePolicy;
}

type EdgeType = "native" | "email" | "contact_link" | "discord" | "slack" | "sms";
type EdgeStatus = "active" | "disabled";
type SecurityLevel = "e2ee" | "gateway_secured";
```

### 5.3 Edge Types

| Type | Address Format | Security Level | Description |
|------|---------------|----------------|-------------|
| `native` | `@handle` | `e2ee` | Direct Relay-to-Relay, highest security |
| `email` | `alias@rlymsg.com` | `gateway_secured` | Receive from any email sender |
| `contact_link` | `/c/{slug}` | `gateway_secured` | Public contact form |
| `discord` | Discord channel | `gateway_secured` | Discord bridge (future) |
| `slack` | Slack channel | `gateway_secured` | Slack bridge (future) |
| `sms` | Phone number | `gateway_secured` | SMS bridge (future) |

### 5.4 Cryptographic Unlinkability

**This is a critical security property.** Each edge has its own unique X25519 keypair, generated randomly—NOT derived from the identity key.

```
┌─────────────────────────────────────────────────────────────────┐
│                 EDGE KEY INDEPENDENCE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   WRONG (linkable):                                              │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  edgeKey = deriveKey(identityKey, edgeId)               │   │
│   │  // Observer with two edge keys can prove same owner!   │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   CORRECT (unlinkable):                                          │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  edgeKey = nacl.box.keyPair()  // Random, independent   │   │
│   │  // Each edge has mathematically unrelated keypair      │   │
│   │  // No way to prove two edges belong to same identity   │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- An observer who knows two of your edge addresses cannot prove they belong to the same person
- Even the server cannot correlate edges to identities without direct database access to the `identity_id` column
- This provides strong privacy even against a fully compromised server

### 5.5 Edge Lifecycle

| Operation | Description | Effect |
|-----------|-------------|--------|
| **Create** | Generate new edge with unique keypair | Ready to receive messages |
| **Disable** | Stop accepting new messages | Instant, preserves history |
| **Rotate** | Disable old → create new with link | Existing conversations transfer |

**Disable is atomic and instant.** When you disable an edge:
- No new messages can be received
- All existing conversations remain accessible
- The edge cannot be re-enabled (create new instead)
- This is the "burn the P.O. Box" operation

### 5.6 Edge Policy

Each edge can have custom policies:

```typescript
interface EdgePolicy {
  rate_limit?: number;        // Max messages per hour
  first_contact: {
    mode: "open" | "pow" | "allowlist" | "mutual";
    pow_difficulty?: number;  // For proof-of-work mode
    allowlist?: string[];     // For allowlist mode
  };
  denylist?: string[];        // Blocked senders
}
```

---

## 6. Handle Layer

### 6.1 Handle Format

Handles are human-readable addresses that resolve to native edges.

```
Full form:    @taylor@userelay.org
Short form:   @taylor                  (implies home server)
```

**Validation rules:**
- 3-24 characters (excluding @ prefix and @server suffix)
- Must start with a letter
- Lowercase alphanumeric and underscores only
- Server portion is a valid domain

### 6.2 Handle ↔ Edge Relationship

A handle IS a native edge. When you claim `@taylor`, you're creating a native edge with address `taylor`.

```
Handle: @taylor@userelay.org
   └─> Native Edge
       ├── type: "native"
       ├── address: "taylor"
       ├── x25519_public_key: [unique random key]
       └── security_level: "e2ee"
```

### 6.3 Handle Resolution

When Alice wants to message `@bob`:

```
1. Alice's client:    POST /v1/edge/resolve { type: "native", address: "bob" }
2. Server returns:    { edgeId, x25519PublicKey, status }
                      (NO identity information!)
3. Alice encrypts:    Using Bob's edge public key
4. Alice sends:       Encrypted message to server
5. Bob decrypts:      Using his edge private key (client-side)
```

**Privacy guarantee:** The resolution endpoint returns ONLY edge information, never identity information.

---

## 7. Messaging Layer

### 7.1 Message Envelope

Every message conforms to this envelope:

```typescript
interface MessageEnvelope {
  // Routing
  message_id: string;           // Unique identifier (ULID)
  protocol_version: string;     // e.g., "1.0"
  conversation_id: string;      // Groups related messages
  edge_id: string;              // Sender's edge (never recipient's identity)
  
  // Security
  origin: EdgeType;             // "native" | "email" | etc.
  security_level: SecurityLevel;// "e2ee" | "gateway_secured"
  signature?: string;           // Ed25519 signature (required for e2ee)
  
  // Payload
  payload: EncryptedPayload;
  
  // Metadata
  created_at: timestamp;        // Rounded to 5-minute intervals on server
}

interface EncryptedPayload {
  content_type: string;         // MIME type of plaintext
  ciphertext: string;           // Base64-encoded ciphertext
  nonce: string;                // Base64-encoded nonce
  
  // Double Ratchet fields (for e2ee)
  dh?: string;                  // Current DH public key
  pn?: number;                  // Previous chain length
  n?: number;                   // Message number in chain
}
```

### 7.2 Conversation Object

Messages are grouped into conversations:

```typescript
interface Conversation {
  conversation_id: string;
  my_edge_id: string;             // Your edge in this conversation
  counterparty_edge_id?: string;  // Their edge (if known)
  origin: EdgeType;               // How conversation started
  security_level: SecurityLevel;  // Current security level
  is_initiator: boolean;          // Did you start the conversation?
}
```

### 7.3 Security Level Rules

| Scenario | Security Level |
|----------|----------------|
| All messages are native (Relay→Relay) | `e2ee` |
| All messages via bridges | `gateway_secured` |
| Mixed origins | `mixed` (display warning) |

---

## 8. Cryptographic Specification

### 8.1 Algorithm Suite

| Purpose | Algorithm | Library | Notes |
|---------|-----------|---------|-------|
| Identity Signing | Ed25519 | TweetNaCl | 32-byte keys |
| Key Exchange | X25519 | TweetNaCl | Curve25519 ECDH |
| Symmetric Encryption | XSalsa20-Poly1305 | TweetNaCl | 24-byte nonce, AEAD |
| Hashing | SHA-256 | Web Crypto | For fingerprints |
| Key Derivation | PBKDF2-SHA256 | Web Crypto | 100,000 iterations |
| Session Encryption | Double Ratchet | Custom | Signal Protocol-based |

**Why TweetNaCl?**
- Audited (Cure53, 2016)
- No native dependencies
- Runs in browsers and extensions
- Battle-tested in many production systems

### 8.2 Double Ratchet Protocol

For native (E2EE) conversations, Relay implements the Double Ratchet algorithm for forward secrecy and post-compromise security.

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOUBLE RATCHET                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐         ┌─────────────┐                       │
│   │   Alice     │         │    Bob      │                       │
│   └──────┬──────┘         └──────┬──────┘                       │
│          │                       │                               │
│          │  Initial Key Exchange │                               │
│          │◄─────────────────────►│                               │
│          │                       │                               │
│    ┌─────┴─────┐           ┌─────┴─────┐                        │
│    │  Ratchet  │           │  Ratchet  │                        │
│    │  State    │           │  State    │                        │
│    │ ┌───────┐ │           │ ┌───────┐ │                        │
│    │ │Root K │ │           │ │Root K │ │                        │
│    │ │Chain K│ │           │ │Chain K│ │                        │
│    │ │ DH KP │ │           │ │ DH KP │ │                        │
│    │ └───────┘ │           │ └───────┘ │                        │
│    └───────────┘           └───────────┘                        │
│          │                       │                               │
│          │   Message 1           │                               │
│          │─────────────────────►│                               │
│          │   (new DH key)        │                               │
│          │                       │                               │
│          │   Message 2           │                               │
│          │◄─────────────────────│                               │
│          │   (ratchet step)      │                               │
│          │                       │                               │
│                                                                  │
│   Properties:                                                    │
│   ✓ Forward Secrecy: Past messages safe if current key leaked   │
│   ✓ Post-Compromise: Security recovers after key compromise     │
│   ✓ Per-Message Keys: Each message has unique key               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.3 Key Derivation Functions

```typescript
// Root Key Ratchet (HKDF-based)
function KDF_RK(rootKey: Uint8Array, dhOutput: Uint8Array): { rk: Uint8Array; ck: Uint8Array } {
  const prk = HMAC_SHA256(rootKey, dhOutput);
  const output = HKDF_Expand(prk, "RelayDoubleRatchetRootKey", 64);
  return {
    rk: output.slice(0, 32),   // New root key
    ck: output.slice(32, 64),  // New chain key
  };
}

// Chain Key Ratchet
function KDF_CK(chainKey: Uint8Array): { ck: Uint8Array; mk: Uint8Array } {
  return {
    ck: HMAC_SHA256(chainKey, [0x01]),  // Next chain key
    mk: HMAC_SHA256(chainKey, [0x02]),  // Message key
  };
}
```

### 8.4 Message Encryption Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  ENCRYPTION FLOW (E2EE)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Get or initialize ratchet state                             │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  state = loadRatchetState(conversationId)           │    │
│      │        || initializeRatchet(sharedSecret)           │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
│   2. Derive message key from chain                               │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  { chainKey, messageKey } = KDF_CK(state.chainKey)  │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
│   3. Encrypt message content                                     │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  nonce = randomBytes(24)                            │    │
│      │  ciphertext = nacl.secretbox(plaintext, nonce, mk)  │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
│   4. Build ratchet message                                       │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  message = {                                        │    │
│      │    ciphertext,                                      │    │
│      │    nonce,                                           │    │
│      │    dh: state.DHs.publicKey,  // Current DH key      │    │
│      │    pn: state.PN,             // Previous chain len  │    │
│      │    n: state.Ns               // Message number      │    │
│      │  }                                                  │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
│   5. Sign the message                                            │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  signature = Ed25519.sign(hash(message), secretKey) │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
│   6. Update and save ratchet state                               │
│      ┌─────────────────────────────────────────────────────┐    │
│      │  state.chainKey = chainKey                          │    │
│      │  state.Ns++                                         │    │
│      │  saveRatchetState(conversationId, state)            │    │
│      └─────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.5 Cryptographic Assumptions

Relay's security relies on the hardness of:

1. **Discrete Logarithm Problem** on Curve25519
2. **Collision Resistance** of SHA-256
3. **Semantic Security** of XSalsa20-Poly1305 (AEAD)
4. **Password-Based Key Derivation** of PBKDF2

**Post-Quantum Consideration:** These algorithms are NOT quantum-resistant. Relay's roadmap includes migration to CRYSTALS-Kyber (key encapsulation) and CRYSTALS-Dilithium (signatures) when standards mature.

---

## 9. Transport & API

### 9.1 Base URL

```
https://{home_server}/v1/
```

### 9.2 Authentication

Relay uses challenge-response authentication with Ed25519 signatures:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Client                              Server                     │
│      │                                   │                       │
│      │  POST /v1/auth/nonce              │                       │
│      │  { identityId }                   │                       │
│      │─────────────────────────────────►│                       │
│      │                                   │                       │
│      │  { nonce, expiresAt }             │                       │
│      │◄─────────────────────────────────│                       │
│      │                                   │                       │
│      │  Sign: "relay-auth:{nonce}"       │                       │
│      │                                   │                       │
│      │  POST /v1/auth/verify             │                       │
│      │  { publicKey, nonce, signature }  │                       │
│      │─────────────────────────────────►│                       │
│      │                                   │                       │
│      │  { token, expiresAt }             │                       │
│      │◄─────────────────────────────────│  (JWT, 1 hour)        │
│      │                                   │                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Core Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/v1/identity/register` | Signature | Register new identity |
| `POST` | `/v1/auth/nonce` | None | Request authentication nonce |
| `POST` | `/v1/auth/verify` | Signature | Verify signature, get JWT |
| `POST` | `/v1/edge` | JWT | Create new edge |
| `GET` | `/v1/edges` | JWT | List user's edges |
| `POST` | `/v1/edge/resolve` | None | Resolve edge to public key |
| `DELETE` | `/v1/edge/:id` | JWT | Disable an edge |
| `GET` | `/v1/conversations` | JWT | List conversations |
| `POST` | `/v1/messages` | JWT | Send a message |
| `GET` | `/v1/conversations/:id/messages` | JWT | Get messages |

### 9.4 Edge Resolution (Critical Endpoint)

The `/v1/edge/resolve` endpoint is central to Relay's privacy model:

**Request:**
```json
POST /v1/edge/resolve
{
  "type": "native",
  "address": "taylor"
}
```

**Response:**
```json
{
  "edgeId": "01HQXYZ...",
  "type": "native",
  "status": "active",
  "securityLevel": "e2ee",
  "x25519PublicKey": "base64...",
  "displayName": "Taylor"
}
```

**What is NOT returned:**
- ❌ `identity_id` — Never exposed
- ❌ `owner` — Never exposed
- ❌ Any information linking edge to identity

### 9.5 Transport Security

| Requirement | Specification |
|-------------|---------------|
| TLS Version | 1.3+ required |
| Certificate Validation | Mandatory, no overrides |
| Certificate Pinning | Recommended for clients |
| Downgrade Protection | Enforced |

---

## 10. Bridge Architecture

### 10.1 What Are Bridges?

Bridges allow Relay users to receive messages from external platforms (email, Discord, etc.) in their unified inbox.

```
┌─────────────────────────────────────────────────────────────────┐
│                      BRIDGE ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   External World                    Relay World                  │
│   ┌─────────────┐                  ┌─────────────┐              │
│   │   Email     │                  │   Client    │              │
│   │   Sender    │                  │             │              │
│   └──────┬──────┘                  └──────▲──────┘              │
│          │                                │                      │
│          │ (1) Send to                    │ (4) Decrypt         │
│          │ xyz@rlymsg.com                 │ & Display           │
│          ▼                                │                      │
│   ┌──────────────┐    (3) Store    ┌──────┴──────┐              │
│   │    Email     │    encrypted    │   Server    │              │
│   │    Bridge    │────────────────►│             │              │
│   │   (Worker)   │                 └─────────────┘              │
│   └──────────────┘                                              │
│          │                                                       │
│          │ (2) Encrypt for                                       │
│          │ recipient's edge key                                  │
│          ▼                                                       │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  encryptedPayload = nacl.box(email, recipientEdgePubkey) │  │
│   │  // Worker CANNOT read after encryption                   │  │
│   │  // Server CANNOT read (no keys)                          │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 Email Bridge Flow (Inbound)

1. **Email arrives** at `xyz123@rlymsg.com`
2. **Bridge resolves edge** via `/v1/edge/resolve`
3. **Bridge encrypts entire email** with recipient's edge X25519 key
4. **Bridge forwards encrypted payload** to server
5. **Server stores ciphertext** (cannot decrypt)
6. **Client fetches and decrypts** with edge private key

**Zero-knowledge properties:**
- Server never sees plaintext email content
- Server never sees sender's email address (only a hash for conversation matching)
- Only the recipient can decrypt

### 10.3 Email Bridge Flow (Outbound / Reply)

For replies, the flow protects the external recipient's email address:

```
┌─────────────────────────────────────────────────────────────────┐
│                    OUTBOUND EMAIL FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Client fetches worker's public key                          │
│      GET /public-key → { x25519PublicKey }                       │
│                                                                  │
│   2. Client encrypts recipient email FOR THE WORKER              │
│      encryptedRecipient = nacl.box(                              │
│        recipientEmail,       // "alice@gmail.com"                │
│        workerPublicKey       // Worker can decrypt               │
│      )                                                           │
│                                                                  │
│   3. Client sends to worker                                      │
│      POST /send {                                                │
│        content: "Hello...",                                      │
│        encryptedRecipient,   // Only worker can read             │
│        edgeAddress: "xyz@rlymsg.com"                             │
│      }                                                           │
│                                                                  │
│   4. Worker decrypts recipient (transiently, in memory)          │
│      recipientEmail = nacl.box.open(encryptedRecipient)          │
│                                                                  │
│   5. Worker sends email via Resend                               │
│      From: xyz123@rlymsg.com                                     │
│      To: alice@gmail.com                                         │
│                                                                  │
│   6. Worker purges decrypted recipient from memory               │
│      // Never logged, never stored                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key property:** The server NEVER learns the external recipient's email address. Only the worker (transiently) and the user (encrypted locally) know it.

### 10.4 Bridge Security Levels

| Bridge | Security Level | What Bridge Sees | Notes |
|--------|---------------|------------------|-------|
| **Native** | `e2ee` | Nothing | End-to-end encrypted |
| **Email** | `gateway_secured` | Email content (transiently) | Encrypted before storage |
| **Discord** | `gateway_secured` | Message content (transiently) | Platform sees metadata |
| **SMS** | `gateway_secured` | Full plaintext* | *Carrier sees everything |

*SMS is inherently insecure. Relay encrypts at the application layer, but carriers see plaintext.

---

## 11. Security Model & Threat Analysis

### 11.1 Adversary Classes

Relay is designed to protect against these adversary classes:

#### Class 1: Passive Network Observer

**Capabilities:**
- Observe encrypted traffic
- Correlate timing and message sizes
- Monitor DNS and IP addresses

**Mitigations:**
- TLS 1.3+ for all connections
- Certificate pinning (recommended)
- Future: message padding, mixnet integration

#### Class 2: Active Network Attacker (MITM)

**Capabilities:**
- Intercept and modify traffic
- Inject malicious responses
- Perform TLS interception

**Mitigations:**
- TLS with strict certificate validation
- Ed25519 signatures on all messages
- Challenge-response authentication with nonces

#### Class 3: Malicious Server Operator (PRIMARY THREAT MODEL)

This is Relay's primary threat model. We assume the server is fully compromised.

**What they GET:**
| Data | Description |
|------|-------------|
| Encrypted messages | Ciphertext (useless without client keys) |
| Edge addresses | `xyz123@rlymsg.com` (not linked to identity in API) |
| Conversation IDs | UUIDs (unlinkable without decryption) |
| Timestamps | Rounded to 5-minute intervals |
| Message status | Sent/delivered/failed |

**What they DON'T GET:**
| Data | Why Not |
|------|---------|
| Private keys | Never touch server |
| Plaintext content | Encrypted client-side |
| User identities | Architecturally separated from edges |
| Precise timestamps | Rounded to 5 minutes |
| IP addresses | Never logged |
| Social graph | Participants use salted hashes |

**Attack difficulty:** To deanonymize a user, an attacker must:
1. Compromise the database
2. Correlate edge → identity (requires multiple table joins)
3. Decrypt message content (requires client keys)
4. Break Ed25519/X25519 (mathematically infeasible)

#### Class 4: Compromised Client Device

**Capabilities:**
- Access private keys in memory
- Read all decrypted content
- Impersonate user

**Mitigations:**
- Passphrase encryption (PBKDF2, 100k iterations)
- Auto-lock on inactivity
- Device key revocation (multi-device mode)
- Memory zeroization after use

#### Class 5: State-Level Actor

**Capabilities:**
- All of the above
- Subpoena server operators
- Demand backdoors

**Mitigations:**
- No server-side key escrow (cannot comply with key requests)
- Open protocol enables self-hosting
- Encryption provides mathematical guarantees
- Transparency about limitations

### 11.2 What Relay CANNOT Protect Against

We believe in honest security communication. Relay cannot protect against:

| Threat | Why Not | Mitigation |
|--------|---------|------------|
| **Compromised endpoint** | If malware owns your device, it owns your keys | Use trusted devices, keep software updated |
| **Rubber hose cryptanalysis** | Coercion defeats cryptography | Use deniable encryption (future) |
| **Key loss** | No server-side recovery (by design) | Keep secure backups |
| **Sophisticated traffic analysis** | Metadata not fully hidden (yet) | Future mixnet integration |
| **Quantum computers** | Current algorithms not quantum-resistant | Migration planned when standards mature |

### 11.3 Attack Scenarios

#### Scenario: Server Database Breach

**Attack:** Attacker gains full read access to server database.

**What they get:**
```sql
-- They can run queries like:
SELECT * FROM messages;          -- Encrypted blobs (useless)
SELECT * FROM edges;             -- Edge addresses (not linked to users in API)
SELECT * FROM conversations;     -- UUIDs and encrypted content
```

**What they CANNOT determine:**
- Who sent which message
- Who received which message
- What any message says
- Which edges belong to which identity (without key)

**Protection level:** Even with full database access, an attacker learns almost nothing useful.

#### Scenario: Man-in-the-Middle on First Contact

**Attack:** Attacker intercepts handle resolution and substitutes their public key.

**Mitigations:**
- Server signs identity lookups
- Key continuity checking (TOFU model)
- Out-of-band fingerprint verification (recommended)

**Residual risk:** First contact vulnerable if attacker controls both network AND server.

#### Scenario: Handle Hijacking

**Attack:** Attacker tries to claim victim's handle.

**Why it fails:**
- Handle claims require Ed25519 signature with the identity's private key
- No "password reset" mechanism (there's no password)
- Private key never touches server

#### Scenario: Spam Flood

**Attack:** Attacker floods user with spam messages.

**Response:**
1. Disable the affected edge (atomic, instant)
2. Create new edge if needed
3. Identity and other edges unaffected

**Design principle:** Burn the edge, not the identity.

### 11.4 Security Properties Summary

| Property | Native (E2EE) | Bridge (Gateway-Secured) |
|----------|---------------|--------------------------|
| **Confidentiality** | ✅ Strong (only endpoints) | ⚠️ Gateway sees content transiently |
| **Integrity** | ✅ Strong (AEAD + signature) | ⚠️ TLS only |
| **Authenticity** | ✅ Strong (Ed25519) | ⚠️ Based on gateway |
| **Forward Secrecy** | ✅ Double Ratchet | ❌ Not applicable |
| **Unlinkability** | ✅ Unique edge keys | ✅ Unique edge keys |
| **Metadata Protection** | ⚠️ Limited | ❌ Gateway sees metadata |

---

## 12. Privacy Guarantees

### 12.1 Zero-Knowledge Architecture

Relay implements a zero-knowledge architecture where servers are untrusted storage layers.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZERO-KNOWLEDGE MODEL                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   CLIENT (trusted)                  SERVER (untrusted)          │
│   ┌─────────────────┐              ┌─────────────────┐          │
│   │ • Private keys  │              │ • Ciphertext    │          │
│   │ • Plaintext     │              │ • UUIDs         │          │
│   │ • Encryption    │◄────────────►│ • Routing       │          │
│   │ • Decryption    │   encrypted  │ • Storage       │          │
│   │ • Key derivation│    only      │ • Rate limiting │          │
│   └─────────────────┘              └─────────────────┘          │
│                                                                  │
│   The server is a "dumb pipe" that stores and routes encrypted   │
│   blobs. It cannot decrypt, analyze, or correlate user data.     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 12.2 What the Server Stores

| Field | Example | Can Decrypt? |
|-------|---------|--------------|
| `messages.encrypted_content` | `{ ciphertext: "...", nonce: "..." }` | ❌ No |
| `edges.address` | `xyz123@rlymsg.com` | N/A (not encrypted) |
| `edges.x25519_public_key` | `base64...` | N/A (public key) |
| `conversations.id` | `01HQX...` (ULID) | N/A (random ID) |
| `messages.created_at` | `2026-02-01T12:35:00Z` | N/A (rounded to 5 min) |

### 12.3 What the Server NEVER Stores

| Data | Why Not |
|------|---------|
| Private keys | Never sent to server |
| Plaintext content | Encrypted client-side before sending |
| Email addresses | Hashed or encrypted in edge metadata |
| IP addresses | Never logged, rate limiting by identity |
| Precise timestamps | Rounded to 5-minute intervals |
| User agents | Not stored |

### 12.4 Metadata Minimization

| Metadata | Traditional Systems | Relay |
|----------|---------------------|-------|
| IP addresses | Logged per request | ❌ Never logged |
| Timestamps | Precise (millisecond) | Rounded to 5 minutes |
| Message sizes | Visible | Future: padding |
| Social graph | Fully visible to server | Fragmented by edge architecture |
| Read receipts | Server-mediated | Client-only (optional) |
| Typing indicators | Server-mediated | Not implemented |
| Online status | Server-tracked | Not implemented |

### 12.5 Compliance Properties

#### GDPR Compliance

| Requirement | How Relay Complies |
|-------------|-------------------|
| Data minimization (Art. 5) | Zero-knowledge, minimal metadata |
| Right to access (Art. 15) | User can export all (encrypted) data |
| Right to erasure (Art. 17) | Account deletion cascades all data |
| Data portability (Art. 20) | Standard JSON export |
| Privacy by design (Art. 25) | Encryption by default |

#### Law Enforcement Requests

**What can be provided (if compelled):**
- Encrypted message blobs (useless without user's key)
- Account creation timestamp (rounded to day)
- Edge addresses (not linkable to identity via API)

**What CANNOT be provided (even if compelled):**
- Plaintext message content (we don't have it)
- Decryption keys (we don't have them)
- User identities (architecturally separated)
- IP addresses (never logged)

---

## 13. Implementation Requirements

### 13.1 Client Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| Private key encryption | **MUST** | PBKDF2, minimum 100k iterations |
| Secure random generation | **MUST** | CSPRNG only (crypto.getRandomValues) |
| Memory protection | **SHOULD** | Zero keys after use |
| TLS certificate validation | **MUST** | No insecure overrides |
| Signature verification | **MUST** | Verify all received messages |
| Content Security Policy | **MUST** | For web-based clients |
| Auto-lock on inactivity | **SHOULD** | Configurable timeout |

### 13.2 Server Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| TLS 1.3+ | **MUST** | All connections |
| No plaintext logging | **MUST** | Never log message content |
| No IP logging | **MUST** | Rate limit by identity, not IP |
| Timestamp rounding | **MUST** | Round to 5-minute intervals |
| Input validation | **MUST** | Reject malformed requests |
| Rate limiting | **MUST** | All endpoints |
| Nonce expiry | **MUST** | 5 minutes maximum |

### 13.3 Bridge Worker Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| No content logging | **MUST** | Never log plaintext |
| No recipient logging | **MUST** | Decrypt transiently, purge immediately |
| Ed25519 payload signing | **MUST** | Prevent injection |
| Key rotation | **SHOULD** | Annual rotation of worker keys |

---

## 14. Future Roadmap

### 14.1 Current Status (v1.0)

| Feature | Status |
|---------|--------|
| Identity system | ✅ Complete |
| Edge architecture | ✅ Complete |
| Email bridge | ✅ Complete |
| Double Ratchet | ✅ Complete |
| Zero-knowledge storage | ✅ Complete |
| Native messaging | 🔄 In Progress |

### 14.2 Short-Term (v1.x)

| Feature | Description |
|---------|-------------|
| Native Relay-to-Relay | Full E2EE between Relay users |
| Multi-device support | Device keys signed by master identity |
| Group conversations | MLS-based group encryption |
| Key verification UI | Fingerprint comparison, safety numbers |

### 14.3 Medium-Term (v2.x)

| Feature | Description |
|---------|-------------|
| Post-quantum migration | CRYSTALS-Kyber/Dilithium hybrid |
| Message padding | Normalize sizes to prevent traffic analysis |
| Discord/Slack bridges | Additional platform integrations |
| Federation | Multiple servers, decentralized |

### 14.4 Long-Term

| Feature | Description |
|---------|-------------|
| Mixnet integration | Timing obfuscation via mix nodes |
| Sealed sender | Hide sender from server during routing |
| Hardware key support | YubiKey, HSM integration |
| Onion routing | Multi-hop message routing |

---

## Appendices

### Appendix A: Cryptographic Primitives Reference

| Purpose | Algorithm | Parameters | Library |
|---------|-----------|------------|---------|
| Signing | Ed25519 | 32-byte seed | TweetNaCl |
| Key Exchange | X25519 | 32-byte keys | TweetNaCl |
| Symmetric | XSalsa20-Poly1305 | 24-byte nonce, 32-byte key | TweetNaCl |
| Hash | SHA-256 | 256-bit output | Web Crypto |
| KDF (password) | PBKDF2-SHA256 | 100k iterations, 32-byte salt | Web Crypto |
| KDF (ratchet) | HKDF-SHA256 | Custom info strings | TweetNaCl/Custom |

### Appendix B: Security Level Badges

| Level | Badge | UI Text |
|-------|-------|---------|
| `e2ee` | 🔒 | "End-to-end encrypted. Only you and the recipient can read this." |
| `gateway_secured` | 🔁 | "Relayed via [origin]. Protected in transit, but processed by gateway." |
| `mixed` | ⚠️ | "This conversation contains messages with different security levels." |

### Appendix C: Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `INVALID_SIGNATURE` | 401 | Ed25519 signature verification failed |
| `NONCE_EXPIRED` | 401 | Authentication nonce expired |
| `IDENTITY_NOT_FOUND` | 404 | Identity not registered |
| `EDGE_NOT_FOUND` | 404 | Edge does not exist |
| `HANDLE_TAKEN` | 409 | Handle already claimed |
| `RATE_LIMITED` | 429 | Too many requests |

### Appendix D: Reference Implementation

The reference implementation is maintained at:

| Component | Repository | Status |
|-----------|------------|--------|
| Protocol Spec | `relay-protocol` | This document |
| Client (Extension) | `relay-client` | Active development |
| Server | `relay-server` | Active development |
| Email Worker | `relay-server/email-worker` | Active development |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-31 | Initial specification |
| 1.1.0 | 2026-02-02 | Edge-to-edge encryption, threat model integration, comprehensive rewrite for public audience |

---

## Contributing

Relay is an open protocol. We welcome contributions:

- **Security issues:** Please report privately to security@userelay.org
- **Protocol improvements:** Open an issue or PR in the relay-protocol repository
- **Implementations:** Build your own Relay-compatible client or server

---

## License

This specification is released under the MIT License.

---

<p align="center">
  <strong>Relay Protocol v1.1.0</strong><br/>
  <em>Your messages. Your identity. Your control.</em>
</p>
