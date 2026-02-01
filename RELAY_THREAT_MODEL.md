# Relay Protocol Threat Model

**Status:** Active  
**Version:** 1.1.0  
**Date:** February 1, 2026  
**Authors:** Relay Foundation

**Related Documents:**
- [Relay Protocol Specification](RELAY_PROTOCOL_v1.md)
- [Relay Security & Privacy Ethos](../RELAY_ETHOS.md) - Core principles and implementation standards

---

## 1. Overview

This document describes the threat model for the Relay Protocol. It identifies adversaries, attack surfaces, and the mitigations built into the protocol and reference implementation.

**Core Principle:** Relay is designed as a **zero-knowledge communication system** where servers cannot decrypt user data or identify communication patterns, even with full system access. See [RELAY_ETHOS.md](../RELAY_ETHOS.md) for complete security principles.

**Scope:** This threat model covers:
- The Relay Protocol as specified in RELAY_PROTOCOL_v1.md
- Client implementations (extension, webapp, mobile)
- Server implementations (home servers, gateways)
- Bridge workers (email, Discord, etc.)
- Federation between servers (future)

**Out of scope:**
- Operating system security
- Hardware security (beyond acknowledgment)
- Physical attacks
- External bridge provider security (email providers, Discord, etc.)

---

## 2. Security Goals

### 2.1 Primary Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Zero-Knowledge** | Server cannot decrypt user data or identify communication partners | Client-side encryption, encrypted recipient addresses |
| **Confidentiality** | Only intended recipients can read message content | E2EE with X25519-XSalsa20-Poly1305 |
| **Integrity** | Messages cannot be modified without detection | Ed25519 signatures, AEAD encryption |
| **Authenticity** | Sender identity is cryptographically verifiable | Ed25519 signing keys |
| **Forward Secrecy** | Compromise of current keys doesn't expose past messages | Per-conversation ephemeral keys (Phase 4) |
| **Metadata Minimization** | Limit exposure of who-talks-to-whom, when, and patterns | Timestamp rounding, no IP logging, architecture isolation |

### 2.2 Secondary Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Availability** | Service remains accessible under attack | Rate limiting, CDN, redundancy |
| **Unlinkability** | Edges cannot be linked to identities | Handle → Edge separation, encrypted external IDs |
| **Pseudonymous Usage** | Users can participate without revealing identity | Disposable edges, no KYC |
| **Honest Labeling** | Users always know true security posture | Security level badges (e2ee vs gateway-secured) |
| **Transparency** | Security claims are verifiable | Open source crypto, published protocols |

---

## 3. Trust Model

### 3.1 Zero-Knowledge Architecture

**Core Design Principle:** Servers are untrusted storage and routing layers. They never have access to:
- Private keys (never leave client)
- Plaintext message content (encrypted client-side)
- Plaintext recipient addresses (encrypted for workers)
- User identities (handles separated from edges)

See [RELAY_ETHOS.md](../RELAY_ETHOS.md) for complete zero-knowledge implementation standards.

### 3.2 Entities and Trust Levels

| Entity | Trust Level | Access | Notes |
|--------|-------------|--------|-------|
| **User's own client** | Full | Private keys, plaintext content | Holds secrets, performs all crypto |
| **User's home server** | **None** | Encrypted blobs, rounded timestamps, UUIDs | Cannot decrypt, cannot identify users |
| **Bridge workers** | Transient | Recipient addresses (decrypted for sending) | Decrypt transiently, never store, never log plaintext |
| **Counterparty's client** | Conditional | Plaintext after decryption | Trusted with content after key exchange |
| **Counterparty's server** | **None** | Encrypted blobs only | Same as home server |
| **External bridges** | Minimal | Metadata (timing, sender edge) | Email providers, Discord, etc. see metadata |
| **Network infrastructure** | **None** | TLS-encrypted traffic | Assumed hostile |

### 3.3 What We Trust Servers To Do

Home servers are trusted to:
- ✅ Store encrypted content without tampering (but we verify signatures)
- ✅ Route messages to correct destinations
- ✅ Apply rate limits honestly
- ✅ Delete data when requested

Home servers are **EXPLICITLY NOT** trusted to:
- ❌ Not read message content (they can't - it's encrypted)
- ❌ Not log metadata (we assume they do - architecture minimizes it)
- ❌ Not attempt deanonymization (architecture prevents it)
- ❌ Be available forever (clients cache locally)
- ❌ Not comply with legal requests (they get encrypted data only)

**Key difference from traditional systems:** Most systems trust servers not to be malicious. **Relay assumes servers ARE malicious** and uses cryptography and architecture to limit damage.

### 3.4 Worker Trust Model

**Bridge workers** (Cloudflare Workers for email, Discord, etc.) handle a special case:
- **MUST** transiently decrypt recipient addresses to send via external APIs
- **CANNOT** see message content (encrypted separately)
- **MUST** verify cryptographic signatures on requests
- **MUST NOT** log plaintext values
- **MUST NOT** store decrypted data

Worker secrets (X25519 keys) are rotated annually and never shared with servers.

### 3.5 Bridge Trust Model

External bridges have different security properties:

| Bridge Type | Trust Required | What They See | E2E Encrypted? |
|-------------|----------------|---------------|----------------|
| **Native** (Relay→Relay) | None | Nothing (encrypted) | ✅ Yes |
| **Email** | Worker only | Edge address, timing | ✅ Yes (Relay layer) |
| **Discord/Telegram** | Worker + platform | Bot account, timing | ✅ Yes (Relay layer) |
| **SMS** | Worker + carrier | Phone number, timing, **plaintext*** | ⚠️ Partial (Relay layer only) |

*SMS is NOT encrypted by carriers - only Relay's encryption layer protects content.

Users are informed via security badges when using lower-security bridges.

---

## 4. Adversary Model

### 4.1 Adversary Classes

#### Class 1: Passive Network Observer
**Capabilities:**
- Observe encrypted traffic
- Correlate timing and sizes
- Monitor DNS, IP addresses

**Mitigations:**
- TLS 1.3+ for all connections
- Certificate pinning (recommended)
- Padding (future: message size normalization)

#### Class 2: Active Network Attacker
**Capabilities:**
- Modify network traffic
- Perform MITM attacks
- Inject malicious responses

**Mitigations:**
- TLS with certificate validation
- Signature verification on all messages
- Challenge-response authentication

#### Class 3: Malicious Server Operator (PRIMARY THREAT MODEL)
**Capabilities:**
- Full database read/write access
- Log all metadata
- Delay or drop messages
- Attempt to inject fake messages
- Subpoena/warrant compliance
- Correlate timing patterns

**What they GET:**
- Encrypted message content (useless without keys)
- Conversation IDs (UUIDs, not linkable)
- Edge addresses (not directly linked to identities)
- Rounded timestamps (5-minute granularity)
- Message delivery status

**What they DON'T GET:**
- Plaintext message content (encrypted client-side)
- Private keys (never on server)
- User identities (handles separated from edges architecturally)
- Precise timestamps (rounded to 5 minutes)
- IP addresses (never logged)
- Communication partners (participants use salted hashes)

**Mitigations:**
- **Zero-knowledge architecture** (see RELAY_ETHOS.md)
- Client-side encryption for all sensitive data
- Architectural isolation (Handle → Edge → Conversation layers)
- Encrypted external IDs in edge metadata
- Timestamp rounding to prevent pattern analysis
- No IP logging (rate limiting by identity, not IP)
- Signature verification (detects message injection)
- Forward secrecy (per-conversation keys, future phase)

#### Class 4: Compromised Client
**Capabilities:**
- Access private keys
- Read all decrypted content
- Impersonate user

**Mitigations:**
- Key storage encryption (passphrase-derived)
- Device key revocation (for multi-device)
- Backup passphrase for recovery
- No server-side key backup (limits blast radius)

#### Class 5: Sophisticated State Actor
**Capabilities:**
- All of the above
- Subpoena server operators
- Demand backdoors

**Mitigations:**
- No server-side key escrow
- Open protocol enables self-hosting
- Encryption provides mathematical guarantees
- Transparency about limitations

---

## 5. Attack Surface Analysis

### 5.1 Client Attack Surfaces

| Surface | Attacks | Mitigations |
|---------|---------|-------------|
| **Private key storage** | Key extraction, brute force | Passphrase encryption (Argon2id), memory protection |
| **UI rendering** | XSS, injection | Content sanitization, CSP, no remote code |
| **Message parsing** | Buffer overflow, crashes | Input validation, safe parsing libraries |
| **Key exchange** | MITM, key substitution | Signature verification, fingerprint comparison |
| **Backup files** | Theft of encrypted backup | Strong passphrase, Argon2id key derivation |

### 5.2 Server Attack Surfaces

| Surface | Attacks | Mitigations |
|---------|---------|-------------|
| **API endpoints** | Injection, DoS, auth bypass | Input validation, rate limiting, auth middleware |
| **Database** | SQL injection, data breach | Parameterized queries, encryption at rest |
| **Authentication** | Replay, brute force | Challenge-response, nonce expiry, rate limiting |
| **Federation** | Spoofed servers, routing attacks | Signature verification, server key pinning |
| **Gateway bridges** | Content injection, spam | Worker authentication, content validation |

### 5.3 Protocol Attack Surfaces

| Surface | Attacks | Mitigations |
|---------|---------|-------------|
| **Identity creation** | Sybil attacks | Rate limiting, proof of work (optional) |
| **Handle claiming** | Squatting, impersonation | First-come-first-serve, abuse reporting |
| **Edge creation** | Spam edge generation | Per-identity limits, edge quotas |
| **Message sending** | Spam, abuse | Rate limits, block/report, edge revocation |
| **Key rotation** | Malicious rotation | Dual signature requirement |

---

## 6. Cryptographic Considerations

### 6.1 Algorithm Choices

| Purpose | Algorithm | Justification |
|---------|-----------|---------------|
| Signing | Ed25519 | Fast, secure, small keys, no side-channel issues |
| Key exchange | X25519 | Curve25519, widely analyzed, efficient |
| Symmetric | XSalsa20-Poly1305 | NaCl standard, authenticated encryption |
| Hash | SHA-256 | Widely supported, sufficient security margin |
| KDF | Argon2id | Memory-hard, resistant to GPU/ASIC attacks |

### 6.2 Cryptographic Assumptions

The security of Relay relies on:
1. Discrete logarithm problem hardness on Curve25519
2. Collision resistance of SHA-256
3. Semantic security of XSalsa20-Poly1305
4. Memory-hardness of Argon2id

### 6.3 Post-Quantum Considerations

Current algorithms are **NOT** quantum-resistant. Future protocol versions may add:
- CRYSTALS-Kyber for key encapsulation
- CRYSTALS-Dilithium for signatures
- Hybrid mode during transition

---

## 7. Specific Threat Scenarios

### 7.1 Server Compromise (PRIMARY THREAT)

**Scenario:** Attacker gains full access to a Relay server (database, API, everything).

**What they get:**
- Encrypted message blobs (E2EE - useless without client keys)
- Conversation IDs (UUIDs - not linkable without massive effort)
- Edge addresses (xyz123@rlymsg.com - not linked to user identity)
- Rounded timestamps (5-minute granularity)
- Encrypted edge metadata (external IDs encrypted)
- Message delivery status

**What they DON'T get:**
- **Private keys** (never on server)
- **Plaintext message content** (encrypted client-side, server can't decrypt)
- **User identities** (handles architecturally separated from edges)
- **Communication partners** (participants use salted hashes, not reversible)
- **Precise timing** (timestamps rounded to 5 minutes)
- **IP addresses** (never logged - rate limiting by identity)
- **Decryption capability** (no keys on server)

**Attack difficulty:**
To deanonymize a conversation, attacker must:
1. Compromise database (get encrypted data)
2. Correlate edge addresses to handles (requires multiple table joins)
3. Correlate handles to identities (no direct link)
4. Crack encryption (mathematically infeasible with current tech)

**User mitigation:**
- Use E2EE (native Relay-to-Relay) whenever possible
- Use disposable edges for untrusted communications
- Expect metadata to be logged (architecture minimizes it)
- Consider self-hosting for maximum control

**Protocol guarantee:** Even with full server access, attacker cannot read historical messages or identify users without breaking cryptography.

### 7.2 Client Device Theft

**Scenario:** Physical device is stolen with Relay client installed.

**Protection layers:**
1. Device lock screen (OS-level)
2. Relay passphrase encryption (Argon2id)
3. Session token expiry

**User mitigation:**
- Use strong passphrase (not PIN)
- Enable device encryption
- Consider device key revocation (multi-device mode)

### 7.3 Man-in-the-Middle on First Contact

**Scenario:** Attacker intercepts handle lookup and substitutes their public key.

**Mitigations:**
- Signature verification on all messages
- Key continuity checking (TOFU model)
- Out-of-band verification option (fingerprint comparison)
- Server signing of identity lookups (prevents casual MITM)

**Residual risk:** First contact is vulnerable if attacker controls network AND server.

### 7.4 Malicious Contact Link

**Scenario:** User shares contact link, attacker sends spam/abuse.

**Mitigations:**
- Edge policies (rate limits, proof of work)
- One-click edge disable
- Abuse reporting
- Edge rotation

**Design principle:** Burn the edge, not the identity.

### 7.5 Handle Hijacking (Account Takeover)

**Scenario:** Attacker tries to claim victim's handle.

**Why it fails:**
- Handles bound to identity via signature
- Handle claim requires proof of private key
- No password reset (no password exists)

**Residual risk:** Social engineering of server operator (policy problem, not protocol).

### 7.6 Spam and Abuse

**Scenario:** Attacker floods user with messages.

**Mitigations:**
- Per-edge rate limits
- Edge disable (atomic, instant)
- Block sender (identity-level)
- First contact policies (proof of work, allowlist, mutual)
- Abuse signals for platform-level action

### 7.7 Metadata Correlation

**Scenario:** Adversary correlates timing, sizes, and patterns to infer relationships.

**Current limitations:**
- Metadata visible to home server
- Timing attacks possible
- Message sizes not normalized

**Future mitigations:**
- Message padding (size normalization)
- Mixnet integration (timing obfuscation)
- Onion routing (path obfuscation)

**Honest disclosure:** v1 does NOT provide strong metadata protection against sophisticated adversaries.

---

## 8. Security Properties by Feature

### 8.1 Native (E2EE) Messages

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality | ✅ Strong | Only endpoints can decrypt |
| Integrity | ✅ Strong | AEAD + signature |
| Authenticity | ✅ Strong | Ed25519 signature |
| Forward secrecy | ⚠️ Partial | Per-message ephemeral keys, but no ratchet |
| Deniability | ❌ No | Signatures are non-repudiable |
| Metadata protection | ⚠️ Limited | Server sees routing metadata |

### 8.2 Gateway-Secured Messages

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality | ⚠️ Limited | Gateway can read content |
| Integrity | ⚠️ Limited | TLS only, no e2ee signature |
| Authenticity | ⚠️ Limited | Based on gateway attestation |
| Forward secrecy | ❌ No | Depends on gateway retention |
| Deniability | N/A | Content may be logged externally |
| Metadata protection | ❌ No | Gateway sees everything |

### 8.3 Edge Management

| Property | Status | Notes |
|----------|--------|-------|
| Creation | ✅ Secure | Authenticated, rate-limited |
| Revocation | ✅ Strong | Instant, atomic, irreversible |
| Rotation | ✅ Secure | Linked via `rotated_from_edge_id` |
| Discovery | ⚠️ Design choice | Edges are discoverable by design |

---

## 9. Implementation Security Requirements

### 9.1 Client Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| Private key encryption | MUST | Argon2id, minimum 3 iterations |
| Secure random generation | MUST | CSPRNG only |
| Memory protection | SHOULD | Zero keys after use |
| Certificate validation | MUST | No insecure overrides |
| Input sanitization | MUST | All untrusted content |
| Content Security Policy | MUST | For web-based clients |
| Signature verification | MUST | All received messages |

### 9.2 Server Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| TLS 1.3+ | MUST | All connections |
| Rate limiting | MUST | All endpoints |
| Input validation | MUST | Reject malformed requests |
| Encrypted storage | SHOULD | At-rest encryption |
| Minimal logging | SHOULD | No content logging |
| Auth token rotation | SHOULD | Short-lived tokens |
| Nonce expiry | MUST | 5 minutes maximum |

### 9.3 Gateway Requirements

| Requirement | Priority | Notes |
|-------------|----------|-------|
| No content logging | MUST | Protocol requirement |
| Prompt delivery | MUST | Don't delay messages |
| No content modification | MUST | Pass-through only |
| Worker authentication | MUST | Prevent injection |
| Rate limiting | SHOULD | Prevent abuse |

---

## 10. Known Limitations and Non-Goals

### 10.1 Explicitly Not Addressed

| Limitation | Rationale | Planned? |
|------------|-----------|----------|
| **Perfect traffic analysis resistance** | Would require mixnets/onion routing (UX cost) | Future (Phase 10+) |
| **Quantum resistance** | Curve25519 not quantum-safe; awaiting mature PQ standards | Planned (Phase 7) |
| **Perfect forward secrecy** | Phase 4 adds per-conversation keys (good); Signal ratchet (future) | In Progress |
| **Full metadata encryption** | Routing requires some metadata; minimize instead | Ongoing |
| **Server availability guarantee** | Decentralized redundancy future work | Future |
| **Endpoint security** | Cannot protect compromised devices | Never (user responsibility) |
| **Content moderation** | Zero-knowledge prevents server scanning | Never (by design) |
| **No metadata ever** | Some metadata unavoidable for routing | Never (minimize instead) |

**Key points:**
- ✅ We **DO** provide zero-knowledge (server can't decrypt)
- ✅ We **DO** minimize metadata (timestamps rounded, no IPs, architecture isolation)
- ⚠️ We **DON'T** eliminate all metadata (impossible while functional)
- ⚠️ We **DON'T** protect compromised endpoints (no system can)
- ⚠️ We **DON'T** claim quantum resistance (yet - planned migration)

### 10.2 Honest User Communication

Users should understand:
1. **E2EE doesn't hide who you talk to** — Some metadata visible to servers (minimized)
2. **Bridges have different security** — Email providers see metadata, SMS carriers see plaintext
3. **Key loss is permanent** — No server-side recovery (by design - zero-knowledge)
4. **First contact has risks** — Initial key exchange could be attacked (verify fingerprints)
5. **Server operators can be compelled** — Legal requests expose metadata (but not content)
6. **We can't protect compromised devices** — Malware on your device defeats all encryption
7. **Quantum computers are a future threat** — Current crypto not quantum-resistant (migration planned)
8. **Zero-knowledge means no moderation** — We can't scan for illegal content (trade-off for privacy)

---

## 11. Incident Response

### 11.1 If Private Key Compromised

1. Generate new identity immediately
2. Notify contacts via out-of-band channel
3. Old identity should be considered burned
4. Consider publishing key revocation (future feature)

### 11.2 If Device Keys Compromised (Multi-Device)

1. Revoke compromised device key immediately
2. Other device keys remain valid
3. Master identity unaffected
4. Consider rotating master key if device had access

### 11.3 If Server Compromised

1. All metadata should be considered exposed
2. E2EE content remains protected
3. Gateway-secured content may be exposed
4. Users should rotate edges
5. Server operator should rotate server keys

---

## 12. Future Security Enhancements

### 12.1 Short-Term (Current - Phase 4-6)

- ✅ **Zero-knowledge architecture** (Complete - email bridge working)
- 🔄 **Per-conversation ephemeral keys** (In Progress - Phase 4)
- 📋 **Handle → Edge separation** (Planned - enables disposable edges)
- 📋 **Native Relay-to-Relay** (Planned - highest security communication)
- 📋 **Timestamp rounding to 5 minutes** (Planned - reduce pattern analysis)
- 📋 **Remove all IP logging** (Planned - privacy improvement)

### 12.2 Medium-Term (Phase 7-10)

- **Message padding** - Normalize sizes to prevent analysis
- **Post-quantum migration** - CRYSTALS-Kyber/Dilithium hybrid mode
- **Double ratchet** - Signal-style key ratcheting for forward secrecy
- **Key verification UI** - Fingerprint comparison, TOFU warnings
- **Proof-of-work first contact** - Spam mitigation
- **Reproducible builds** - Verify extension matches source

### 12.3 Long-Term (Future Phases)

- **Onion routing** - Multi-hop message routing for metadata protection
- **Sealed sender** - Hide sender from server during routing
- **Decentralized federation** - Multi-server redundancy
- **Group encryption** - MLS-based secure group messaging
- **Hardware key support** - YubiKey, HSM integration
- **Mix networks** - Timing obfuscation

---

## 13. Implementation Standards

See [RELAY_ETHOS.md](../RELAY_ETHOS.md) for complete implementation standards including:
- Code review checklist (zero-knowledge compliance)
- Logging standards (no PII, no plaintext)
- Database schema requirements (encryption, hashing)
- API security standards (authentication, rate limiting)
- Worker security standards (transient decryption only)
- Testing requirements (security tests mandatory)

---

## 14. Security Audit Status

| Component | Last Audit | Auditor | Status |
|-----------|------------|---------|--------|
| Protocol spec | N/A | Pending | ⏳ Needed before v1.0 |
| Security ethos | 2026-02-01 | Internal | ✅ Documented |
| Crypto library (tweetnacl) | 2016 | Cure53 | ✅ Passed (third-party) |
| Reference client | N/A | Pending | ⏳ Needed before v1.0 |
| Reference server | N/A | Pending | ⏳ Needed before v1.0 |
| Email worker | N/A | Pending | ⏳ Needed before v1.0 |

**Pre-audit status:** Currently in active development. Professional security audit required before v1.0 public release.

---

## 15. Compliance

### 15.1 GDPR Compliance

| Requirement | Implementation |
|-------------|----------------|
| Data minimization (Art. 5) | ✅ Zero-knowledge design, minimal metadata |
| Right to access (Art. 15) | ✅ User can export all encrypted data |
| Right to erasure (Art. 17) | ✅ Account deletion cascades |
| Data portability (Art. 20) | ✅ Standard JSON export format |
| Privacy by design (Art. 25) | ✅ Encryption by default, zero-knowledge |

### 15.2 Law Enforcement Requests

**What we CAN provide:**
- Encrypted message blobs (useless without user's key)
- Account creation timestamp (rounded to day)
- Edge addresses (not directly linkable to identity)
- Encrypted metadata

**What we CANNOT provide (even if compelled):**
- Plaintext message content (we don't have it)
- Decryption keys (never on server)
- User identities (architecturally separated)
- Communication partners (salted hashes)
- IP addresses (never logged)
- Precise timestamps (rounded)

**Future:** Transparency reports (aggregate data, no individual cases)

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-31 | Initial threat model |
| 1.1.0 | 2026-02-01 | Updated for zero-knowledge architecture, added ethos reference, expanded malicious server scenario |

---

**End of Threat Model**
