# Relay Protocol Threat Model

**Status:** Draft  
**Version:** 1.0.0  
**Date:** January 31, 2026  
**Authors:** Relay Foundation

---

## 1. Overview

This document describes the threat model for the Relay Protocol. It identifies adversaries, attack surfaces, and the mitigations built into the protocol and reference implementation.

**Scope:** This threat model covers:
- The Relay Protocol as specified in RELAY_PROTOCOL_v1.md
- Client implementations (extension, webapp, mobile)
- Server implementations (home servers, gateways)
- Federation between servers

**Out of scope:**
- Operating system security
- Hardware security (beyond acknowledgment)
- Physical attacks

---

## 2. Security Goals

### 2.1 Primary Goals

| Goal | Description |
|------|-------------|
| **Confidentiality** | Only intended recipients can read message content |
| **Integrity** | Messages cannot be modified without detection |
| **Authenticity** | Sender identity is cryptographically verifiable |
| **Non-repudiation** | Senders cannot deny sending signed messages |
| **Forward secrecy** | Compromise of long-term keys doesn't expose past messages |

### 2.2 Secondary Goals

| Goal | Description |
|------|-------------|
| **Availability** | Service remains accessible under attack |
| **Metadata minimization** | Limit exposure of who-talks-to-whom |
| **Anonymity preservation** | Support pseudonymous usage |
| **Honest labeling** | Users always know true security posture |

---

## 3. Trust Model

### 3.1 Entities and Trust Levels

| Entity | Trust Level | Notes |
|--------|-------------|-------|
| **User's own client** | Full | Holds private keys, decrypts content |
| **User's home server** | Partial | Sees metadata, stores encrypted blobs |
| **Counterparty's client** | Conditional | Trusted with plaintext after decryption |
| **Counterparty's server** | Minimal | Routing only, no content access for e2ee |
| **Gateway servers** | Minimal | Sees plaintext for bridged content |
| **Network infrastructure** | None | Assumed hostile (TLS protects) |

### 3.2 What We Trust Servers To Do

Home servers are trusted to:
- ✅ Route messages correctly
- ✅ Store encrypted content without tampering
- ✅ Enforce rate limits honestly
- ✅ Not inject additional metadata

Home servers are **NOT** trusted to:
- ❌ Not read message content (they can't for e2ee)
- ❌ Not log metadata (we assume they might)
- ❌ Be available forever (clients should cache)

### 3.3 Gateway Trust Model

Gateways for bridged content (email, Discord, etc.):
- **MUST** handle plaintext during bridging
- **MUST** follow minimum gateway requirements (no logging content)
- **MAY** be operated by third parties
- **CANNOT** provide e2ee guarantees

Users are informed via security level labeling that gateway-secured messages have different trust properties.

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

#### Class 3: Malicious Server Operator
**Capabilities:**
- Read stored data
- Log all metadata
- Delay or drop messages
- Inject fake messages (attempt)

**Mitigations:**
- End-to-end encryption (server sees ciphertext only)
- Client-side signature verification
- Multi-server redundancy (future)
- Client-side message caching

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

### 7.1 Server Compromise

**Scenario:** Attacker gains full access to a Relay server.

**What they get:**
- Encrypted message blobs (e2ee)
- Plaintext messages for gateway-secured content
- All metadata (sender, recipient, timestamps)
- Handle → identity mappings

**What they DON'T get:**
- Private keys (never on server)
- Ability to decrypt e2ee messages
- Ability to forge signatures

**User mitigation:**
- Use e2ee whenever possible
- Minimize metadata (use edges strategically)
- Consider self-hosting

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

| Limitation | Rationale |
|------------|-----------|
| **Full anonymity** | Not a Tor replacement; metadata visible to server |
| **Quantum resistance** | Deferred to future protocol version |
| **Perfect forward secrecy** | No Signal-style ratchet in v1 |
| **Deniability** | Signatures are intentionally non-repudiable |
| **Server availability** | Decentralized redundancy is future work |
| **Encrypted metadata** | Would require significant complexity |

### 10.2 Honest User Communication

Users should understand:
1. **E2EE doesn't hide who you talk to** — metadata is visible to servers
2. **Gateway-secured is NOT e2ee** — bridges require trust in gateway
3. **Key loss is permanent** — no recovery mechanism
4. **First contact has risks** — initial key exchange could be attacked
5. **Server operators can be compelled** — legal requests may expose metadata

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

### 12.1 Short-Term (v1.x)

- Key pinning / TOFU warnings
- Proof-of-work for first contact
- Enhanced rate limiting

### 12.2 Medium-Term (v2.x)

- Double ratchet for forward secrecy
- Group encryption (MLS-based)
- Message size padding

### 12.3 Long-Term (v3.x)

- Post-quantum algorithms
- Onion routing for metadata protection
- Sealed sender (hide sender from server)

---

## 13. Security Audit Status

| Component | Last Audit | Auditor | Status |
|-----------|------------|---------|--------|
| Protocol spec | N/A | Pending | ⏳ Not started |
| Crypto library (tweetnacl) | 2016 | Cure53 | ✅ Passed |
| Reference client | N/A | Pending | ⏳ Not started |
| Reference server | N/A | Pending | ⏳ Not started |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-31 | Initial threat model |

---

**End of Threat Model**
