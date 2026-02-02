# Relay Security & Privacy Ethos

**Version:** 1.0  
**Last Updated:** February 1, 2026  
**Status:** Living Document

---

## Mission Statement

**Relay is your private communications perimeter.**

We build a secure, zero-knowledge communication infrastructure that protects user privacy even in worst-case scenarios. Our architecture ensures that servers, operators, and attackers with full system access cannot determine:
- Who is communicating with whom
- What messages contain
- User identities behind handles or edges
- Communication patterns or relationships

Relay is not just encrypted messaging—it's a **fundamental shift in trust assumptions**. Users should trust Relay's architecture, not its operators.

---

## Core Principles

### 1. Zero-Knowledge by Default
**Principle:** The server learns nothing about user communications except what is mathematically unavoidable.

**What this means:**
- Message content is always encrypted client-side
- Server cannot decrypt any user data
- Recipient identities are hidden from server
- Handles are not directly linkable to identities
- Metadata is minimized or eliminated where possible

**Red lines:**
- ❌ NEVER store plaintext message content
- ❌ NEVER store plaintext recipient addresses
- ❌ NEVER store keys that could decrypt user data
- ❌ NEVER log sensitive user actions in plaintext

### 2. Cryptographic Protection
**Principle:** Use battle-tested, audited cryptographic primitives correctly.

**Commitments:**
- X25519-XSalsa20-Poly1305 (NaCl box) for message encryption
- Ed25519 for digital signatures
- Proper random number generation (crypto.getRandomValues)
- Authenticate before decrypt (AEAD only)
- No custom crypto - use TweetNaCl/libsodium implementations

**Red lines:**
- ❌ NEVER implement custom cryptography
- ❌ NEVER use deprecated algorithms (MD5, SHA-1, RC4, etc.)
- ❌ NEVER skip authentication on encrypted data
- ❌ NEVER reuse nonces

### 3. Minimal Metadata
**Principle:** Minimize metadata collection and retention. Metadata reveals patterns even when content is encrypted.

**What we DO store (minimum viable):**
- User account creation timestamp (rounded to day)
- Encrypted message content
- Encrypted conversation key material
- Edge addresses (not linkable to identities without database compromise)
- Coarse-grained message timestamps (rounded to nearest 5 minutes)
- Message delivery status (sent/delivered/failed)

**What we DON'T store:**
- Plaintext message content
- Plaintext recipient addresses
- IP addresses (not logged, not stored)
- Device fingerprints
- Precise timestamps (rounded to reduce pattern analysis)
- User agents or browser details
- Geographic location data
- Social graphs (who talks to whom)
- Message read receipts (optional client-side only)
- Typing indicators
- Online/offline status

**Timestamp handling:**
- Round all timestamps to nearest 5 minutes on server
- Clients can track precise times locally
- Prevents timing correlation attacks
- Reduces communication pattern leakage

**Red lines:**
- ❌ NEVER log IP addresses (even in error logs)
- ❌ NEVER store precise communication patterns
- ❌ NEVER build social graphs on server
- ❌ NEVER track user behavior beyond absolute necessities

### 4. Architectural Isolation
**Principle:** System architecture prevents data correlation even if database is fully compromised.

**Handle → Edge Separation:**
```
Identity (user account, encrypted)
  └─> Handle (persistent, @username)
      └─> Edge (disposable, bridge endpoint)
          └─> Conversation (encrypted)
              └─> Messages (encrypted)
```

**Key architectural requirements:**
- Edges cannot be traced to identities without multiple table joins AND decryption
- Handles are not stored in plaintext associated with identity keys
- Conversation participants use salted hashes (not reversible)
- External IDs (email addresses, Discord IDs) are encrypted in edges.metadata
- No foreign keys directly linking edges to identities

**Database compromise scenario:**
- Attacker gains full database read access
- Can see: encrypted messages, edge addresses, conversation IDs, rounded timestamps
- Cannot determine: who sent messages, who received messages, message content, user identities
- Cannot link: handles to real identities, edges to specific users, conversations to participants

**Red lines:**
- ❌ NEVER store direct identity → edge links
- ❌ NEVER store plaintext external IDs (email, phone, Discord username)
- ❌ NEVER use predictable IDs (use UUIDs)
- ❌ NEVER store decryption keys server-side

### 5. Client-Side Encryption
**Principle:** All encryption and decryption happens on the client. Server is a dumb storage layer.

**Client responsibilities:**
- Generate and manage all encryption keys
- Encrypt messages before sending to server
- Decrypt messages after receiving from server
- Derive encryption keys from user secrets
- Validate signatures on received data

**Server responsibilities:**
- Store encrypted data
- Route encrypted messages
- Provide encrypted data on request
- Verify authenticated requests (identity via JWT)
- NEVER access plaintext data

**Red lines:**
- ❌ NEVER decrypt on server
- ❌ NEVER generate user keys on server
- ❌ NEVER send plaintext to server
- ❌ NEVER trust server with sensitive operations

### 6. Forward Secrecy
**Principle:** Compromise of current keys does not compromise historical messages.

**Implementation (Phase 4 - In Progress):**
- Per-conversation ephemeral keys (not identity keys)
- Key rotation after N messages
- Old keys deleted after rotation
- Double Ratchet algorithm for ongoing conversations

**Benefits:**
- Past messages safe even if current key compromised
- Conversation isolation (one conversation breach ≠ all conversations)
- Stronger security model than identity-key-only

**Red lines:**
- ❌ NEVER reuse conversation keys across conversations
- ❌ NEVER skip key rotation
- ❌ NEVER retain old keys unnecessarily

### 7. Transparency & Auditability
**Principle:** Users should be able to verify Relay's security claims.

**Commitments:**
- Open source core cryptography code
- Published protocol specification (relay-protocol)
- Documented threat model
- Public security audits (before v1.0)
- Reproducible builds (future)
- Bug bounty program (future)

**Red lines:**
- ❌ NEVER hide security-critical code
- ❌ NEVER make unverifiable claims
- ❌ NEVER obscure threat model limitations

### 8. Defense in Depth
**Principle:** Multiple layers of protection. Assume every component can fail.

**Layers:**
1. **Cryptography:** Even if server compromised, data stays encrypted
2. **Authentication:** Even if network intercepted, requests are signed
3. **Isolation:** Even if one conversation compromised, others safe
4. **Key separation:** Even if worker key leaked, user keys safe
5. **Bridge isolation:** Even if bridge compromised, Relay infrastructure safe

**Red lines:**
- ❌ NEVER rely on single point of security
- ❌ NEVER assume server is trustworthy
- ❌ NEVER assume network is secure
- ❌ NEVER assume client is uncompromised (but minimize impact)

---

## Technical Implementation Standards

### Encryption Standards

**Message Encryption:**
```typescript
// Per-conversation ephemeral keys (Phase 4)
conversationKey = generateX25519KeyPair()
encryptedConversationKey = nacl.box(
  conversationKey.secretKey,
  identityPublicKey,
  identitySecretKey
)

// Message encryption with conversation key
encryptedMessage = nacl.box(
  messageContent,
  recipientConversationPublicKey,
  senderConversationSecretKey
)
```

**Key Derivation:**
```typescript
// Identity key from user secret (Ed25519)
identityKeyPair = nacl.sign.keyPair.fromSeed(userSecret)

// Encryption keys derived from identity key (X25519)
encryptionKeyPair = deriveX25519FromEd25519(identityKeyPair)
```

**Stored Encrypted Fields:**
- `messages.encrypted_content` - Full message payload
- `edges.metadata.external_id` - Bridge-specific IDs (email, Discord ID, etc.)
- `edges.metadata.credentials` - API tokens, OAuth secrets
- `conversations.encrypted_key_material` - Per-conversation keys

### Database Security Standards

**What goes in the database:**
```sql
-- ACCEPTABLE (encrypted or non-sensitive)
messages.encrypted_content          -- Fully encrypted
messages.conversation_id            -- UUID (not reversible)
messages.created_at                 -- Rounded to 5 minutes
messages.status                     -- Delivery status only

-- ACCEPTABLE (hashed or derived)
conversation_participants.external_hash  -- SHA-256(salt + email), not reversible

-- UNACCEPTABLE (would violate zero-knowledge)
-- messages.plaintext_content       ❌ Never!
-- edges.email_address              ❌ Must be encrypted in metadata
-- conversation_participants.email  ❌ Use hash only
-- users.last_login_ip              ❌ No IP logging
```

**Encryption in database:**
- All sensitive fields use per-edge or per-identity encryption keys
- Server cannot decrypt without user's key
- Fields stored as TEXT containing JSON: `{ ephemeralPubkey, nonce, ciphertext }`

**Queries must not leak patterns:**
```sql
-- BAD: Leaks communication pattern
SELECT sender_id, recipient_id, timestamp FROM messages;

-- GOOD: Only conversation ID (unlinkable without decryption)
SELECT encrypted_content, conversation_id FROM messages WHERE conversation_id = $1;
```

### API Security Standards

**Authentication:**
- JWT tokens for user authentication (short-lived, 1 hour)
- Ed25519 signatures for worker-to-server communication
- No API keys in URLs (use Authorization header)
- Rate limiting per identity (not per IP, avoids logging IPs)

**Request/Response:**
```typescript
// Client sends encrypted content only
POST /v1/messages {
  conversationId: "uuid",
  encryptedContent: "base64...", // Server cannot read
  ephemeralPubkey: "base64...",
  nonce: "base64..."
}

// Server returns encrypted content only
GET /v1/messages?conversationId=uuid {
  messages: [{
    id: "uuid",
    encryptedContent: "base64...", // Server cannot read
    createdAt: "2026-02-01T12:35:00Z", // Rounded
    status: "delivered"
  }]
}
```

**What APIs NEVER return:**
- Plaintext message content
- Plaintext recipient addresses
- User IP addresses
- Precise timestamps
- Decryption keys

### Worker Security Standards

**Cloudflare Worker Zero-Knowledge Design:**

The email worker is a critical component that temporarily handles plaintext data (recipient email addresses) for external bridge communication. Security requirements:

**Transient Decryption Only:**
```typescript
// Worker decrypts recipient transiently
const recipientEmail = decryptRecipient(
  encryptedRecipient, 
  workerPrivateKey
);

// Use immediately
await sendEmail(recipientEmail, content);

// Explicit memory clearing (JS GC handles this, but document intent)
recipientEmail = null;

// NEVER log plaintext
console.log(`Email sent to ${recipientEmail.substring(0, 3)}***`);
//                            ^-- Only log partial for debugging
```

**Worker Security Requirements:**
- ✅ Decrypt only what's necessary (recipient address, not message content)
- ✅ Use immediately and discard
- ✅ Never log plaintext values
- ✅ Verify cryptographic signatures on all requests
- ✅ Separate encryption keys per worker type
- ❌ Never store decrypted data
- ❌ Never send plaintext back to server
- ❌ Never log full values (use partial masking)

**Worker Rotation:**
- Rotate worker encryption keys annually
- Provision new keys before rotation
- Deprecate old keys after overlap period
- Document rotation in security audit log

### Logging Standards

**Acceptable logging:**
```
✅ "User authenticated successfully"
✅ "Message delivery failed: Resend API error 429"
✅ "Conversation created: uuid-123"
✅ "Edge deleted: uuid-456"
✅ "Worker signature verification passed"
```

**Unacceptable logging:**
```
❌ "User 127.0.0.1 authenticated"
❌ "Message sent to bob@example.com"
❌ "Decrypted content: Hello world"
❌ "Edge xyz123@rlymsg.com belongs to user Alice"
❌ "Conversation between uuid-123 and uuid-456"
```

**Error logging:**
- Scrub all PII from stack traces before sending to error tracking (Sentry)
- Never include decrypted data in error messages
- Mask sensitive values (show first 3 chars only)
- Use error codes instead of descriptive messages with PII

**Log retention:**
- Application logs: 7 days maximum
- Security audit logs: 90 days (authentication, key operations)
- Error logs: 30 days
- No long-term user behavior logging

---

## Threat Model

### What We Protect Against

**1. Passive Server Compromise**
- Attacker gains read-only database access
- **Result:** Sees encrypted data, cannot decrypt
- **Mitigation:** Client-side encryption, minimal metadata

**2. Active Server Compromise**
- Attacker gains full server control (RCE, database, etc.)
- **Result:** Can see new messages if intercept during routing, but cannot decrypt stored messages
- **Mitigation:** End-to-end encryption, forward secrecy, client verification of server responses

**3. Network Interception (MITM)**
- Attacker intercepts TLS traffic (compromised CA, etc.)
- **Result:** Sees encrypted payloads, cannot decrypt
- **Mitigation:** Application-layer encryption on top of TLS

**4. Malicious Relay Server Operator**
- Server operator tries to spy on users
- **Result:** Cannot decrypt messages or identify users
- **Mitigation:** Zero-knowledge architecture, no server-side keys

**5. Law Enforcement / Government Request**
- Server receives legal demand for user data
- **Result:** Can only provide encrypted data (useless without client key)
- **Mitigation:** No plaintext data to provide, transparent warrant canary (future)

**6. Bridge Compromise (Email, Discord, etc.)**
- External bridge provider (Resend, Discord API) compromised
- **Result:** Bridge provider sees metadata (sender bridge address, timing), but NOT message content or internal Relay identity
- **Mitigation:** Message content encrypted even before sending to bridge, bridges can't link to Relay identity

**7. Metadata Analysis**
- Attacker analyzes communication patterns (timing, frequency, sizes)
- **Result:** Some pattern leakage unavoidable (rounded timestamps)
- **Mitigation:** Timestamp rounding, padding (future), mix networks (future)

### What We DON'T Protect Against

**Be honest about limitations:**

**1. Compromised Client Device**
- If user's device is compromised (malware, keylogger), all bets are off
- Attacker can steal keys, read messages before encryption
- **Why:** Relay cannot protect against endpoint compromise
- **Mitigation:** User responsibility to secure devices, potential future HSM/hardware key support

**2. Malicious Client**
- User installs compromised/unofficial Relay client
- **Why:** Cannot prevent users from running untrusted code
- **Mitigation:** Code signing, reproducible builds, open source verification

**3. Social Engineering**
- Attacker tricks user into sharing keys or revealing identity
- **Why:** No technical solution for human vulnerabilities
- **Mitigation:** User education, clear security warnings

**4. External Bridge Metadata**
- Email provider (Gmail) sees user's email address and timing
- Discord sees user's Discord account and messages
- **Why:** Bridges are external, we can't control their logging
- **Mitigation:** Clear disclosure that bridges have metadata, encourage using disposable edge addresses

**5. Traffic Analysis (Advanced)**
- Sophisticated timing/pattern analysis can reveal relationships
- **Why:** Some metadata leakage is unavoidable without significant UX degradation
- **Mitigation:** Timestamp rounding, future padding/delays, mix networks

**6. Quantum Computer Attacks (Future)**
- X25519/Ed25519 vulnerable to quantum attacks
- **Why:** Current crypto not quantum-resistant
- **Mitigation:** Plan migration to post-quantum crypto (CRYSTALS-Kyber/Dilithium) when standardized and audited

---

## Bridge Security Matrix

Bridges connect Relay to external platforms. Each bridge has different security characteristics:

| Bridge | Relay Encryption | Bridge Sees Content | Bridge Sees Identity | Recommended Use |
|--------|------------------|---------------------|---------------------|-----------------|
| **Native** (Relay→Relay) | ✅ Full E2E | ❌ Never | ❌ Never | Default, highest security |
| **Email** | ✅ Content encrypted | ❌ No* | ⚠️ Edge address only** | Disposable edges recommended |
| **Discord** | ✅ Content encrypted | ❌ No* | ⚠️ Bot account | Use dedicated bot account |
| **Telegram** | ✅ Content encrypted | ❌ No* | ⚠️ Bot account | Use dedicated bot account |
| **Slack** | ✅ Content encrypted | ❌ No* | ⚠️ Workspace identity | Professional use only |
| **SMS** | ✅ Content encrypted | ⚠️ Carrier sees plaintext*** | ⚠️ Phone number | Least secure, avoid if possible |
| **Signal** | ✅ Double encrypted**** | ⚠️ Signal sees encrypted | ⚠️ Phone number | Good but complex setup |

**Notes:**
- \* Bridge provider sees encrypted ciphertext, cannot decrypt
- \*\* Email bridge only sees edge address (xyz123@rlymsg.com), not linked to user identity
- \*\*\* SMS is NOT end-to-end encrypted by carriers, only Relay's layer protects content
- \*\*\*\* Signal has its own E2E encryption, Relay adds another layer

**User guidance:**
- **High security needs:** Use native Relay-to-Relay
- **Medium security:** Email/Discord/Telegram with disposable edges
- **Low security (convenience):** SMS for reaching non-tech-savvy users
- **Never use SMS for sensitive communications** - carrier can see plaintext

---

## Development Guidelines

### Code Review Checklist

Every code change must answer YES to all:

- [ ] Does this maintain zero-knowledge? (Server cannot read user data)
- [ ] Is encryption client-side? (No server-side decryption)
- [ ] Are all sensitive fields encrypted in database?
- [ ] Are timestamps rounded appropriately?
- [ ] Are there no IP addresses in logs?
- [ ] Are error messages free of PII?
- [ ] Does this minimize metadata collection?
- [ ] Is this using audited crypto libraries? (TweetNaCl/libsodium)
- [ ] Are nonces generated randomly and never reused?
- [ ] Is authentication required before decryption? (AEAD)
- [ ] Could this expose user identity linkage?
- [ ] Are API responses free of sensitive metadata?

**If ANY answer is NO, the code MUST be revised.**

### Testing Requirements

**Security tests MUST include:**
- Verify encrypted data cannot be decrypted server-side
- Verify API responses don't leak metadata
- Verify timestamps are rounded
- Verify signatures are validated
- Verify authentication is required
- Verify rate limiting works without IP logging
- Verify no plaintext in logs (grep for sensitive patterns)

**Threat model testing:**
- Simulate database compromise (can attacker decrypt?)
- Simulate network interception (can attacker read content?)
- Simulate malicious server operator (what can they learn?)

### Feature Development Process

**Before implementing ANY feature:**

1. **Evaluate against ethos:**
   - Does this maintain zero-knowledge?
   - What metadata does this create?
   - Can this be done client-side instead of server-side?
   - How does this affect the threat model?

2. **Privacy impact assessment:**
   - What new data is stored?
   - Who can access it?
   - How long is it retained?
   - Can it be correlated with other data?

3. **Document trade-offs:**
   - If feature requires metadata, document why it's necessary
   - Explore alternatives that minimize metadata
   - Get approval for any new metadata storage

4. **Update threat model:**
   - How does this change attack surface?
   - Update RELAY_THREAT_MODEL.md accordingly

**Example - Adding "Read Receipts":**
- ❌ BAD: Server tracks when messages are read → metadata leakage
- ✅ GOOD: Client sends encrypted "read" status to sender → no server metadata

---

## Trade-Off Decision Framework

Some features create tension between security/privacy and usability. Use this framework:

### Security vs Usability Trade-Offs

**Non-Negotiable (Security Wins):**
- Message content encryption (zero-knowledge)
- Recipient identity encryption (zero-knowledge)
- No IP logging (privacy)
- Client-side key generation (security)
- No backdoors (transparency)

**Negotiable (Balance Required):**
- Timestamp precision (privacy vs UX)
  - **Decision:** Round to 5 minutes (good balance)
- Account recovery (security vs UX)
  - **Decision:** No recovery by default, optional encrypted backup (user choice)
- Search functionality (privacy vs UX)
  - **Decision:** Client-side search only (slower but private)
- Multi-device sync (security vs UX)
  - **Decision:** Device-to-device key exchange via QR (complex but secure)

**Allowed (UX Wins with Safeguards):**
- Error reporting (UX)
  - **Safeguard:** Scrub all PII from reports
- Performance monitoring (UX)
  - **Safeguard:** Aggregate metrics only, no per-user tracking
- Feature usage analytics (UX)
  - **Safeguard:** Anonymous, aggregated, user opt-out

### Decision Process

When evaluating trade-offs:

1. **Default to privacy/security** - Bias toward user protection
2. **Explore alternatives** - Can we achieve UX goal without compromise?
3. **Minimize harm** - If compromise needed, minimize data collected
4. **User control** - Let users opt-in to convenience features
5. **Transparency** - Clearly document what data is collected and why
6. **Reversibility** - Can user delete/export data? Can we reduce collection later?

**Example:**
- **Feature:** Auto-complete for recipient addresses (UX improvement)
- **Privacy concern:** Requires server to know user's contact list
- **Evaluation:** 
  - ❌ Server-stored contacts: Violates zero-knowledge
  - ✅ Client-side storage: Maintains privacy, slightly less convenient
  - **Decision:** Client-side only, accept UX limitation

---

## User-Facing Communication

### How We Explain Relay to Users

**Marketing message:**
> "Relay is your private communications perimeter. Like a VPN for your conversations, Relay creates a secure barrier between your private communications and the outside world. Your messages, contacts, and identity stay encrypted and private—even we can't read them."

**Key points to emphasize:**
- 🔒 **End-to-end encrypted** - Only you can read your messages
- 🕵️ **Zero-knowledge** - We can't see who you're talking to or what you're saying
- 🎭 **Anonymous by design** - No connection between your identity and your edges
- 🗑️ **Disposable addresses** - Create and destroy edges without affecting your identity
- 🌉 **Bridge safely** - Connect to email, Discord, Telegram while staying private

**What we DON'T claim:**
- ❌ "Completely anonymous" (external bridges have metadata)
- ❌ "Unhackable" (endpoint security is user's responsibility)
- ❌ "Impossible to crack" (quantum computing future threat)
- ❌ "No metadata ever" (some metadata unavoidable, but minimized)

**Honest limitations:**
- External bridges (email, SMS) see some metadata
- We cannot protect compromised devices
- Sophisticated traffic analysis could reveal patterns
- Quantum computers may break current crypto (future concern)

### Security Disclosures

**Transparency with users:**
- Clear explanation of what data we store
- Honest about threat model limitations
- Disclose when external bridges are used
- Explain what happens in worst-case compromise
- Provide data export and deletion tools

**Security page content (relay.com/security):**
- How encryption works (simplified)
- What data we store (encrypted messages, nothing else)
- What happens if we're hacked (they get encrypted data only)
- What happens with law enforcement request (we have nothing to give)
- How to verify our claims (open source, audits)
- Bug bounty program (future)

---

## Compliance & Legal

### Law Enforcement Requests

**Our position:**
- We cannot decrypt user data (zero-knowledge design)
- We cannot identify who is communicating with whom
- We can only provide what we have: encrypted data

**Response to legal requests:**
1. Verify validity of request
2. Inform user if legally permitted
3. Provide only what is technically possible:
   - Encrypted message content (useless without user key)
   - Account metadata (creation date, rounded)
   - Edge addresses (not linkable to identity without database + keys)
4. Push back on overly broad requests
5. Publish transparency reports (aggregate data, no individual cases)

**What we CANNOT provide (even if compelled):**
- Plaintext message content (we don't have it)
- Decryption keys (we don't have them)
- Communication partners (we don't know them)
- IP addresses (we don't log them)
- Precise timestamps (we only have rounded versions)

### GDPR / Privacy Regulations

**Data minimization (GDPR Article 5):**
- ✅ We collect minimal data necessary
- ✅ We retain data only as long as needed
- ✅ User can export all their data (encrypted)
- ✅ User can delete account and all data

**Right to be forgotten:**
- User can delete account → cascades to all edges, conversations, messages
- Encrypted messages deleted from database
- No backups retained after standard retention period (30 days)
- No residual data links user to past communications

**Data portability:**
- User can export:
  - Encrypted messages (in standard JSON format)
  - Edge configurations
  - Conversation metadata
  - Encrypted conversation keys
- Export includes decryption instructions for use outside Relay

### Content Moderation Challenges

**Problem:** We can't see message content, so we can't moderate.

**Our approach:**
- Client-side reporting: User can report another user
- Server can ban accounts/edges based on reports
- Cannot scan for illegal content (we can't see it)
- Rely on external bridge moderation (email providers, Discord, etc.)

**For CSAM and illegal content:**
- Clear Terms of Service prohibiting illegal use
- Report abuse mechanism (user-initiated)
- Cooperate with authorities when users are reported
- Accept that zero-knowledge means we can't proactively scan

**This is a fundamental trade-off:**
- Strong privacy = No content scanning
- Users must self-moderate and report abuse
- Law enforcement must investigate via traditional means

---

## Future Enhancements

### Roadmap for Improved Privacy

**Phase 5: Padding and Timing Obfuscation**
- Pad all messages to fixed sizes (e.g., 512 bytes, 2KB, 8KB tiers)
- Prevents message size analysis
- Optional random delays (prevent timing analysis)

**Phase 6: Mix Networks**
- Route messages through multiple Relay nodes
- Prevents traffic analysis by single server
- Inspired by Tor/Mixmaster design

**Phase 7: Post-Quantum Cryptography**
- Migrate to CRYSTALS-Kyber (key exchange)
- Migrate to CRYSTALS-Dilithium (signatures)
- Hybrid approach (classic + PQ) during transition

**Phase 8: Decentralization**
- Relay Protocol enables multiple Relay servers
- Users choose their server (or self-host)
- Federation like email, but encrypted
- No central authority

**Phase 9: Hardware Security Module (HSM) Support**
- Store keys in hardware tokens (YubiKey, etc.)
- Stronger protection against malware
- Air-gapped signing

**Phase 10: Reproducible Builds**
- Users can verify extension binary matches source code
- Prevents supply chain attacks
- Builds from CI/CD are bit-for-bit identical

---

## Ethos Compliance Checklist

Use this before merging any code:

### Zero-Knowledge Compliance
- [ ] Server cannot decrypt user data
- [ ] Server cannot identify communication partners
- [ ] All sensitive data encrypted client-side
- [ ] No plaintext in database

### Metadata Minimization
- [ ] Timestamps rounded to 5 minutes
- [ ] No IP addresses logged
- [ ] No user behavior tracking
- [ ] No social graph construction

### Cryptographic Security
- [ ] Using TweetNaCl/libsodium
- [ ] Nonces generated randomly
- [ ] Authentication before decryption (AEAD)
- [ ] No custom crypto

### Architectural Isolation
- [ ] No direct identity → edge links
- [ ] UUIDs for all IDs (not sequential)
- [ ] Hashed external IDs
- [ ] No reversible metadata

### Logging & Error Handling
- [ ] No PII in logs
- [ ] Error messages scrubbed
- [ ] Stack traces don't leak sensitive data
- [ ] Log retention < 30 days

### API Security
- [ ] Authentication required
- [ ] Rate limiting (no IP-based)
- [ ] No sensitive data in responses
- [ ] Proper CORS configuration

### Documentation
- [ ] Threat model updated
- [ ] Privacy impact assessed
- [ ] Trade-offs documented
- [ ] User-facing security docs updated

---

## Conclusion

**Relay's ethos is simple: Build systems that don't require trust.**

Users should not have to trust Relay operators, servers, or infrastructure. The architecture itself should guarantee privacy, even if every component is compromised.

This is not just good security—it's respect for user autonomy. Private communication is a fundamental right, and Relay exists to protect it.

**Every line of code we write must honor this mission.**

---

**Questions or concerns about this ethos?**  
Open an issue in relay-workspace or discuss in team meetings. This is a living document—update it as we learn and grow.

**Remember:** When in doubt, choose privacy. We can always add features, but we can never undo privacy violations.
