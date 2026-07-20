# ADVICE: Scope the crypto-seam rewrite (SOW §3.2) — AEAD/header-protection re-pointing and key-update ratchet deletion

Status: **SCOPE ONLY — no production code written or modified by this document.** This is a design/
scope document for board review before any implementation agent touches
`ConnectionSecrets.java`, `CryptoStream.java`, `QuicPacket.java`, the packet parsers,
`KeyUpdateSupport`, or `ShortHeaderPacket`. It follows the concreteness convention established by
`ADVICE-CertificateSelectorTest-RSA-Fixture-Fix-2026-07-20.md` (read as a model): exact file/line
citations, exact method signatures actually read from source (not paraphrased), explicit open
questions, no hand-waving.

Everything below was produced by reading, in full: `SOW-Kwik-JSSE-QUIC-TLS-Transport.md`;
`core/src/main/java/tech/kwik/core/tls/QuicTlsPort.java` and `QuicTlsPortImpl.java`;
`core/src/main/java/tech/kwik/core/crypto/ConnectionSecrets.java`, `CryptoStream.java`,
`KeyUpdateSupport.java`, `Aead.java`, `BaseAeadImpl.java`, `MissingKeysException.java`,
`SecureHash.java` (util); `core/src/main/java/tech/kwik/core/packet/QuicPacket.java`,
`ShortHeaderPacket.java`, `PacketParser.java`, `ClientRolePacketParser.java`,
`ServerRolePacketParser.java`, `RetryPacket.java` (partial, integrity-tag section);
`core/src/main/java/module-info.java`; the relevant call sites in
`core/src/main/java/tech/kwik/core/impl/QuicConnectionImpl.java`,
`QuicClientConnectionImpl.java`, `core/src/main/java/tech/kwik/core/server/impl/ServerConnectorImpl.java`,
`ServerConnectionCandidate.java`, `ServerConnectionImpl.java`, and
`core/src/main/java/tech/kwik/core/send/SenderImpl.java`; the test files
`ConnectionSecretsTest.java`, `CryptoStreamTest.java` (imports/setup), `CryptoTestUtils.java`,
`TestUtils.java` (crypto helper); and — because kwik's crypto seam cannot be scoped correctly
without knowing what the real engine actually does internally, not just what its public interface
says — the DirtyChai engine implementation source, **read-only, per this task's isolation
safeguard** (`jdk.internal.net.quic.QuicTLSEngine.java`, `QuicOneRttContext.java`, and
`sun.security.ssl.QuicTLSEngineImpl.java` / `QuicKeyManager.java`, all under
`/home/user/GitHub/DirtyChai/src/java.base/share/classes/`). No DirtyChai file was written to.

---

## 1. Full current-state inventory

### 1.1 `ConnectionSecrets.java` (`core/src/main/java/tech/kwik/core/crypto/ConnectionSecrets.java`)

Owns two `AtomicReferenceArray<Aead>` (one per `EncryptionLevel`, client and server side) plus
`originalClientInitialSecret` (Retry dual-retention, see §6). Concretely:

- **Raw secrets pulled from agent15**: `computeHandshakeSecrets(TrafficSecrets, CipherSuite)`
  (`:209`) calls `tlsTrafficSecrets.getClientHandshakeTrafficSecret()` /
  `.getServerHandshakeTrafficSecret()`; `computeApplicationSecrets(TrafficSecrets)` (`:224`) calls
  `.getClientApplicationTrafficSecret()` / `.getServerApplicationTrafficSecret()`;
  `computeEarlySecrets(TrafficSecrets, CipherSuite, Version)` (`:163`) calls
  `.getClientEarlyTrafficSecret()`. `TrafficSecrets` is `tech.kwik.agent15.engine.TrafficSecrets`.
- **kwik's own HKDF key derivation**: `computeInitialSecret(Version)` (`:146`) does
  `HKDF.fromHmacSha256().extract(initialSalt, originalDestinationConnectionId)` — this is the
  RFC 9001 §5.2 Initial-secret derivation, using `at.favre.lib.hkdf`. `createKeys(...)` (`:169`)
  builds concrete `Aead` objects (`Aes128Gcm` / `Aes256Gcm` / `ChaCha20`, chosen by cipher suite)
  from each secret; those constructors (`BaseAeadImpl`, read in full) do the actual
  HKDF-Expand-Label calls (`hkdfExpandLabel`, `:148`) to derive `key`/`iv`/`hp` per RFC 9001 §5.1/5.4.
- **Key-update wrapping**: at `App` level only, `createKeys` (`:195-203`) wraps both client and
  server `Aead`s in `KeyUpdateSupport` and cross-registers them via `setPeerAead` — see §2.
- **Public API surface consumed elsewhere**: `getClientAead` / `getServerAead` / `getPeerAead` /
  `getOwnAead` (role-relative) / `getOriginalClientInitialAead` / `discardKeys(EncryptionLevel)`.
  `MissingKeysException` (read in full, `core/src/main/java/tech/kwik/core/crypto/MissingKeysException.java`)
  is thrown by all the getters when a level's `Aead` is null, carrying a `Cause` enum
  (`MissingKeys` / `DiscardedKeys`) — this maps directly to the port's own
  `QuicKeyUnavailableException` plus `keysAvailable(KeySpace)` / `discardKeys(KeySpace)`, so the
  exception-cause distinction is preservable, not lost, in the rewrite (see §4).

### 1.2 `CryptoStream.java` — **SOW imprecision: this file is not part of the AEAD/key seam**

`CryptoStream.java` is named as a §3.2 "file" in the SOW, but having read it in full, it contains
**zero** AEAD, HKDF, or key-derivation code. Its entire job is: reassemble raw CRYPTO-frame bytes
into complete TLS handshake messages (the `add(CryptoFrame)` state machine, `:106-164`), parse them
via agent15's `TlsMessageParser` (`:201-212`), and dispatch typed `HandshakeMessage` objects to a
`TlsEngine` (`sendTo(HandshakeMessage, TlsEngine)`, `:337-349`, a manual `instanceof` cascade over
`ClientHello`/`ServerHello`/`EncryptedExtensions`/`CertificateMessage`/`CertificateVerifyMessage`/
`FinishedMessage`/`NewSessionTicketMessage`/`CertificateRequestMessage`). `CryptoStreamTest.java`
(read: imports/setup) confirms this empirically — every import is agent15 message types
(`ClientHello`, `FinishedMessage`, `CertificateMessage`, mocked `TlsEngine`); there is no AEAD or
secret material anywhere in the 619-line test file.

This is squarely the **message-object vs. byte-oriented pull model** impedance the SOW's own §7.1
already scoped as a *driver-seam* (§3.3) concern: "`CryptoStream` parses raw CRYPTO into typed TLS
messages... the JDK `QuicTLSEngine` is byte-oriented — feed `consumeHandshakeBytes`, pull
`getHandshakeBytes`." §7.2's effort table even lists "`CryptoStream` → byte pipe (keep reassembly,
delete TLS-message parsing)" as its own line, separate from the "Delete `ConnectionSecrets`
AEAD/HKDF" line. **Recommendation: `CryptoStream.java` should be scoped and staged under §3.3
(handshake-driver seam), not under this crypto-seam (§3.2) rewrite.** It is listed here only
because this task's brief named it explicitly; nothing below treats it as in-scope for the AEAD/
key-update rewrite, and no crypto-seam implementation step in §7 of this document touches it. Flag
this as a correction for whoever next revises the SOW's §3.2 file list.

### 1.3 `QuicPacket.java` — the actual two-step protect/unprotect choke point

Confirmed by reading `LongHeaderPacket.java`, `ShortHeaderPacket.java`, `RetryPacket.java`,
`VersionNegotiationPacket.java` line-by-line for their `generatePacketBytes`/`parse` methods: **all
concrete packet types except `RetryPacket` and `VersionNegotiationPacket` funnel through the same
two `QuicPacket`-base-class methods**, so `QuicPacket.java` is genuinely the single rewrite site for
protect/unprotect, not one of several:

- **Unprotect (receive path)**: `parsePacketNumberAndPayload(ByteBuffer, int, byte, int, Aead, long, Logger)`
  (`:108-217`). Sequence, with exact line numbers:
  1. Sample 16 bytes at `packetNumberStart + 4` (`:120-134`, RFC 9001 §5.4.2/5.4.3).
  2. `createHeaderProtectionMask(sample, aead)` (`:139`) → `aead.createHeaderProtectionMask(sample)`.
  3. XOR-unmask flags + packet number (`:144-172`).
  4. `decodePacketNumber(...)` (`:177`).
  5. Reconstruct `frameHeader` as AAD (`:184-192`).
  6. `decryptPayload(payload, frameHeader, packetNumber, aead)` (`:205`) → builds a 12-byte nonce by
     XOR-ing the packet number into `aead.getIv()` (`:264-278`), calls
     `aead.checkKeyPhase(((ShortHeaderPacket) this).keyPhaseBit)` **only if `this instanceof
     ShortHeaderPacket`** (`:268-269`) — i.e. key-phase checking is short-header/App-level only, as
     expected — then `aead.aeadDecrypt(associatedData, message, nonce)`.
  7. `parseFrames(frameBytes, log)` (`:209`).
- **Protect (send path)**: `protectPacketNumberAndPayload(ByteBuffer, int, ByteBuffer, int, Aead)`
  (`:449-491`). Sequence: build AAD from the buffer written so far (`:456-459`), `encryptPayload(...)`
  (`:464`) → same IV-XOR-nonce construction, `aead.aeadEncrypt(...)`, then
  `createHeaderProtectionMask(encryptedPayload, pnLength, aead)` (`:469`, the 4-argument overload at
  `:227-239`, which re-derives the 16-byte sample from the *already-encrypted* payload/tag at a
  computed offset) to mask the packet number and flags bits (`:471-485`).
- **`ShortHeaderPacket`-specific key-phase plumbing** (`ShortHeaderPacket.java`, read in full):
  `setUnprotectedHeader` (`:106-108`) extracts `keyPhaseBit` from the decrypted flags byte on
  receive; `generatePacketBytes` (`:136-169`) reads `keyPhaseBit = aead.getKeyPhase()` (`:148`)
  **before** building the header, then encodes it into the flags byte, then calls
  `protectPacketNumberAndPayload`. `parse` (`:68-94`) calls `aead.confirmKeyUpdateIfInProgress()`
  on successful decrypt (`:85`) or `aead.cancelKeyUpdateIfInProgress()` on `DecryptionException`
  (`:88`) — this is the transport-side half of the key-update ratchet the WARN is about (§2).

### 1.4 The packet parsers — `ClientRolePacketParser.java` / `ServerRolePacketParser.java`

Both extend the abstract `PacketParser.java` (read in full) and implement only
`getAead(QuicPacket, ByteBuffer)` — **neither does any AEAD/HKDF work itself**; their entire job is
selecting *which* `ConnectionSecrets`-held `Aead` to hand to `QuicPacket.parse(..., Aead aead, ...)`
based on `EncryptionLevel` and version-matching logic. This maps directly onto §3.5's `EncryptionLevel`
→ `KeySpace` translation being done **at the parser boundary**, which is the natural, minimal-diff
place to put it. Two non-trivial behaviors found here, both bearing on §1.6 below:

- `ClientRolePacketParser.getAead` (`:62-68`): if an incoming packet's version differs from the
  connection's negotiated version and its level is `Initial`, it constructs a **brand-new,
  throwaway `ConnectionSecrets`** (`new ConnectionSecrets(new VersionHolder(packet.getVersion()), ...)`)
  purely to call `computeInitialKeys(originalDestinationConnectionId)` and grab its `Aead` — used
  during version negotiation to decode an Initial packet in the *old* version while the primary
  connection object has already moved to the *new* negotiated version.
- `ServerRolePacketParser.getAead` (`:93-98`): the "compatible version negotiation" case
  (RFC 9369) does the same thing via `connectionSecrets.getInitialPeerSecretsForVersion(packet.getVersion())`
  (`ConnectionSecrets.java:142-144`), which likewise constructs a one-off `Aes128Gcm` for a
  *different* QUIC version's Initial secret while the primary connection continues under its own
  version.

### 1.5 `KeyUpdateSupport.java` and `Aead`/`BaseAeadImpl` — see §2 in full (the WARN)

### 1.6 Blast-radius-adjacent construction sites the SOW's §3.2 file list omits

Repo-wide grep for `ConnectionSecrets` outside the `crypto` package (main sources) turns up **three
more files that construct `ConnectionSecrets` instances directly**, beyond the SOW's named list:

- `core/src/main/java/tech/kwik/core/server/impl/ServerConnectorImpl.java:384-391`
  (`sendConnectionRefused`): constructs a **throwaway** `ConnectionSecrets`, calls
  `computeInitialKeys(dcid)`, and immediately uses its `Aead` to send one `CONNECTION_REFUSED`
  Initial packet — this runs in the server's single-threaded receive loop, **before any per-connection
  object (and therefore before any per-connection `QuicTlsPort`/engine) exists.**
- `core/src/main/java/tech/kwik/core/server/impl/ServerConnectionCandidate.java:364-379`: same
  pattern in reverse — constructs a throwaway `ConnectionSecrets`, computes Initial keys from the
  DCID, and uses the resulting `Aead` to **decrypt the very first Initial packet of a prospective
  connection**, again before any full connection/engine object is created (this is what lets the
  server route/validate the first packet before deciding whether to accept it).
- `core/src/main/java/tech/kwik/core/impl/QuicConnectionImpl.java:162`: constructs the connection's
  **real**, long-lived `ConnectionSecrets` — this one *does* correspond 1:1 to a per-connection
  engine/port instance and is unremarkable.

`core/src/main/java/tech/kwik/core/send/SenderImpl.java:421` (`send(AssembledDatagram)`) calls
`connectionSecrets.getOwnAead(packet.getEncryptionLevel())` immediately before
`packet.generatePacketBytes(aead)` — this is the actual outbound call site that must be re-pointed
to select a `KeySpace` and drive the port, and it explicitly handles the `MissingKeysException`/
`DiscardedKeys` case (`:426-433`) by silently dropping the packet from the send batch rather than
failing — this drop-on-discarded-keys behavior must be preserved via `port.keysAvailable(KeySpace)`
or the equivalent `QuicKeyUnavailableException` catch.

**Why 1.6 matters, and connects directly to §5 below**: the two `ServerConnectorImpl` /
`ServerConnectionCandidate` sites need INITIAL secrets with **no full connection and no full
`QuicTlsPort`/engine in existence yet**. This is a genuine architectural gap the SOW's §3.2 write-up
does not surface at all (it assumes one engine per connection is the unit of re-pointing). See §5.

---

## 2. The key-update ratchet — resolving the WARN precisely

### 2.1 What kwik does today (transport-side ratchet, confirmed by full reads)

`KeyUpdateSupport implements Aead` (read in full) is a decorator wrapping the real per-direction
`Aead`, installed only at `EncryptionLevel.App` (`ConnectionSecrets.java:195-203`), with the two
peer instances cross-registered via `setPeerAead` so each side can tell the other "your keys are
stale, catch up" (`checkPeerKeys`, `:141-146`).

- **Self-initiated update**: `QuicClientConnectionImpl.updateKeys()` (`:859-872`, read in full) is a
  **public API method** on the client connection. Guarded by `handshakeState == Confirmed`, it calls
  `connectionSecrets.getClientAead(App).computeKeyUpdate(true)`. `KeyUpdateSupport.computeKeyUpdate`
  (`:111-122`) computes new secrets via `aead.computeNextApplicationTrafficSecret()`
  (RFC 9001 §6.1's `"quic ku"`/`"quicv2 ku"` HKDF-Expand-Label, in `BaseAeadImpl.java:103-120`) and,
  because `selfInitiated=true`, installs them **immediately** (`keyUpdateCounter++; aead = updatedAead;`).
  There is no rate-limiting or "wait for peer ack of current phase" check anywhere in this path.
- **Peer-initiated update (detected on receive)**: `QuicPacket.decryptPayload` calls
  `aead.checkKeyPhase(keyPhaseBit)` (`:269`) before every App-level decrypt.
  `KeyUpdateSupport.checkKeyPhase` (`:87-97`) compares the observed bit against
  `keyUpdateCounter % 2`; on mismatch it **speculatively** computes new keys into `updatedAead` and
  sets `possibleKeyUpdateInProgresss = true`, then `aeadDecrypt` (`:70-78`) is tried against
  `updatedAead` instead of `aead` while that flag is set. `ShortHeaderPacket.parse` (`:83-93`) then
  either calls `confirmKeyUpdateIfInProgress()` (decrypt succeeded → `aead = updatedAead`,
  `keyUpdateCounter++`, and it checks whether the **peer's own** `Aead` also needs to catch up via
  `checkPeerKeys`) or `cancelKeyUpdateIfInProgress()` (decrypt failed → discard `updatedAead`,
  the mismatch was packet corruption, not a real key update).
- **Key-phase bit on send**: `ShortHeaderPacket.generatePacketBytes` reads `aead.getKeyPhase()`
  (`:148`) synchronously, before building the header, to decide which bit to encode.

### 2.2 What the real engine does today (confirmed against DirtyChai source, not the interface javadoc alone)

This is the load-bearing finding of this whole document, and it is **stronger** than what the SOW's
WARN anticipated. The SOW's WARN frames the risk as "two key-phase *authorities* racing" — implying
kwik could, in principle, keep partial ownership if it were careful. Having read the actual engine
implementation (`sun/security/ssl/QuicKeyManager.java`, the `OneRttKeyManager` inner class, lines
~655–780), **there is no way for kwik to retain any part of this authority even if it wanted to**:

- **Peer-initiated rollover is fully autonomous inside the engine.** `decryptPacket` → (internally)
  compares the incoming `keyPhase` int argument against `currentKeyPhase`; on mismatch it tries
  `decryptUsingNextKeys` (pre-generated "next" `KeySeries`, computed speculatively — this is the
  *exact same* speculate-then-confirm-or-cancel structure as kwik's `KeyUpdateSupport`, just
  entirely inside the engine, invisible to the caller). Confirmed at `QuicKeyManager.java:790-830`
  (method header: *"uses 'next' keys to try and decrypt the incoming packet. if that succeeded then
  it implies that the key update was indeed initiated by the peer and this method then rolls over
  the keys... if the packet decryption using the 'next' key fails, then this method just returns
  back false (and doesn't roll over the keys)"*). The caller (kwik) never sees any of this; it just
  calls `decryptPacket(ONE_RTT, packetNumber, keyPhaseFromHeader, ...)` and either gets decrypted
  bytes or an exception.
- **Self-initiated rollover is fully autonomous inside the engine, and — critically — it is NOT
  caller-triggerable at all.** `encryptPacket`'s implementation (`QuicKeyManager.java:659-686`) calls
  a private `maybeInitiateKeyUpdate(currentSeries, packetNumber)` (`:708-744`) on **every** encrypt
  call. That method's own comment: *"based on certain internal criteria, this method may trigger a
  key update"* — the criterion is a hardcoded **80% of the AEAD cipher's confidentiality limit**
  (`:711-719`, `"which is arbitrary"` per the engine's own code comment). **Correction to an earlier
  draft of this section**: that trigger is gated by `initiateKeyUpdate` (`:746-773`) checking
  `CipherPair.usedByBothEndpoints()`, and `usedByBothEndpoints()` (`QuicKeyManager.java:87-90`) is
  `readCipher.hasDecryptedAny() && writeCipher.hasEncryptedAny()` (both defined in
  `QuicCipher.java:241` and `:309`) — i.e. it checks only that *some* packet has been successfully
  encrypted and decrypted under the current-phase keys in each direction, not that a packet was
  specifically *acknowledged* in the current phase, which is RFC 9001 §6.1's literal text ("An
  endpoint MUST NOT initiate a subsequent key update unless it has received an acknowledgment for a
  packet that was sent protected with keys from the current key phase" — quoted verbatim in
  `initiateKeyUpdate`'s own comment at `:750-757`, immediately above the weaker check the code
  actually performs). This is a looser proxy for the RFC's ack-based gate, not a literal
  implementation of it. Practically inert: the only thing that trips `maybeInitiateKeyUpdate` at all
  is the 80%-confidentiality-limit heuristic above, which needs on the order of millions of packets
  to reach, so by the time it fires, ACKs will certainly have flowed in both directions regardless of
  whether the engine specifically tracked them — but the doc should describe the actual gating
  condition precisely rather than assert literal ack-gating. **There is no public method on
  `QuicTLSEngine` — and none on
  `QuicTLSEngineImpl` beyond the interface either, confirmed by grepping the whole implementation
  file — that lets a caller request "roll over the 1-RTT write keys now."** The `headerGenerator`
  callback passed to `encryptPacket` receives whatever key phase the engine has already decided on
  (`:682-684`: `writeCipher.getKeyPhase()` is read *after* `maybeInitiateKeyUpdate` has possibly
  already rolled over) — the caller is a passive recipient of the engine's decision, never a driver
  of it.

### 2.2.1 Correction: old-key retention is a net improvement, not a neutral trade

One further point the earlier draft did not surface, confirmed by reading both sides again
specifically for this question: **kwik's current code retains zero old keys after a key-phase
rollover, which is itself a live RFC 9001 §6.5 gap today, and the engine fixes it as a side effect of
this rewrite — this should be stated as an improvement, not filed only under "what gets deleted."**

- **kwik today**: `KeyUpdateSupport.confirmKeyUpdateIfInProgress()` (`KeyUpdateSupport.java:130-139`)
  does `keyUpdateCounter++; aead = updatedAead; updatedAead = null;` — the previous-phase `aead`
  reference is simply overwritten and dropped. Nothing is preserved for a delayed or reordered packet
  that arrives late, still tagged with the *old* key phase, after a rollover has already been
  confirmed. RFC 9001 §6.5 ("Receiving Packets Before a Key Update Completes") expects exactly this
  case to be handled — decrypting delayed prior-phase packets is not optional, it is the specific
  scenario the section exists for — and kwik's current code cannot do it once
  `confirmKeyUpdateIfInProgress()` has run.
- **The engine**: `OneRttKeyManager.KeySeries` (`QuicKeyManager.java:471-521`) carries an explicit
  `old` field (a `QuicReadCipher`, not just the current one) alongside `current`/`next`, and
  `canUseOldDecryptKey(pktNum)` (`:503-520`) gates its use on whether `pktNum` is lower than the
  lowest packet number the *current* key has decrypted so far — directly implementing RFC 9001 §6.5's
  delayed-packet allowance, citing the RFC section in its own comment (`:515`). `decryptPacket`
  (`:584-648`) uses this: on a key-phase mismatch it first tries `series.canUseOldDecryptKey` before
  concluding a genuine update is in progress (`:611-648`).
- **Net effect on this rewrite**: this is not merely "the engine's ratchet replaces kwik's ratchet
  with different internal plumbing" — it is a **strict correctness improvement**, closing a gap that
  exists in kwik's shipped code today. Worth stating plainly when this rewrite is presented for review
  or in release notes: the crypto-seam rewrite doesn't just simplify the key-update path, it fixes a
  real RFC-conformance gap along the way.

### 2.3 The exact, unambiguous boundary (what to delete, what replaces it)

**Delete entirely, not adapt:**

- `KeyUpdateSupport.java` — the whole class. Every method on it (`checkKeyPhase`,
  `computeKeyUpdate`, `confirmKeyUpdateIfInProgress`, `cancelKeyUpdateIfInProgress`,
  `computeNextApplicationTrafficSecret`, `getKeyPhase`, `getKeyUpdateCounter`, `setPeerAead`) has no
  post-rewrite caller, because its entire reason to exist — mediating between kwik's own ratchet
  state and the transport — no longer applies once the engine holds both directions' key-phase
  state internally.
- The `App`-level `KeyUpdateSupport` wrapping in `ConnectionSecrets.createKeys` (`:195-203`) —
  falls away automatically once `ConnectionSecrets` itself is deleted (§4).
- `ShortHeaderPacket`'s three ratchet call sites: `aead.confirmKeyUpdateIfInProgress()` (`:85`),
  `aead.cancelKeyUpdateIfInProgress()` (`:88`), and `keyPhaseBit = aead.getKeyPhase()` (`:148`) —
  deleted, not translated to a port-equivalent call, because **no port-equivalent call exists** (§2.2).
  The replacement shape is structural, not a 1:1 substitution — see §3.
- `QuicPacket.decryptPayload`'s `aead.checkKeyPhase(((ShortHeaderPacket) this).keyPhaseBit)` call
  (`:268-269`) — deleted; the key-phase bit parsed off the wire header becomes a plain `int` argument
  passed straight into `port.decryptPacket(ONE_RTT, packetNumber, keyPhase, ...)`, with no
  intermediate kwik-side interpretation.
- `Aead.java`'s ratchet-related default methods (`checkKeyPhase`, `computeKeyUpdate`,
  `confirmKeyUpdateIfInProgress`, `cancelKeyUpdateIfInProgress`, `getKeyPhase`,
  `getKeyUpdateCounter`, `setPeerAead`) — dead once `Aead`/`BaseAeadImpl`/`Aes128Gcm`/`Aes256Gcm`/
  `ChaCha20`/`KeyUpdateSupport` are all deleted (§4).

**What replaces it:** nothing kwik-side. The engine's per-packet `decryptPacket(KeySpace,
packetNumber, keyPhase, ...)` call (already on the port, exact signature confirmed in
`QuicTlsPort.java:239-241`) *is* the entire replacement for the peer-initiated half; there is no
kwik-side bookkeeping left to do — the caller doesn't even need to remember the current key phase
across calls, since the engine tracks that internally. For the self-initiated half, per §2.2 there
is genuinely nothing to re-point to (§2.4).

**Effect on `ShortHeaderPacket.generatePacketBytes`'s structure**: today it reads
`aead.getKeyPhase()` **before** constructing the header (`:148`), then builds the whole header
buffer, then separately calls `protectPacketNumberAndPayload`. Under the engine's
`encryptPacket(KeySpace, packetNumber, headerGenerator, packetPayload, output)` shape
(`QuicTLSEngine.java:314-318`, and confirmed at the implementation level,
`QuicKeyManager.java:681-684`), the key phase for a given encrypt call is **only known inside the
call**, because `maybeInitiateKeyUpdate` can flip it as a side effect of the very call that's
asking for it. This means `ShortHeaderPacket`'s header-construction logic must become a *callback*
(`IntFunction<ByteBuffer>`, taking the key phase the engine hands it and returning the header bytes
with that bit encoded) rather than a value read up front — a real structural change to the method,
not just a substitution of one AEAD call for another. This is exactly the "rewrite, not deletion"
character the SOW's §3.2 intro correctly anticipates for `QuicPacket`+parsers generally; it applies
with particular force to this one method because of the key-phase-inside-the-callback detail.

### 2.4 The gap this creates: kwik's public `updateKeys()` API has no engine equivalent

This is new information, not previously documented anywhere in the SOW or its predecessor ADVICE
series, and it is the sharpest form the WARN's risk actually takes. Per §2.2, **there is no engine
API to request a self-initiated key update.** `QuicClientConnectionImpl.updateKeys()` (`:859-872`)
is public API (used for QUIC-conformance interop testing and/or deliberate key rotation by an
advanced caller — RFC 9001 §6 says an endpoint "MAY initiate a key update"). After this rewrite, the
method has **no engine call to delegate to**. This is not a matter of finding the right call; the
call does not exist on `QuicTLSEngine`, and grepping the entire `QuicTLSEngineImpl.java` for any
method beyond the interface's own 31 (there is none related to key update) confirms this is not an
oversight in the port or an under-read of the interface — it is an actual capability the JDK engine
does not expose. See open question OQ-1.

---

## 3. Call-site re-pointing plan

All six items below replace kwik's two-step `aeadEncrypt`+`createHeaderProtectionMask` /
`aeadDecrypt`+(unmask first) pattern with the port's two-mandatory-calls-per-direction pattern,
confirmed against `QuicTlsPort.java`'s actual signatures (not assumed ones) and cross-checked
against `QuicTlsPortImpl.java`'s delegation (both read in full, §3.1 area above).

| Today (`QuicPacket.java`) | Replaces with (`QuicTlsPort`) | Order |
|---|---|---|
| `createHeaderProtectionMask(sample, aead)` (`:139`, receive) | `computeHeaderProtectionMask(KeySpace, incoming=true, sample)` | **First** — must happen before `decryptPacket`, per the engine's own javadoc: *"Header protection must be removed before calling this method."* |
| `decodePacketNumber` + `decryptPayload` → `aead.aeadDecrypt(AAD, ciphertext, nonce)` (`:263-279`) | `decryptPacket(KeySpace, packetNumber, keyPhase, packet, headerLength, output)` | Second. **Nonce construction disappears from kwik entirely** — the engine takes the full packet number directly (not a pre-XOR'd nonce); kwik no longer touches `aead.getIv()` at all. |
| `encryptPayload` → `aead.aeadEncrypt(AAD, plaintext, nonce)` (`:241-261`) | `encryptPacket(KeySpace, packetNumber, headerGenerator, packetPayload, output)` | First call in the pair (see below — it also decides the key phase as a side effect, §2.3). |
| `createHeaderProtectionMask(ciphertext, pnLength, aead)` (`:227-239`, send) | `computeHeaderProtectionMask(KeySpace, incoming=false, sample)` | **Second**, sampling from `encryptPacket`'s `output` — order is reversed relative to receive, matching RFC 9001 §5.4.1 ("header protection is applied after packet protection") and the port's own header-note (`QuicTlsPort.java:196-205`) confirming this is not fused into either call, for either direction. |
| `computePacketNumberSize`/`getHeaderProtectionSampleSize`-equivalent (kwik hardcodes `16`, e.g. `:130`, `:235`) | `getHeaderProtectionSampleSize(KeySpace)` | Called once, replaces the hardcoded literal — this is a real (if minor) correctness improvement: kwik's `16` is an AES-GCM/ChaCha20-specific constant baked into the transport layer today; the port makes it cipher-suite-agnostic. |
| Encryption-overhead constant (`ShortHeaderPacket.estimateLength`, `:122`, hardcoded `+ 16`) | `getAuthTagSize()` | Replaces the hardcoded literal for the same reason. |

**Send-path ordering, spelled out** (since the port's two calls interact via the `headerGenerator`
callback, this is not simply "call A then call B"): the caller builds an unprotected-header
*template* (everything except the key-phase bit, for short-header packets), passes it as an
`IntFunction<ByteBuffer>` into `encryptPacket`, which internally (a) decides the key phase
(§2.3), (b) invokes the callback with that phase to get the final header bytes, (c) uses those
header bytes as AAD, (d) writes ciphertext+tag to `output`. The caller then samples 16 bytes (or
`getHeaderProtectionSampleSize(KeySpace)` bytes) from that `output` and calls
`computeHeaderProtectionMask(KeySpace, false, sample)` to get the mask to XOR into the still-unprotected
header bytes it kept from the callback. **This is a genuinely different control flow from today's
`ShortHeaderPacket.generatePacketBytes`**, which builds the complete header up front and only then
protects it — confirming again that this is a rewrite of the method's structure, not a call
substitution.

**Receive-path ordering** is a more direct 1:1 replacement of today's sequence (sample → unmask
header → decrypt), just swapping `aead.createHeaderProtectionMask`/`aead.aeadDecrypt` for
`port.computeHeaderProtectionMask`/`port.decryptPacket`, and dropping the nonce-construction and
`checkKeyPhase` code (§2.3).

**What `ClientRolePacketParser`/`ServerRolePacketParser` change to**: their `getAead(...)` methods'
`EncryptionLevel`-keyed `Aead` lookup is replaced by an `EncryptionLevel → KeySpace` mapping (§4)
used to select which `KeySpace` argument to pass into the port calls above — the parsers no longer
"get an object," they translate an enum. The two version-negotiation-adjacent branches (§1.4) need
their own resolution — see OQ-2/OQ-3 (§5, §9).

---

## 4. Key-space mapping

`QuicTLSEngine.KeySpace` (confirmed, `QuicTLSEngine.java:48-54`): `INITIAL`, `HANDSHAKE`, `RETRY`,
`ZERO_RTT`, `ONE_RTT`. kwik's `EncryptionLevel` (`core/src/main/java/tech/kwik/core/common/EncryptionLevel.java`,
read in full): `Initial`, `ZeroRTT`, `Handshake`, `App`. The mapping is a straight rename except for
one name-shape mismatch and one exclusion:

| `EncryptionLevel` | `KeySpace` | Note |
|---|---|---|
| `Initial` | `INITIAL` | 1:1, but see §5 — a single engine's `INITIAL` key-space is a **single slot**, and kwik sometimes needs two Initial key sets alive at once. |
| `Handshake` | `HANDSHAKE` | 1:1. |
| `App` | `ONE_RTT` | Name differs; semantics identical (RFC 9001's "Application Data (1-RTT) Keys", both enums' own doc comments cite the same RFC language). |
| `ZeroRTT` | `ZERO_RTT` | **Excluded by construction per SOW §3.5 (STD-010 §6.2)** — this document does not scope 0-RTT re-pointing; `ZeroRttPacket.java` is out of scope here (§3.5 is a separate work item). |
| *(none)* | `RETRY` | kwik's `RetryPacket` does not use `ConnectionSecrets`/`Aead` at all — it computes its own static-key AEAD integrity tag directly with `javax.crypto.Cipher` (`RetryPacket.java:242-`, read in part), independent of TLS secrets entirely (RFC 9001 §5.8's fixed public key). The port's `signRetryPacket`/`verifyRetryPacket` (already present, `QuicTlsPort.java:246-255`) are the eventual replacement, but the SOW places that under §3.3, not §3.2, and this document does not scope it further — noted here only so the key-space table is complete. |

Kwik's `EncryptionLevel` enum can **stay** (it's referenced far too widely — `PnSpace` mapping,
logging, `CryptoStream`'s per-level construction, etc. — to be worth deleting), and should simply
gain a translation function to `QuicTLSEngine.KeySpace` used at the `PacketParser`/`SenderImpl` call
sites identified in §1.4/§1.6. This keeps the `QuicTlsPort` import boundary narrow (per §3.1's own
design goal) — translation happens once, at the seam, not scattered.

---

## 5. The gap §3.2/§3.5 don't surface: one engine holds only one `INITIAL` key set at a time

### 5.1 The single-slot collision — CONFIRMED, not merely structural evidence (Step A's spike is DONE)

**Correction to the earlier draft: this is no longer a "flagged as needing a spike" open item — it
has been empirically confirmed.** The structural evidence stands as before (reading
`sun/security/ssl/QuicTLSEngineImpl.java:698-709`, `deriveInitialKeys` delegates to
`this.initialKeyManager.deriveKeys(...)`; `QuicKeyManager.java:93-100`, `93` area, each
per-`KeySpace` manager holds a **single** `keySeries`/`CipherPair` field, not a map keyed by
connection ID or version) — and it is now backed by both a direct code citation and an empirical
result:

- **Direct proof in the engine's own code**: `InitialKeyManager.deriveKeys(...)`
  (`QuicKeyManager.java:255-337`) reads, at `:322-330`:
  ```
  final CipherPair old = this.cipherPair;
  // we don't check if keys are already available, since it's a
  // valid case where the INITIAL keys are regenerated due to a
  // RETRY packet from the peer or even for the case where a
  // different quic version was negotiated by the server
  this.cipherPair = new CipherPair(readCipher, writeCipher);
  if (old != null) {
      old.discard(true);
  }
  ```
  The engine's own comment names *exactly* the Retry and version-negotiation cases this document
  independently identified below, and confirms its own design intent is "regenerate in place," not
  "layer a second set." `old.discard(true)` actively destroys the previous `CipherPair` (both the
  read and write ciphers), it does not merely drop a reference to it.
- **Empirical confirmation, run for this document's review round**: a board reviewer constructed a
  real DirtyChai engine (`QuicTlsPortImpl.forClient`/`forServer` over a genuine `SSLContext`, the
  same construction path as the week-1 spike), called `deriveInitialKeys` twice with two different
  DCIDs on the same engine instance, kept the `Aead`/cipher object returned after the *first* call,
  and attempted to decrypt a packet that had been encrypted under the *first* derivation's keys,
  after the *second* derivation had run. Result: `AEADBadTagException` — the first key set is
  unusable after the second `deriveInitialKeys` call, exactly as `old.discard(true)` above predicts.

**This confirms the single-slot-per-engine-instance claim as settled fact, not a hypothesis.** What
remains open is not *whether* this collision is real, but *which design response* (§5.3/OQ-4) each
of the three colliding call sites should use — that decision is still for the board, per §5.3 below.

### 5.2 Three call sites, examined individually for a concurrent-key requirement

The original draft treated these three call sites as a single, undifferentiated problem needing one
uniform answer among options (a)/(b)/(c). A follow-up review re-examined each site individually,
specifically asking: *does this site ever need two different Initial key sets usable at the same
instant*, the way the single-slot collision in §5.1 would break, *or is "derive right before use,
then discard" always sufficient?* The three sites turn out to have materially different shapes, and
one piece of the follow-up's own working hypothesis was refuted by this closer read — see the
specific findings below, then §5.3 for the recommendation that follows once the evidence is in.

1. **Post-Retry dual retention — genuinely needs two live Initial key sets, open-endedly.**
   `ConnectionSecrets.recomputeInitialKeys(byte[])` (`:130-134`) is called from exactly one call site
   that does real dual retention: `ServerConnectionImpl.java:485`, inside `process(InitialPacket,
   ...)`'s `retryRequired` branch, immediately after `sendRetry()`. (Correction to the earlier
   draft's citation: `QuicClientConnectionImpl.java:691` and `ServerConnectionImpl.java:635` call the
   *no-arg* `recomputeInitialKeys()` overload, used for version-negotiation recompute — a different,
   single-slot-replacing operation, not dual retention; they are call site 2 below, not part of this
   site.) `recomputeInitialKeys(byte[])` stashes the pre-Retry client Initial `Aead` into
   `originalClientInitialSecret` (`:131`) *before* overwriting the primary Initial slot, and
   `getOriginalClientInitialAead()` (`:284-291`) returns that stashed value for as long as it is
   non-null — read by `ServerRolePacketParser.getAead` (`:70`) whenever a token-less Initial packet
   arrives while `retryRequired` is set. **Checked specifically for this document: how long must the
   old key set remain usable?** There is no timeout, deadline, or state-transition in the code that
   ever clears `originalClientInitialSecret` — it is set once (on Retry) and never reset for the rest
   of the `ConnectionSecrets` object's life. Notably, `discardKeys(Initial)`
   (`ServerConnectionImpl.java:553`, fired on the server's first successfully-processed Handshake
   packet, per RFC 9001's "discard Initial keys" rule) nulls the `clientSecrets`/`serverSecrets`
   arrays but does **not** clear `originalClientInitialSecret` — a separate field entirely — so in
   the current code `getOriginalClientInitialAead()` would still return the stale pre-Retry keys even
   after Initial keys are nominally "discarded" (a latent quirk worth a note for whoever implements
   this, not a defect this document is scoping a fix for). **Conclusion: this site's requirement is
   genuinely open-ended dual retention with no bound coded anywhere** — the strongest possible form
   of the concurrent-two-key-sets need, and the one squarely incompatible with a single-slot engine.

2. **Compatible version negotiation — also needs two live Initial key sets, refuting this
   document's own working hypothesis for this site.** The follow-up hypothesis that motivated this
   review assumed sites 2 and 3 were "derive, use immediately, discard," with no concurrent-old-key
   need. **That assumption is wrong for site 2, and the evidence for why is in the code's own RFC
   citation.** `ServerRolePacketParser.getAead` (`:93-97`) has a branch guarded by
   `versionNegotiationStatusSupplier.get() == VersionChangeUnconfirmed`, whose comment quotes RFC
   9369 directly: *"The server MUST NOT discard its original version Initial receive keys until it
   successfully processes a packet with the negotiated version."* Tracing the trigger
   (`ServerConnectionImpl.java:635`/`QuicClientConnectionImpl.java:691`, the no-arg
   `recomputeInitialKeys()`): when the server (or client) switches its *primary* Initial keys over to
   the newly-negotiated version, RFC 9369 explicitly requires the *original*-version Initial receive
   keys to keep working until a negotiated-version packet is confirmed — i.e., during the
   `VersionChangeUnconfirmed` window, both the primary (new-version) and the original-version Initial
   key sets must be decodable, because a client Initial packet in either version may legitimately
   still arrive. **This is the same shape of requirement as site 1**, not the "derive-use-discard"
   shape the hypothesis assumed. Where site 2 *does* differ from site 1 in a way that matters for the
   design choice: it does not need a **persisted** old-key object the way site 1's
   `originalClientInitialSecret` field is persisted state. `ConnectionSecrets.getInitialPeerSecretsForVersion(Version)`
   (`:142-144`) and `ClientRolePacketParser.getAead`'s alt-version branch (`:62-68`) both recompute
   the alt-version Initial secret **fresh, from scratch, on every single call** — a pure function of
   the (public DCID, version, fixed RFC salt) triple, with no ratchet state, no caching, and no
   reliance on anything surviving between calls. Because Initial secrets have no negotiated/ephemeral
   component (§5.1's confidentiality point again), re-deriving identically on every call costs nothing
   functionally — it is not an optimization being skipped, it is simply how this code already works,
   and it happens to sidestep the single-slot problem entirely, *provided* the recomputation doesn't
   share a slot with whatever holds the *primary* connection's own current-version Initial keys. If
   it did share that slot, deriving the alt-version secret would destroy the primary connection's own
   live Initial keys — a real hazard, not a hypothetical one, and a reason this site cannot safely
   reuse the connection's *own* per-connection engine's `INITIAL` keyspace for this purpose.

3. **Pre-connection candidate/refusal packets — a genuine multi-threaded concurrency hazard, refuting
   the implicit "single receive loop, so it's safe" assumption.** The two sub-sites here are not
   symmetric, and this matters for whether option (c)'s shared engine is safe:
   - `ServerConnectorImpl.sendConnectionRefused` (`:377-390`) is confirmed single-threaded: its
     caller, `processInitial` (`:363-375`), has its own comment stating *"this method is only called
     from one thread (see receiveLoop)"* — i.e. genuinely serialized with itself, no self-concurrency.
   - `ServerConnectionCandidate.parseInitialPacket`/`parsePackets` (`:146-176`) is **not** on that
     thread. `parsePackets`'s own comment: *"Execute packet parsing on separate thread, to make this
     method return a.s.a.p."* — it dispatches via `executor.submit(...)`, and `executor` is
     `context.getSharedServerExecutor()` (`ServerConnectionCandidate.java:116`), the *same*
     `ThreadPoolExecutor(1, 10, ...)` pool constructed in `ServerConnectorImpl` (`:148-151`,
     `maxSharedExecutorThreads = 10`). The `synchronized(this)` block inside `parsePackets` (`:153`)
     serializes processing *per candidate object*, explicitly noted as being for duplicate-packet
     ordering ("duplicate initial packets might arrive faster than they are processed") — it is
     **not** a global lock. Confirmed by reading the constructor: every new `ServerConnectionCandidate`
     (`ServerConnectorImpl.java:406`, one per prospective connection) gets its own candidate-scoped
     lock, submitted to the shared pool.
   
   **Conclusion**: up to 10 different `ServerConnectionCandidate` instances can call into their own
   Initial-key derivation *truly concurrently*, on different worker-pool threads, and that can also
   run concurrently with `ServerConnectorImpl.sendConnectionRefused` on the dedicated receive-loop
   thread. There is **no invariant in the current code, documented or otherwise, that serializes
   Initial-key derivation across the server's accept path** — the opposite is true by explicit
   design (dispatching to a worker pool exists specifically to let the receive loop return fast under
   load). A shared single engine instance (option (c) as literally read — "held once per
   `ServerConnector`") would need a **new** lock added around derive-then-use for every candidate and
   every refusal, serializing exactly the traffic this pool was built to parallelize — under the kind
   of Initial-packet flood where that parallelism matters most (a plausible DoS-amplification shape,
   not merely a style concern). This directly contradicts any assumption that this site "can
   genuinely never run concurrently" — it can, routinely, under normal (non-adversarial) load with
   more than one connection attempt in flight, and the code deliberately makes this so.

### 5.3 Resolution — see §10, OQ-4, for the concrete per-site recommendation

Putting §5.1 and §5.2 together: the single-slot collision is real and confirmed (§5.1); site 1
genuinely needs open-ended dual retention (§5.2.1); site 2 *also* genuinely needs concurrent
old-version/new-version retention, contrary to this document's own initial working hypothesis, though
via a stateless recompute-on-demand mechanism rather than a persisted object (§5.2.2); and site 3 has
a real, code-confirmed multi-threaded concurrency hazard that makes a shared engine unsafe without
adding a new lock (§5.2.3). **Why this is not simply "another instance of the WARN's raw-secrets
problem," and why a narrow carve-out is legitimate at all**: RFC 9001 §5.2's Initial secrets are, by
design, not confidential — they're deterministically derived from a public value (the destination
connection ID) and a hardcoded public salt; RFC 9001 itself frames Initial protection as defense
against off-path/on-path corruption and identifiability, not confidentiality from a capable observer.
So unlike Handshake/Application secrets, keeping a narrow, INITIAL-only HKDF path alive for these
three cases does **not** reopen the "raw secrets never requested" security property the fork is built
around (§3.2's stated security point is about the negotiated TLS secrets that back Handshake/App
protection, not the public Initial derivation). See §10/OQ-4 for how this evidence resolves to a
concrete recommendation.

---

## 6. Dependency cleanup — verified, not assumed

### 6.1 `at.favre.lib.hkdf` — retained, Initial-only, per §5.3/OQ-4's resolved recommendation

Repo-wide grep (`--include=*.java .` from the repo root, plus `build.gradle`/`module-info.java`
greps) confirms **exactly five source files** use `at.favre.lib.hkdf`, and no others exist anywhere
in the reactor (`qlog`, `cli`, `interop`, `samples`, `h09` all clean):
`ConnectionSecrets.java`, `BaseAeadImpl.java`, `ChaCha20.java`, `Aes128Gcm.java`, `Aes256Gcm.java`.
`core/build.gradle:49-50` declares it; `module-info.java:3` requires it
(`requires at.favre.lib.hkdf;`).

Four of the five (`BaseAeadImpl.java`, `ChaCha20.java`, `Aes256Gcm.java`, and the Handshake/App-level
paths of `ConnectionSecrets.java`) are deleted/gutted by this rewrite, as before. **Updated per
§5.3/OQ-4's resolved recommendation (option (a), uniformly, for all three Initial-key-multiplicity
call sites — no longer conditional on a future board choice among three options, since the evidence
in §5.2 converges on one answer): `ConnectionSecrets` survives in reduced, Initial-only form, and so
does the dependency itself, scoped strictly to Initial-level HKDF derivation.** `Aes128Gcm.java`
specifically also survives (it's the concrete `Aead` implementation `createKeys(Initial, ...)` and
`getInitialPeerSecretsForVersion` construct) — the other three cipher-suite classes
(`Aes256Gcm`/`ChaCha20`, plus `BaseAeadImpl`'s Handshake/App-level machinery) do not, since Initial
secrets are always `TLS_AES_128_GCM_SHA256` per RFC 9001 §5.2, never cipher-suite-negotiated. This
finalizes what the earlier draft of this document left conditional on a future §5 decision — the
"likely drops" framing in the SOW's §3.2 "Dependency cleanup" bullet should be read as **"retained,
Initial-only, one class + the dependency,"** not as dropped, pending only the OQ-4 sign-off in §5.3.

### 6.2 `io.whitfin.siphash` — confirmed stays, exactly as the SOW says

Repo-wide grep confirms exactly one consumer:
`core/src/main/java/tech/kwik/core/util/SecureHash.java` (read in full, 37 lines) — wraps
`io.whitfin.siphash.SipHash`/`SipHashContext` purely to hash a destination connection ID
(`generateHashCode(byte[] dcid)`) for stateless CID routing. No AEAD, no TLS secret, no traffic key
material anywhere near it. `core/build.gradle:52` and `module-info.java:4` are its only other
references. **Confirmed, not just restated from the SOW**: this dependency is untouched by the
crypto-seam rewrite regardless of how §5 resolves.

---

## 7. Blast radius

### 7.1 Production code (beyond the SOW's four named files)

Full inventory, from repo-wide greps of `ConnectionSecrets`, `KeyUpdateSupport`, `BaseAeadImpl`,
`Aes128Gcm`, `Aes256Gcm`, `ChaCha20`:

- `core/src/main/java/tech/kwik/core/crypto/`: `ConnectionSecrets.java` (**reduced, not deleted**, to
  an Initial-only shape, per §5.3/§6.1's resolved recommendation), `CryptoStream.java` (**out of this
  scope's remit**, §1.2), `KeyUpdateSupport.java` (deleted, §2.3), `Aead.java` (interface — most
  methods deleted; the ratchet methods per §2.3 and the Handshake/App `aeadEncrypt`/`aeadDecrypt`
  plumbing go, but the interface itself and its Initial-relevant methods remain, implemented by
  `Aes128Gcm`), `BaseAeadImpl.java`, `Aes256Gcm.java`, `ChaCha20.java` (deleted — Handshake/App-level
  cipher-suite machinery, no longer needed once those levels go through the port), `Aes128Gcm.java`
  (**retained**, Initial-only — it's the concrete `Aead` `createKeys(Initial, ...)` and
  `getInitialPeerSecretsForVersion` construct, and Initial is always
  `TLS_AES_128_GCM_SHA256` per RFC 9001 §5.2), `MissingKeysException.java` (semantics preserved via
  `QuicKeyUnavailableException`/`keysAvailable` for Handshake/App levels, retained as-is for the
  Initial-only `ConnectionSecrets` — see §1.1).
- `core/src/main/java/tech/kwik/core/packet/`: `QuicPacket.java`, `ShortHeaderPacket.java` (rewrite,
  §2.3/§3), `LongHeaderPacket.java` (calls the rewritten `QuicPacket` methods but needs no method-
  body changes itself, confirmed by its two call sites both being into `QuicPacket`'s shared
  helpers), `PacketParser.java`, `ClientRolePacketParser.java`, `ServerRolePacketParser.java`
  (§1.4/§3), `RetryPacket.java` and `VersionNegotiationPacket.java` — **correction, added on
  review: these two are NOT untouched.** Both files `import tech.kwik.core.crypto.Aead`
  (`RetryPacket.java:23`, `VersionNegotiationPacket.java:23`) and both override the abstract
  `QuicPacket` methods this rewrite changes the signature of — `parse(ByteBuffer, Aead, long, Logger,
  int)` (`RetryPacket.java:130`, `VersionNegotiationPacket.java:73`) and `generatePacketBytes(Aead)`
  (`RetryPacket.java:216`, `VersionNegotiationPacket.java:139`) — confirmed by grep that neither
  method body ever dereferences the `aead` parameter (zero `aead.` call sites in either method): 
  `RetryPacket` computes its own static-key AEAD integrity tag directly via `javax.crypto.Cipher`
  (RFC 9001 §5.8's fixed public key, independent of TLS secrets, per §4's table), and
  `VersionNegotiationPacket` has no encryption at all (it's a cleartext packet type). So when
  `QuicPacket`'s abstract signatures change to take `QuicTlsPort`/`KeySpace` instead of `Aead`
  (§3/§4), **both files need a mechanical, signature-only edit** — updating the parameter type on
  these two overrides to keep the class compiling — even though neither file's actual logic changes
  at all. Call this out explicitly in the implementation step (§8) so whoever does this doesn't
  accidentally start "fixing" the real retry-integrity-tag or version-negotiation logic while
  touching these files for what should be a one-line signature edit each.
- `core/src/main/java/tech/kwik/core/impl/QuicConnectionImpl.java` (`:162`, `ConnectionSecrets`
  construction → port/engine construction, but the *triggering* calls — `computeInitialKeys`,
  `computeHandshakeSecrets`, etc. — live in `QuicClientConnectionImpl`/`ServerConnectionImpl` and
  are §3.3 driver-seam territory, not this document's scope; only the field type and constructor
  call at this one line are crypto-seam-adjacent).
- `core/src/main/java/tech/kwik/core/server/impl/ServerConnectorImpl.java`,
  `ServerConnectionCandidate.java` — §1.6/§5, need a scope decision before they can be re-pointed.
- `core/src/main/java/tech/kwik/core/send/SenderImpl.java:421` — §1.6, the outbound `Aead`
  selection call site.
- `core/src/main/java/module-info.java` — `requires at.favre.lib.hkdf;` line, conditional on §5/§6.1.

### 7.2 Test code — this is the larger, less obvious blast radius

Repo-wide grep for `ConnectionSecrets` in tests: 10 files
(`ConnectionSecretsTest.java`, `ServerConnectorImplTest.java`, `InitialPacketTest.java`,
`ClientRolePacketParserTest.java`, `QuicClientConnectionImplTest.java`, `HandshakePacketTest.java`,
`ServerConnectionCandidateTest.java`, `ServerRolePacketParserTest.java`,
`ServerConnectionImplTest.java`, `SenderImplTest.java`).

More importantly, **a shared test fixture used across seven test files constructs a real, working
`Aead`** and will need a wholesale replacement, not a tweak:
`core/src/test/java/tech/kwik/core/crypto/CryptoTestUtils.java`'s `createKeys()` (read in full)
Mockito-mocks an `Aes128Gcm` but wires its `aeadEncrypt`/`aeadDecrypt`/`createHeaderProtectionMask`
to `thenCallRealMethod()` against a genuinely-constructed `Aes128Gcm` instance — i.e. it's a real
crypto fixture, not a pure stub. `core/src/test/java/tech/kwik/core/impl/TestUtils.java:35-36`
wraps it as `TestUtils.createKeys()`. Confirmed callers (grep, excluding the two utility files
themselves): `HandshakePacketTest.java`, `InitialPacketTest.java`, `ShortHeaderPacketTest.java`,
`ZeroRttPacketTest.java`, `core/src/test/java/tech/kwik/core/send/AbstractSenderTest.java`,
`PacketAssemblerTest.java`, `SenderImplTest.java` — **7 files**, spanning both `packet` and `send`
test packages, all of which need a new fixture shape once `Aead`/`Aes128Gcm` are gone. The natural
replacement is a small helper that derives real `INITIAL`-space keys via a `QuicTlsPort` (either
`QuicTlsPortImpl.forClient`/`forServer` over a real DirtyChai engine, mirroring what the week-1
spike already proved works with zero handshake state — `QuicTlsPortImplRealEngineTest.java` and
`spike/QuicTlsEngineInitialPacketSpike.java` are existing precedent for this — or a hand-written
`FakeQuicTlsPort` per §6.2's mock-testability rationale, for tests that don't need real bytes to
round-trip). Deciding which of those two fixture styles each of the 7 files needs is implementation
work, not scope work, but the count and shape of the migration is now known precisely, which the SOW
did not previously establish.

`KeyUpdateSupport` has **no dedicated test file** (confirmed — no `KeyUpdateSupportTest.java`
anywhere in the tree); its behavior is presumably exercised only indirectly through
`ShortHeaderPacketTest`/connection-level tests, which is itself worth a callout: there is no unit
test whose deletion needs separate justification beyond "the class it tests is gone," but also no
existing test that would have caught a key-update regression in isolation — the eventual
implementation step for §2's deletion should add a **new** targeted test (real engine, two packets,
confirm phase flip and old-phase-decrypt-still-works-during-grace-window), not just rely on deleting
the old one cleanly.

---

## 8. Staged implementation breakdown

Given the scale (§9) and the SOW's own preference for gated spikes over big-bang changes (§7.1's
precedent), the crypto-seam rewrite specifically — as distinct from the driver seam (§3.3) — breaks
into four independently-verifiable increments:

**Step A — Key-space mapping + the §5 decision (prerequisite, ~1-2 days, reduced from ~2-3 now that
the spike is done).** **Correction: the empirical spike this step originally scoped is
CONFIRMED, not pending** — §5.1 records both the direct code proof (`QuicKeyManager.java:322-330`'s
`old.discard(true)`) and the empirical result (real DirtyChai engine, two `deriveInitialKeys` calls,
`AEADBadTagException` on the stale key), run for this document's review round. What Step A still
needs to do, now narrower than originally scoped: (1) get an explicit board/Peter sign-off on §5.3/
OQ-4's resolved recommendation (option (a), uniformly, for all three call sites — the analysis is
done, per-site, in §5.2; this is a sign-off gate, not open investigation); (2) finalize the
`EncryptionLevel`↔`KeySpace` mapping and the reduced `ConnectionSecrets` shape (Initial-only) once
that sign-off lands. This step still produces no rewritten `QuicPacket` code — it's a
decision-and-sign-off gate, not a verification spike anymore.

**Step B — `QuicPacket`/`ShortHeaderPacket`/`LongHeaderPacket` call-site re-pointing (~4-6 days).**
Rewrite the six call sites in §3 to talk to `QuicTlsPort` instead of `Aead`, including the
structural `IntFunction<ByteBuffer>` header-generator change in `ShortHeaderPacket.generatePacketBytes`
(§2.3). Delete the nonce-construction code (`encryptPayload`/`decryptPayload`'s IV-XOR logic) since
the engine now owns nonce derivation. At this point `KeyUpdateSupport` and the ratchet call sites
are **not yet deleted** — leave them as dead code behind the old `Aead` interface if that's the
cheapest way to keep the build green mid-step, or delete them here if `ShortHeaderPacket`'s rewrite
naturally removes their only call sites as a side effect (likely, per §2.3 — worth checking rather
than assuming). Verify with a targeted round-trip test mirroring the week-1 spike (real two engines,
one INITIAL packet each direction, tamper-byte negative path) extended to cover a `ShortHeaderPacket`/
`ONE_RTT` round trip once Step C below has `setOneRttContext` wiring available from the driver-seam
work.

**Correction — the §3.3 dependency here is more than "a minimal stub," sharpen accordingly.** The
earlier draft's phrasing ("may need to borrow a minimal stub from §3.3") understates this. The stub
object itself — `QuicOneRttContext` — is trivial to construct. What is not trivial is *reaching a
state where it's needed*: `port.keysAvailable(QuicTLSEngine.KeySpace.ONE_RTT)` only becomes true
after real TLS 1.3 handshake messages have been driven through the engine via
`consumeHandshakeBytes(KeySpace, ByteBuffer)`/`getHandshakeBytes(KeySpace)` (both already on
`QuicTlsPort.java:137-144`) far enough to derive 1-RTT traffic secrets — that is real §3.3
handshake-driver-seam work (a minimal but genuine ClientHello/ServerHello/Finished exchange through
the engine), not a trivial test fixture. A future implementer reading only "borrow a minimal stub"
could reasonably assume this is a five-minute mock; it is closer to standing up a cut-down version of
§3.3's own driver before Step B's `ONE_RTT` round-trip test can even begin. Flag this cross-seam
dependency explicitly, and size it accordingly, to whoever sequences §3.2 against §3.3 — Step B's
`INITIAL`/`HANDSHAKE`-level round-trip coverage has no such dependency and can proceed independently.

**Step C — Key-update ratchet deletion, as its own isolated, carefully-reviewed step (~2-3 days,
matching §7.2a's "+5d" line but split from the rest of the crypto-seam work deliberately).** Delete
`KeyUpdateSupport.java`, the `Aead` ratchet methods, and any ratchet call sites not already removed
as a side effect of Step B. This is called out as its own step, separate from Step B, specifically
*because* of the WARN: giving it an isolated diff and an isolated review pass makes it easy for a
reviewer to confirm "no kwik-side key-phase state remains" by inspection of a small, self-contained
change, rather than needing to audit it as one hunk inside a much larger `QuicPacket` rewrite. Add
the new targeted key-update test flagged in §7.2 here.

**Correction — Step C/D circularity, found and fixed on review.** As originally drafted, Step C
deleted `KeyUpdateSupport.java` outright, but `new KeyUpdateSupport(...)` is constructed at exactly
two lines, both inside `ConnectionSecrets.createKeys()` (`ConnectionSecrets.java:198-199` — confirmed
by grep as the *sole* construction site anywhere in the tree), and the doc assigned all of
`ConnectionSecrets`'s cleanup to Step D. Taken literally, Step C's diff would delete the class while
leaving `ConnectionSecrets.createKeys()` still referencing it — the build breaks between Step C and
Step D, contradicting §8's own "each step independently verifiable" design goal. **Fix: Step C's diff
must also include the narrow edit to `createKeys()`'s `App`-level branch (`:195-203`) that removes the
`KeyUpdateSupport` wrapping and `setPeerAead` cross-registration, replacing it with a direct
`clientSecrets.set(...)`/`serverSecrets.set(...)` of the plain `Aead` — i.e. the same 8-ish lines
`ConnectionSecrets.java` would need touched either way, pulled forward into Step C instead of left for
Step D.** This is deliberately the *narrowest* fix, not "merge C into D" or "reorder them": it keeps
Step C's own stated purpose (an isolated, reviewable diff proving no kwik-side key-phase state
remains) intact — arguably strengthens it, since the reviewer can now see in the same small diff both
"the class is gone" and "its one call site no longer references it" — without dragging Step C into
`ConnectionSecrets`'s much larger dependency-cleanup scope (deleting the whole class, `BaseAeadImpl`,
the cipher suite classes, `at.favre.lib.hkdf`), which stays in Step D exactly as before. Step D's
`ConnectionSecrets` diff should note that the `KeyUpdateSupport` wrapping is already gone by the time
Step D starts, rather than re-deriving that fact.

**Step D — `ConnectionSecrets`/dependency cleanup + full suite (~2-3 days, scope depends on Step
A's decision).** Delete (or reduce, per §5) `ConnectionSecrets.java`, `BaseAeadImpl.java`,
`Aes128Gcm.java`, `Aes256Gcm.java`, `ChaCha20.java`; remove `at.favre.lib.hkdf` from
`build.gradle`/`module-info.java` if Step A's decision allows it; rewrite the 7-file test fixture
migration (§7.2); re-point `SenderImpl.java:421` and the `ServerConnectorImpl`/
`ServerConnectionCandidate` sites per Step A's chosen option; run the full `core` suite (baseline:
990 tests, 989 pass / 1 pre-existing skip, per the RSA-fixture ADVICE doc's verification record) and
confirm no new failures beyond ones explicitly expected from this rewrite. (By this point,
`createKeys()`'s `App`-level `KeyUpdateSupport` wrapping has already been removed in Step C per the
correction above — Step D's `ConnectionSecrets` diff is the rest of the file.)

This ordering keeps `KeyUpdateSupport`'s deletion — the single highest-consequence item per the
WARN — in its own small, reviewable step (C) rather than buried inside the larger AEAD re-pointing
(B), and keeps the genuinely novel architectural question (§5) resolved *before* any code is
written against an assumption that might be wrong (A before B).

---

## 9. Effort/risk estimate for the crypto-seam portion specifically

The SOW's §7.2a correction already isolates "key-update relocation" as "+5d on top of the floor
table's crypto-seam line" and separately budgets "Delete `ConnectionSecrets` AEAD/HKDF; delegate to
engine encrypt/decrypt/HP in the packet path" at 3-5 days (§7.2's table) — call that combined
baseline **8-10 days**. This document's findings push that estimate up, concentrated in two places
not previously accounted for:

- **§5's Initial-key-multiplicity gap is new scope, not covered by any existing line in §7.2/§7.2a —
  now resolved to the low-cost end of the original range.** §5.3/OQ-4 resolves to option (a),
  narrow HKDF-only retention, for all three call sites — close to today's code, no `SSLContext`
  plumbing into `ServerConnectorImpl`/`ServerConnectionCandidate` needed, and no new locking around
  the shared-executor concurrency hazard found in §5.2.3 (since (a)'s per-call construction has no
  shared mutable state to lock). **Updated cost: modest, not the "+3-5 days" upper bound this
  document originally flagged for the throwaway/shared-engine options** — mostly the work of
  reducing `ConnectionSecrets` to its Initial-only shape (§6.1/§7.1) and re-pointing the three call
  sites to it, which is close to a no-op relative to today's code since they already use this exact
  code path.
- **The `ShortHeaderPacket.generatePacketBytes` structural rewrite (§2.3/§3) is more invasive than
  "delegate to engine encrypt/decrypt/HP" suggests.** The header-generator-callback inversion is a
  genuine control-flow change, not a substitution, and it is the one place where a subtle bug (e.g.
  building the header template with a placeholder key-phase bit that doesn't get correctly
  overwritten by the callback's actual argument) could silently produce wire-correct-looking but
  wrong packets. Budget review time accordingly — this is exactly the kind of thing the Step B/Step
  C split (§8) is meant to make reviewable in isolation.
- **The 7-file test-fixture migration (§7.2) is real, non-mechanical work**, not a mechanical
  find-replace — each of the 7 call sites needs a decision about whether it wants a real-engine
  fixture or a `FakeQuicTlsPort` stub, and the real-engine option requires the DirtyChai JDK toolchain
  to be available wherever these tests run (already true per §3.1's landed Gradle toolchain work,
  but worth re-confirming it's still green before Step D starts).

**Revised crypto-seam-specific estimate: ~12-16 days**, up from the SOW's implied ~8-10, driven
by §5 (new scope the SOW didn't carry) and the fixture migration (known blast radius the SOW didn't
enumerate). This is consistent with, and a refinement of, the SOW §7.2a's own framing that the
6-8-week floor under-weights the crypto seam — it does not by itself change the overall 8-12-week
program estimate, since some of this was likely already implicitly absorbed into the "+1-2 weeks"
slack the honest estimate carries, but it should not be treated as free slack once this document's
findings are accounted for explicitly.

**What could make it harder than even this revised estimate:**

- **Superseded by §5.3/OQ-4's resolution**: the earlier draft flagged the risk of Step A's spike
  confirming the worse outcome and OQ-4 landing on a throwaway/shared-engine option, requiring
  `SSLContext` plumbing into `ServerConnectorImpl`/`ServerConnectionCandidate`. The spike is now
  done (§5.1) and OQ-4 resolves to option (a) (§5.3), which needs none of that plumbing — this risk
  no longer applies unless the board's sign-off on §5.3's recommendation overturns it.
- The engine's autonomous 80%-confidentiality-limit key-update trigger (§2.2) interacting with
  kwik's own AEAD-limit tracking/connection-close-on-limit logic, if any exists elsewhere in the
  transport (not investigated as part of this document — flagged as a possible follow-up check
  during Step C, since two independent confidentiality-limit trackers, one now gone, is a milder
  version of the same "two authorities" shape the original WARN was about, just for a different
  invariant).
- `ChaCha20`/cipher-suite-selection logic: this document did not verify whether the engine's cipher
  suite negotiation is drivable/observable the same way kwik's `selectedCipherSuite` field
  (`ConnectionSecrets.java:44`) is used elsewhere (e.g. for `NEW_SESSION_TICKET` or other
  cipher-suite-conditional logic outside the AEAD path) — if any such use exists, it's an additional
  small item Step D needs to account for.

---

## 10. Open questions for board reviewers

**OQ-1 (HIGH — capability loss, needs an explicit decision, not a default).** §2.4: kwik's public
`QuicClientConnectionImpl.updateKeys()` API has no engine equivalent — self-initiated key update is
not exposed by `QuicTLSEngine` at all; the engine triggers it autonomously at ~80% of the AEAD
confidentiality limit and gives the caller no way to request it on demand. Options: (a) delete
`updateKeys()` and document the capability loss in the fork's own notes/NOTICE; (b) keep the method
but make it a documented no-op (or throw `UnsupportedOperationException`), preserving source
compatibility for callers who reference it but not behavior; (c) something not yet identified — is
there a way to *influence* the engine's confidentiality-limit-based trigger (e.g. via
`SSLParameters` or a similar knob) that this document's reading of the interface missed? This
document did not find one, but flags it as a real possibility given the interface's own comment that
the 80% threshold is "arbitrary," which sometimes signals a configurable value elsewhere that wasn't
found. Recommend (a), with prominent documentation, unless a board reviewer knows of an interop-test
requirement that specifically needs on-demand key update — but this is a judgment call, not
something this document can resolve unilaterally.

**Concrete interop-test evidence firming up (a), added on review**: the IETF QUIC interoperability
suite (`quic-interop/quic-interop-runner`, `quic.md`, the "KeyUpdate" test case) is documented as
`keyupdate, client only` — i.e. it applies only when kwik is acting as the *client*, not the server —
and its own description states: *"The client is expected to make sure that a key update happens
early in the connection (during the first MB transferred)"* and, on which side may initiate it,
*"It doesn't matter which peer actually initiated the update."* (source: the quic-interop-runner
project's `quic.md` test-case descriptions, found via web search, not previously cited in this
document.) Since this test only requires *a* key update to occur, from *either* side, during the
connection — and per §2.2 above the engine autonomously initiates rollovers on its own
confidentiality-limit heuristic regardless of whether kwik ever calls `updateKeys()` — a client-side
key update satisfying this test case will occur whether or not kwik's own `updateKeys()` method
exists. This means deleting `updateKeys()` is very likely safe with respect to *this specific*
interop check. It does not rule out some other conformance suite or advanced-caller use case wanting
on-demand key update, which is why this remains a recommendation for board sign-off rather than a
foregone conclusion, but it removes the most obvious interop-suite objection to option (a).

**OQ-2 (MEDIUM — now moot, superseded by OQ-4's resolution).** §1.4/§5: compatible version
negotiation (`ServerRolePacketParser.getAead`, the `getInitialPeerSecretsForVersion` path) needs
Initial secrets for a *second* QUIC version concurrently with the primary connection's negotiated
version. This question was originally framed as "if §5's option (b) or (c) is chosen, does the
engine's `versionNegotiated(QuicVersion)` one-shot `IllegalStateException`
(`QuicTLSEngineImpl.java:718-723`) block reusing the same engine instance for the alt-version Initial
decode?" — **that framing no longer applies**: §5.3/OQ-4 resolves this call site to option (a),
narrow HKDF-only retention, which never calls `versionNegotiated(...)` or touches the port for
Initial-only work at all (§5.2, site 2). Left here for traceability of the original question, not
because it still needs board time.

**OQ-3 (MEDIUM — now moot, superseded by OQ-4's resolution).** §1.4: the client-side
version-negotiation branch (`ClientRolePacketParser.getAead:62-68`) constructs its throwaway
`ConnectionSecrets` with `Role.Client` unconditionally and a `NullLogger`. This was originally about
whether a future throwaway-*port* replacement would need the same `Role`/logging treatment — **moot
under §5.3/OQ-4's resolution**, since this call site keeps constructing a throwaway `ConnectionSecrets`
exactly as it does today (option (a)), never a port/engine instance, so there is no port
client/server factory split to reconcile here. Left for traceability.

**OQ-4 (HIGH — resolved to a concrete per-site recommendation below; still needs board/Peter
sign-off, not a unilaterally final decision).** §5 laid out three options for the
Initial-key-multiplicity gap without picking one. A follow-up review re-examined each of the three
call sites individually against the question "does this site ever need two live Initial key sets at
once, or is derive-then-discard always enough" — full evidence in §5.2 — and that evidence converges
on a single answer applying to **all three sites, not a per-site split**:

  - **(a) Narrow HKDF-only Initial-key retention.** Keep a reduced `ConnectionSecrets` (Initial-level
    derivation only) alive specifically for the three call sites in §5, on the grounds that Initial
    secrets are RFC-9001-public-value-derived and therefore don't reopen the "raw secrets never
    requested" property. Cheapest to implement (closest to today's code), keeps `at.favre.lib.hkdf`
    in the dependency tree, and is the only option that doesn't require giving
    `ServerConnectorImpl`/`ServerConnectionCandidate` access to an `SSLContext`. Con: it's a
    documented, permanent exception to "everything crypto goes through the port," which needs board
    sign-off as a deliberate carve-out, not a default.
  - **(b) Throwaway engine/port instances per use case.** Construct a full (or as-minimal-as-possible)
    `QuicTlsPort` for each of the three call sites, matching the "everything through the port, no
    exceptions" reading of §3.1/§3.2. Needs `SSLContext` plumbed into two classes that don't have it
    today, and pays real per-call engine-construction cost on the server's accept-path hot path.
  - **(c) A dedicated "Initial-only" port/engine held once per `ServerConnector`/connection-candidate
    stage, shared/reused across calls.** Cheaper than (b) per-call, still "through the port" —
    *if* it's actually safe to reuse.

  **Resolution, with the evidence from §5.2 behind each part:**

  1. **Site 1 (Retry dual retention) rules out (c) outright, and makes (b) pointlessly expensive.**
     §5.2.1 confirmed this site needs the *old* and *new* Initial key sets both live, with **no
     bound on how long** — a single shared engine slot (c) cannot represent two live key sets by
     construction (§5.1's confirmed single-slot collision), and even (b)'s "one throwaway engine
     per use" doesn't fit cleanly here either, because what's actually needed is closer to "keep the
     *old* engine object around indefinitely, unmutated, while a second one holds the new keys" —
     which is functionally two long-lived objects, not one throwaway one. (a) already *is* exactly
     that shape (two independent, cheap `Aead` objects, no shared mutable state), at a fraction of
     the construction cost of keeping full engine/`SSLContext` machinery alive indefinitely for
     material that carries no confidentiality requirement in the first place.
  2. **Site 2 (compatible version negotiation) also rules out (c), and makes (b) unnecessary rather
     than merely expensive.** §5.2.2 found — contrary to this document's own initial working
     hypothesis — that this site *also* needs old-version and new-version Initial keys concurrently
     usable, per RFC 9369's explicit "MUST NOT discard" text quoted directly in
     `ServerRolePacketParser.getAead`'s own comment. (c) is unsafe for the same reason as site 1 if
     the shared engine's slot is the *primary* connection's own Initial keyspace (deriving the
     alt-version secret would destroy the primary's live Initial keys). But unlike site 1, this site
     doesn't need *persisted* dual state at all — `getInitialPeerSecretsForVersion` is already a
     pure, stateless, side-effect-free recomputation from public inputs (DCID + version), called
     fresh on every packet. (a)'s existing code *is* this mechanism, at zero marginal cost; (b)'s
     full throwaway `QuicTlsPort`+`SSLContext` construction per stray old-version packet buys
     nothing this site needs and isn't already getting from (a).
  3. **Site 3 (pre-connection candidates/refusals) makes (c) actively unsafe, not just costly, and
     makes (a) the only option that needs no new synchronization.** §5.2.3 found this is **not** a
     single-threaded hot path — `ServerConnectionCandidate.parseInitialPacket` runs on
     `context.getSharedServerExecutor()`, a shared pool of up to 10 threads, with only
     per-candidate (not global) serialization, specifically so the server's accept path can process
     multiple prospective connections in parallel; `ServerConnectorImpl.sendConnectionRefused` runs
     concurrently with all of those on the dedicated receive-loop thread. A shared single engine (c)
     would need a **new** lock added around every derive-then-use on this path, serializing exactly
     the traffic the thread pool exists to parallelize — a plausible DoS-amplification point under
     an Initial-packet flood, not merely a style concern, and a correctness patch for a hazard that
     does not exist today (today's per-call `ConnectionSecrets` construction has no shared mutable
     state at all). (b) avoids the shared-state hazard (each call gets its own object, trivially
     thread-safe) but still requires plumbing `SSLContext` into two classes that don't have it today,
     for no benefit over (a) once Initial secrets' non-confidential nature is accounted for — (a)'s
     per-call `ConnectionSecrets`+`Aead` construction is *already* trivially safe across the worker
     pool (no shared state, hence nothing to lock), with none of (b)'s `SSLContext`-plumbing cost.

  **Concrete recommendation: option (a) — narrow, permanent, documented HKDF-only Initial-key
  retention — for all three call sites, uniformly, not a per-site split.** This is a stronger,
  simpler conclusion than this document's own earlier framing (which treated the choice as
  genuinely close, §5's prior text) and stronger than the follow-up review's own working hypothesis
  (which expected a per-site split between (a) and (c)); the evidence instead shows (c) is
  structurally wrong for site 1, unsafe for sites 2 and 3 without new locking, and (b) is safe but
  strictly dominated by (a) at every site once Initial secrets' public, non-confidential,
  statelessly-re-derivable nature is taken into account. Practically: keep `ConnectionSecrets` (in a
  form reduced to Initial-level derivation only — the `computeInitialSecret`/`createKeys(Initial,
  ...)` path, `at.favre.lib.hkdf` and all, per §6.1) as a deliberate, narrow, permanently-documented
  exception to "everything else goes through the port," scoped strictly to
  `EncryptionLevel.Initial`/`KeySpace.INITIAL`, used at exactly the three call sites in §5.2 and
  nowhere else. **Confidence: high** on the evidence itself (every claim above is a direct code
  citation, not inference); the recommendation is nonetheless presented for board/Peter sign-off,
  not as unilaterally decided, because "make this the one permanent bypass of the port boundary" is
  a policy call about the fork's own architecture, not a fact this document can settle by itself.
  This also resolves §6.1's conditional framing of `at.favre.lib.hkdf`'s droppability
  (**retained**, Initial-only, per the above — not dropped) and OQ-2's question about
  `versionNegotiated(...)`'s one-shot `IllegalStateException` (**moot** — site 2 never calls that
  path on a shared/primary engine under this recommendation, since it never touches the port at all
  for Initial-only work).

**OQ-5 (LOW-MEDIUM).** §7.1's WARN-adjacent risk this document surfaced (§9, "what could make it
harder"): does kwik track its own AEAD confidentiality/integrity limits anywhere outside the
`crypto` package (e.g. connection-close-on-limit logic in `impl`/`server/impl`)? Not investigated as
part of this document — recommend a targeted grep during Step C, since the engine now owns that
limit tracking too (`QuicTransportException`'s doc on `encryptPacket`/`decryptPacket` mentions
"exceeding the AEAD cipher confidentiality/integrity limit" as a thrown condition), and any
kwik-side duplicate tracking would be a smaller-scale echo of the same "two authorities" shape the
original WARN named for key-phase state specifically.

**OQ-6 (LOW).** §7.2: this document recommends `FakeQuicTlsPort`-vs-real-engine be decided
per-test-file during Step D, not uniformly — confirm the board is comfortable with that
file-by-file judgment call rather than wanting a blanket policy (e.g. "all packet-level tests use
the real engine, matching the week-1 spike's precedent, for maximum fidelity" vs. "prefer the fake
port wherever the test doesn't need real bytes, for speed/isolation").

---

## 11. Summary of corrections this document makes to the SOW

For traceability, the concrete corrections/additions to `SOW-Kwik-JSSE-QUIC-TLS-Transport.md` §3.2
this document is making, so a future SOW revision can fold them in:

1. `CryptoStream.java` should not be listed as a §3.2 crypto-seam file — it has no AEAD/HKDF content
   and belongs entirely to §3.3 (§1.2).
2. The §3.2 "Files" list omits `ServerConnectorImpl.java`, `ServerConnectionCandidate.java`, and
   `SenderImpl.java`, all of which construct or consume `ConnectionSecrets`/`Aead` directly (§1.6).
3. A single engine instance appears to hold only one `INITIAL`-key-space slot at a time, which
   collides with three real call sites that need more than one Initial key set alive concurrently —
   this is new scope not previously identified anywhere in the SOW (§5), and it has a nontrivial
   effort impact (§9).
4. Kwik's public `updateKeys()` API has no engine-side equivalent at all (self-initiated key update
   is engine-autonomous, not caller-triggerable) — this is a capability-loss finding stronger than
   the SOW's WARN anticipated, and needs an explicit decision (§2.4, OQ-1).
5. `at.favre.lib.hkdf` is **retained**, scoped to Initial-only, per §5.3/OQ-4's resolved
   recommendation — not the unconditional "likely drops" the SOW's §3.2 phrasing implies (§6.1).
6. `io.whitfin.siphash` staying is now independently confirmed by a repo-wide grep and a full read
   of its sole consumer, not merely restated (§6.2).

**Corrections added in the follow-up review round (this revision):**

7. §2.2's key-update-trigger gating was imprecise: the engine's self-initiated-rollover check
   (`initiateKeyUpdate`/`usedByBothEndpoints()`) tests only whether a packet was successfully
   encrypted/decrypted in each direction under current keys, not specifically whether one was
   *acknowledged* in the current phase (RFC 9001 §6.1's literal text) — practically inert given the
   80%-confidentiality-limit trigger, but described precisely now rather than asserted as literal
   ack-gating (§2.2).
8. Old-key retention across a key-phase rollover is a **net correctness improvement** this rewrite
   delivers, not a neutral trade: kwik's current `KeyUpdateSupport.confirmKeyUpdateIfInProgress()`
   retains zero old keys (a live RFC 9001 §6.5 gap today), while the engine's `KeySeries.old` +
   `canUseOldDecryptKey` correctly retains one prior generation (§2.2.1).
9. OQ-1's "recommend deleting `updateKeys()`" disposition now cites concrete evidence: the IETF
   `quic-interop-runner`'s `keyupdate` test case is client-only and, per its own description,
   indifferent to which peer initiates the update — found via web search of the project's `quic.md`
   (§10, OQ-1).
10. §8's staged breakdown had a real circularity bug: Step C deleted `KeyUpdateSupport.java` while
    its sole construction site (`ConnectionSecrets.createKeys()`) was left for Step D, which would
    have broken the build between steps. Fixed by pulling the one-call-site unwrap into Step C,
    keeping Step D's scope otherwise unchanged (§8, Step C).
11. §7.1's blast-radius list omitted that `RetryPacket.java` and `VersionNegotiationPacket.java` both
    override the `QuicPacket` abstract methods this rewrite re-signatures (`parse`/
    `generatePacketBytes`), even though neither file's logic touches the `Aead` parameter at all —
    both need a mechanical, signature-only edit, called out explicitly so it isn't mistaken for
    real logic work (§7.1).
12. §8's Step B understated its §3.3 dependency: reaching `keysAvailable(ONE_RTT)` requires driving
    a real (if minimal) handshake through `consumeHandshakeBytes`/`getHandshakeBytes`, not just
    constructing the trivial `QuicOneRttContext` stub the earlier phrasing implied (§8, Step B).
13. §5's Initial-key-multiplicity gap is now **resolved**, not merely identified: per-site analysis
    (§5.2) shows the single-slot collision (confirmed empirically, §5.1, not just structurally)
    rules out a shared engine for all three call sites, converging on option (a) — narrow HKDF-only
    retention — uniformly, contrary to this document's own earlier framing that treated the
    trade-off as genuinely close (§5.3, OQ-4).
