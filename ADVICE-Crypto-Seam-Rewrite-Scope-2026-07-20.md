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
  (`:711-719`, `"which is arbitrary"` per the engine's own code comment), gated by RFC 9001 §6.1's
  "peer must have acked a packet in the current phase" rule (`initiateKeyUpdate`, `:746-773`, via
  `CipherPair.usedByBothEndpoints()`). **There is no public method on `QuicTLSEngine` — and none on
  `QuicTLSEngineImpl` beyond the interface either, confirmed by grepping the whole implementation
  file — that lets a caller request "roll over the 1-RTT write keys now."** The `headerGenerator`
  callback passed to `encryptPacket` receives whatever key phase the engine has already decided on
  (`:682-684`: `writeCipher.getKeyPhase()` is read *after* `maybeInitiateKeyUpdate` has possibly
  already rolled over) — the caller is a passive recipient of the engine's decision, never a driver
  of it.

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

Confirmed by reading `sun/security/ssl/QuicTLSEngineImpl.java:698-709`
(`deriveInitialKeys` delegates to `this.initialKeyManager.deriveKeys(...)`) and
`QuicKeyManager.java:93-100` (each per-`KeySpace` manager, including the `InitialKeyManager`, holds
a **single** `keySeries`/`CipherPair` — not a map keyed by connection ID or version). This is
strong structural evidence (not an exhaustive trace of `deriveKeys()`'s body) that **calling
`deriveInitialKeys` a second time on the same engine instance replaces the current Initial keys, it
does not layer a second set alongside the first.** Flagged as needing a short confirming spike
before implementation (§8, and OQ-4) — in the same spirit as the SOW's week-1 spike, this is cheap
to verify empirically and should not be assumed either way without doing so.

If confirmed, this collides with **three** real call sites found in §1.4/§1.6, none of which the
SOW's §3.2/§3.5 write-up anticipates, because both sections implicitly assume "one engine per
connection" is the whole story:

1. **Post-Retry dual retention.** `ConnectionSecrets.recomputeInitialKeys(byte[])` (`:130-134`)
   explicitly preserves the *old* Initial `Aead` (`originalClientInitialSecret`) alongside the *new*
   one, because a client Initial packet sent before the Retry arrived may still show up and needs
   the old DCID-derived keys to decode (`getOriginalClientInitialAead`, `:284-291`). Call sites:
   `QuicClientConnectionImpl.java:691`, `ServerConnectionImpl.java:485,635`.
2. **Compatible version negotiation.** Both packet parsers (§1.4) construct a second, throwaway
   Initial-only secret set for a *different* QUIC version while the primary connection continues
   under its negotiated version.
3. **Pre-connection candidate/refusal packets.** `ServerConnectorImpl`/`ServerConnectionCandidate`
   (§1.6) need Initial keys with **no connection and no engine instance at all** yet.

**Why this is not simply "another instance of the WARN's raw-secrets problem"**: RFC 9001 §5.2's
Initial secrets are, by design, not confidential — they're deterministically derived from a public
value (the destination connection ID) and a hardcoded public salt; RFC 9001 itself frames Initial
protection as defense against off-path/on-path corruption and identifiability, not confidentiality
from a capable observer. So unlike Handshake/Application secrets, keeping a narrow, INITIAL-only
HKDF path alive for these three cases would **not** reopen the "raw secrets never requested"
security property the fork is built around (§3.2's stated security point is about the negotiated
TLS secrets that back Handshake/App protection, not the public Initial derivation). This gives the
design a legitimate third option beyond "spin up a full throwaway engine+SSLContext" or "construct
two port instances per connection": keep `ConnectionSecrets`'s existing HKDF-only Initial-derivation
code (`computeInitialSecret`/the `Aes128Gcm`-via-`createKeys(Initial,...)` path) alive, scoped
*strictly* to `EncryptionLevel.Initial`/`KeySpace.INITIAL`, as a deliberate, narrow, documented
exception to "everything else goes through the port." This is a real design fork, not a foregone
conclusion — see OQ-4/OQ-5 for the three concrete options and why this document does not pick one.

---

## 6. Dependency cleanup — verified, not assumed

### 6.1 `at.favre.lib.hkdf` — conditionally droppable, not unconditionally

Repo-wide grep (`--include=*.java .` from the repo root, plus `build.gradle`/`module-info.java`
greps) confirms **exactly five source files** use `at.favre.lib.hkdf`, and no others exist anywhere
in the reactor (`qlog`, `cli`, `interop`, `samples`, `h09` all clean):
`ConnectionSecrets.java`, `BaseAeadImpl.java`, `ChaCha20.java`, `Aes128Gcm.java`, `Aes256Gcm.java`.
`core/build.gradle:49-50` declares it; `module-info.java:3` requires it
(`requires at.favre.lib.hkdf;`).

All five files are wholly deleted or gutted by this rewrite for Handshake/App-level material — **but
per §5, if the resolution to the Initial-key-multiplicity gap is "keep a narrow HKDF-only Initial
path," then `ConnectionSecrets` (in reduced form) and the dependency itself survive, scoped to
Initial only.** So: **confirmed droppable only if §5's gap is resolved by moving all three Initial
use-cases onto full/throwaway engine instances; retained, but with a much smaller blast radius (one
class, Initial-only), if any of §5's three use-cases keeps the HKDF path.** This is a direct,
evidence-based correction of the SOW's unconditional "likely drops" (§3.2's "Dependency cleanup"
bullet) — it should read as conditional on the §5 decision, not as a standalone item.

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

- `core/src/main/java/tech/kwik/core/crypto/`: `ConnectionSecrets.java` (deleted/reduced, §5/§6.1),
  `CryptoStream.java` (**out of this scope's remit**, §1.2), `KeyUpdateSupport.java` (deleted, §2.3),
  `Aead.java` (interface — most methods deleted, some may remain if §5 keeps a narrow Initial path),
  `BaseAeadImpl.java`, `Aes128Gcm.java`, `Aes256Gcm.java`, `ChaCha20.java` (all deleted, or all but
  one retained in reduced Initial-only form per §5), `MissingKeysException.java` (semantics
  preserved via `QuicKeyUnavailableException`/`keysAvailable`, not necessarily the same class — see
  §1.1).
- `core/src/main/java/tech/kwik/core/packet/`: `QuicPacket.java`, `ShortHeaderPacket.java` (rewrite,
  §2.3/§3), `LongHeaderPacket.java` (calls the rewritten `QuicPacket` methods but needs no method-
  body changes itself, confirmed by its two call sites both being into `QuicPacket`'s shared
  helpers), `PacketParser.java`, `ClientRolePacketParser.java`, `ServerRolePacketParser.java`
  (§1.4/§3), `RetryPacket.java` (**not** touched by this document's scope, §4 table).
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

**Step A — Key-space mapping spike + the §5 decision (prerequisite, ~2-3 days).** Before touching
`QuicPacket.java` at all: (1) empirically confirm or refute §5's "single Initial-key-slot per
engine" claim with a small spike analogous to the week-1 one (construct one engine, call
`deriveInitialKeys` twice with different DCIDs, confirm whether the first Initial `Aead` state
becomes unusable); (2) get an explicit board/Peter decision on which of OQ-4's three options
resolves the three call sites in §5; (3) only then finalize the `EncryptionLevel`↔`KeySpace`
mapping and, if applicable, the reduced `ConnectionSecrets` shape. This step produces no rewritten
`QuicPacket` code — it's a decision-and-verification gate, matching the week-1 spike's role for the
driver seam.

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
work (this step may need to borrow a minimal stub from §3.3 rather than waiting for it fully, since
`ONE_RTT` round-tripping needs *some* handshake to have happened first — flag this cross-seam
dependency explicitly to whoever sequences §3.2 against §3.3).

**Step C — Key-update ratchet deletion, as its own isolated, carefully-reviewed step (~2-3 days,
matching §7.2a's "+5d" line but split from the rest of the crypto-seam work deliberately).** Delete
`KeyUpdateSupport.java`, the `Aead` ratchet methods, and any ratchet call sites not already removed
as a side effect of Step B. This is called out as its own step, separate from Step B, specifically
*because* of the WARN: giving it an isolated diff and an isolated review pass makes it easy for a
reviewer to confirm "no kwik-side key-phase state remains" by inspection of a small, self-contained
change, rather than needing to audit it as one hunk inside a much larger `QuicPacket` rewrite. Add
the new targeted key-update test flagged in §7.2 here.

**Step D — `ConnectionSecrets`/dependency cleanup + full suite (~2-3 days, scope depends on Step
A's decision).** Delete (or reduce, per §5) `ConnectionSecrets.java`, `BaseAeadImpl.java`,
`Aes128Gcm.java`, `Aes256Gcm.java`, `ChaCha20.java`; remove `at.favre.lib.hkdf` from
`build.gradle`/`module-info.java` if Step A's decision allows it; rewrite the 7-file test fixture
migration (§7.2); re-point `SenderImpl.java:421` and the `ServerConnectorImpl`/
`ServerConnectionCandidate` sites per Step A's chosen option; run the full `core` suite (baseline:
990 tests, 989 pass / 1 pre-existing skip, per the RSA-fixture ADVICE doc's verification record) and
confirm no new failures beyond ones explicitly expected from this rewrite.

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

- **§5's Initial-key-multiplicity gap is new scope, not covered by any existing line in §7.2/§7.2a.**
  Depending on which of OQ-4's three options is chosen, this could range from "no extra cost" (if
  the narrow-HKDF-retention option is chosen, since that's close to today's code) to **+3-5 days**
  (if the "second throwaway engine per use case" option is chosen, since that means threading
  `SSLContext` availability into `ServerConnectorImpl`/`ServerConnectionCandidate`, which don't have
  one today, plus handling the possibility that even a throwaway engine construction is too heavy
  for the server's single-threaded receive-loop hot path in `ServerConnectorImpl`).
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

- Step A's spike (§8) confirming the *worse* of the two Initial-key-multiplicity outcomes, and OQ-4
  landing on the "second engine instance" option after all — the `SSLContext` plumbing into
  `ServerConnectorImpl`/`ServerConnectionCandidate` could itself uncover further gaps (e.g. whether
  a server-role engine construction requires client-address-specific SNI/ALPN context that isn't
  cleanly available at the pre-connection candidate stage).
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

**OQ-2 (MEDIUM).** §1.4/§5: compatible version negotiation (`ServerRolePacketParser.getAead`, the
`getInitialPeerSecretsForVersion` path) needs Initial secrets for a *second* QUIC version
concurrently with the primary connection's negotiated version. If §5's option (b) or (c) (below,
OQ-4) is chosen, does the engine's `versionNegotiated(QuicVersion)` call (already on the port,
one-shot per `QuicTLSEngineImpl.java:718-723`: *"A Quic version has already been negotiated
previously"* throws `IllegalStateException` on a second call) make it impossible to reuse the
*same* engine instance for the alt-version Initial decode even transiently? This document did not
trace far enough to answer definitively — flagged for the Step A spike (§8).

**OQ-3 (MEDIUM).** §1.4: the client-side version-negotiation branch
(`ClientRolePacketParser.getAead:62-68`) constructs its throwaway `ConnectionSecrets` with
`Role.Client` unconditionally and a `NullLogger` — worth confirming during implementation whether
the eventual throwaway-port replacement (if that's the chosen §5 option) needs the same
`Role`/logging treatment, or whether the port's client/server factory split (`forClient`/
`forServer`, `QuicTlsPortImpl.java:78-93`) changes what's cheap to construct here.

**OQ-4 (HIGH — this is the central open design question of this whole document, §5).** Three
concrete options for the Initial-key-multiplicity gap, no default recommended here because the
trade-off is genuinely close and touches things outside this document's read (server accept-loop
threading model, whether `SSLContext` is cheaply available at `ServerConnectorImpl`/
`ServerConnectionCandidate` construction time):
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
    today, and needs Step A's spike to confirm engine construction is cheap enough for
    `ServerConnectorImpl`'s single-threaded hot path.
  - **(c) A dedicated "Initial-only" port/engine held once per `ServerConnector`/connection-candidate
    stage (not per packet).** A middle ground: one long-lived engine instance reused across
    candidates/refusals (if the single-Initial-key-slot finding in §5 doesn't actually block reuse
    across *different* DCIDs when each call is `deriveInitialKeys` immediately before use, and
    nothing concurrent reads stale state) — cheaper than (b) per-call, still "through the port."
    Needs the Step A spike to know whether this is even safe (single-slot-replace semantics may make
    this fine for a single-threaded receive loop specifically, since there's no concurrent reader of
    the stale key).

  This document recommends running Step A's spike before picking one, but leans towards (a) or (c)
  over (b) on cost grounds — final call is for the board, not this document.

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
5. `at.favre.lib.hkdf`'s droppability is conditional on the §5/OQ-4 decision, not unconditional as
   the SOW's "likely drops" phrasing implies (§6.1).
6. `io.whitfin.siphash` staying is now independently confirmed by a repo-wide grep and a full read
   of its sole consumer, not merely restated (§6.2).
