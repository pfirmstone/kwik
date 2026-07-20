# ADVICE: Scope the handshake-driver seam rewrite (SOW §3.3) — agent15 push callbacks → JDK engine pull model, per-connection engine construction, server client-auth

Status: **SCOPE ONLY — no production code written or modified by this document.** This is a
design/scope document for board review before any implementation agent touches
`QuicClientConnectionImpl.java`, `ServerConnectionImpl.java`, `QuicConnectionImpl.java`,
`CryptoStream.java`, `ServerConnectionCandidate.java`, `ServerConnectorImpl.java`,
`ServerConnectionFactory.java`, or the builder/API surface. It follows the concreteness
convention of `ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md` (its predecessor and required
companion reading): exact file:line citations from source actually read, spike-verified claims
marked as such, explicit open questions, and SOW contradictions recorded rather than papered over.

Baseline for every citation below: this repo at `b8a7715f` ("docs: mark crypto-seam Step D
DONE"), i.e. **after** the crypto-seam Steps A–D landed. All line numbers are from that commit's
files as read in full for this document.

**Baseline drift note (added before commit):** while this document was being written, `master`
fast-forwarded one commit to `638f4238` ("Remove dead Wireshark secrets-file API surface" — the
crypto-seam doc's §11-item-33 follow-up, merged from `fix/remove-secrets-builder-flag` by the
concurrent session working that branch). That commit only removes the dead `Path
secretsFile`/`wiresharksecrets` plumbing (`Builder.secrets(Path)`, the CLI `-secrets` flag, and
the constructor parameter threaded through `QuicConnectionImpl`/`ConnectionSecrets` and its ~15
call sites); it deletes no handshake-drive logic and does not change any conclusion here.
Consequence for citations: line numbers in `QuicClientConnectionImpl.java` drift by −1 from
~line 63 onward (−2 after ~1424, −6 in the Builder region), `QuicConnectionImpl.java` and
`ConnectionSecrets.java` by −1 in their constructor regions, and single-line shifts in
`ServerConnectionImpl`/`ServerConnectionCandidate`/`ServerConnectorImpl`/`ClientRolePacketParser`.
Citations below are left pinned to `b8a7715f` (re-numbering ~150 citations by hand risks
introducing errors); `638f4238` also already performs two small items this document had listed
for Stage D (removal of `Builder.secrets(Path)`; the `QuicClientConnectionImpl` constructor's
`secretsFile` parameter), which shrinks that stage trivially. The `connectionSecrets.setClientRandom`
dead-weight note (§1.1) still holds — `638f4238` did not touch `setClientRandom`.

**Read in full for this document:** `SOW-Kwik-JSSE-QUIC-TLS-Transport.md` (all sections; §3.3,
§3.4, §3.5, §7.3b closely); `ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md` (all 2083 lines,
including the §11 correction log and the Step B/C/D "DONE" boxes);
`core/src/main/java/tech/kwik/core/impl/QuicClientConnectionImpl.java` (1777 lines),
`QuicConnectionImpl.java` (1108), `HandshakeState.java` (52);
`core/src/main/java/tech/kwik/core/server/impl/ServerConnectionImpl.java` (813),
`ServerConnectionCandidate.java` (397), `ServerConnectorImpl.java` (621),
`ServerConnectionThread.java`; `core/src/main/java/tech/kwik/core/server/ServerConnectionFactory.java` (92);
`core/src/main/java/tech/kwik/core/crypto/CryptoStream.java` (419);
`core/src/main/java/tech/kwik/core/packet/PacketParser.java` (252);
`core/src/main/java/tech/kwik/core/tls/QuicTlsPort.java` (296), `QuicTlsPortImpl.java` (270),
`QuicTransportParametersExtension.java` (head + serialize/parse bodies);
`core/src/main/java/module-info.java`; the DirtyChai engine source **read-only**
(`jdk/internal/net/quic/QuicTLSEngine.java` in full — 508 lines,
`QuicTransportException.java`, `QuicVersion.java`, and targeted reads of
`sun/security/ssl/QuicTLSEngineImpl.java`); and the JGDMS two-engine reference test
`JGDMS/jgdms-jeri/src/test/java/net/jini/jeri/ssl/QuicEngineMtlsTest.java` (457 lines, in full).
No file in DirtyChai or JGDMS was written to.

**Two spike runs were executed for this document** (scratch space only, plain `javac` against the
DirtyChai image, per the `--release`-cannot-see-`jdk.internal.net.quic` constraint recorded in SOW
§3.1): `DriverSeamOrderingSpike.java`, two real engines, real TLS 1.3 handshake to
`HANDSHAKE_CONFIRMED` on both ends. Results are load-bearing for §2.3/§7 below and are marked
**[SPIKE]** where used.

---

## 0. Executive summary of what this document changes relative to the SOW's §3.3 prose

1. **The server must set its local QUIC transport parameters BEFORE `consumeHandshakeBytes`
   ever sees the ClientHello** — the engine builds the EncryptedExtensions (including the
   transport-parameters extension) *during* CH consumption, not at `getHandshakeBytes` pull time.
   **[SPIKE — negative run: deferring the set until after consume but before the first pull
   produced a client-side fatal `0x016d missing_extension`; positive run: setting before consume
   completed to `HANDSHAKE_CONFIRMED`.]** This breaks kwik's current server flow, which computes
   its transport parameters *during* CH processing, after ALPN selection and per-protocol config
   merge (`ServerConnectionImpl.extensionsReceived`, `:344-405`). §2.3 and OQ-P3 below.
2. **The SOW's slowloris framing ("cert validation ... can pin that shared ≤10-thread pool") is
   wrong about which thread is at risk.** Post-candidate TLS processing runs on the dedicated
   per-connection `ServerConnectionThread` (`ServerConnectionThread.java:59-60`, one platform
   thread per connection), not the shared pool. The shared pool is pinned only by the
   pre-connection candidate stage, which does Initial-packet decryption and CH-completeness
   checking and **must remain engine-free** (it already is, and stays so under crypto-seam
   OQ-4's Initial-stays-on-`ConnectionSecrets` resolution). The handshake-completion **deadline**
   is still required — the idle timer is resettable by an attacker and is not a handshake
   deadline — but the "run cert validation per-connection" half of the SOW work item is
   **already satisfied by kwik's existing architecture**. §5 below.
3. **RFC 9369 compatible version negotiation is structurally incompatible with the engine** in
   kwik's current shape: the engine's `versionNegotiated(...)` is one-shot
   (`QuicTLSEngineImpl.java:718-723`, second call → `IllegalStateException`) and the EE is fixed
   at CH-consume time, while kwik switches its version *mid-CH-processing*
   (`ServerConnectionImpl.validateAndProcess:634-643`, `QuicClientConnectionImpl.handleVersionNegotiation:692-700`).
   Recommend scoping compatible-VN out of the fork (V1-or-V2-as-offered only); full VN restart
   (`restartHandshake`) stays deferred to Inc 4 as the SOW already says. OQ-P4.
4. **0-RTT and session tickets do not survive §3.3 even mechanically** — the crypto-seam doc's
   §6.1.1 "ConnectionSecrets must retain 0-RTT derivation" finding is correct *for the crypto
   seam in isolation*, but `computeEarlySecrets` takes an agent15 `TrafficSecrets` as its secret
   source, and both its call sites are `TlsStatusEventHandler.earlySecretsKnown()` callbacks that
   die with the engines this seam deletes. The JDK engine will never expose early secrets ("raw
   secrets never leave the engine"). So §3.5's "strip 0-RTT/early-data/tickets" is not a separate
   later work item: **§3.3 forces it**, and the two must land together. See the supersession note, doc-§3.3.
5. **The engine does not need `deriveInitialKeys` for the CRYPTO seam.** **[SPIKE — the full
   handshake completed without ever calling it.]** Initial-space *packet protection* stays on the
   legacy `ConnectionSecrets`/`Aead` path (crypto-seam OQ-4, signed off); the engine only needs
   CRYPTO **bytes** tagged `KeySpace.INITIAL`, not Initial AEAD keys. The port's
   `deriveInitialKeys` therefore has **no production caller** after §3.3 either — one less thing
   to wire, and a sharp illustration that the two key authorities never overlap.
6. **The engine error surface simplifies kwik's TLS-alert mapping.** `QuicTransportException`
   carries the final QUIC error code directly (`QuicTransportException.java:39-41`; the spike's
   negative run surfaced `0x016d` = `0x100 + missing_extension(0x6d)` already CRYPTO-ERROR-encoded
   by the engine). kwik's hand-rolled `quicError(TlsProtocolException)` mapping
   (`QuicConnectionImpl.java:858-871`) is replaced by `getErrorCode()` passthrough.

---

## 1. Current-state inventory — every agent15 touch point in the live driver/handshake paths

Repo-wide grep baseline: **15 files** in `core/src/main` import `tech.kwik.agent15` at
`b8a7715f`; **2 files** outside core (`cli/KwikCli.java`, `cli/InteractiveShell.java`); **11 test
files** in `core/src/test`. Exhaustive inventory of the production 15, grouped by the six live
paths named in this task's brief plus the API-surface stragglers.

### 1.1 Path 1 — client engine construction and callbacks (`QuicClientConnectionImpl.java`)

Class declares `implements ... TlsStatusEventHandler` (`:98`), field
`private final TlsClientEngine tlsEngine` (`:128`).

| Site | Lines | What it does today |
|---|---|---|
| Engine construction | `:205-236` | `TlsClientEngineFactory.createClientEngine(new ClientMessageSender() {...}, this)` in the constructor. The anonymous `ClientMessageSender` is the **push-model send half**: `send(ClientHello)` (`:207-214`, writes to Initial `CryptoStream`, flips `connectionState = Handshaking`, stashes `originalClientHello`; the `connectionSecrets.setClientRandom` call at `:211` is now dead weight — its only consumer, `appendToFile`, was deleted in crypto-seam Step D), `send(FinishedMessage)` (`:217-221`), `send(CertificateMessage)` (`:224-228`), `send(CertificateVerifyMessage)` (`:231-235`), all → `CryptoStream.write(HandshakeMessage, flush)`. |
| Handshake kickoff | `:527-563` | `startHandshake(...)`: `tlsEngine.setServerName(host)` (`:528`), `addSupportedCiphers(cipherSuites)` (`:529` — agent15 `TlsConstants.CipherSuite` list from the builder), `handleClientAuthentication()` (`:531`), builds `QuicTransportParametersExtension` and `tlsEngine.add(tpExtension)` (`:541-545`), `tlsEngine.add(new ApplicationLayerProtocolNegotiationExtension(...))` (`:546`), optional `EarlyDataExtension` (`:547-549`), `setNewSessionTicket` (`:550-552`), then `tlsEngine.startHandshake(NamedGroup.secp256r1, supportedSignatureAlgorithms)` (`:554-559` — hardcoded group + sig-scheme list, both agent15 enums). |
| Client-cert callback | `:565-578` | `handleClientAuthentication()`: `tlsEngine.setClientCertificateCallback(...)` returning `CertificateWithPrivateKey`, either from the builder's cert/key pair or via `CertificateSelector` over an `X509ExtendedKeyManager`. |
| Status callbacks (the push half being replaced) | `:581-586` `earlySecretsKnown()` (0-RTT secrets, agent15 `TrafficSecrets` via `computeEarlySecrets`); `:589-598` `handshakeSecretsKnown()` (post-Step-D: comment + `hasHandshakeKeys()` only); `:600-620` `hasHandshakeKeys()` (HandshakeState → `HasHandshakeKeys`, `currentEncryptionLevel = Handshake`, post-processing discard of Initial keys/PnSpace `:616-619`); `:623-639` `handshakeFinished()` (HandshakeState → `HasAppKeys`, `currentEncryptionLevel = App`, `connectionState = Connected`, `handshakeFinishedCondition.countDown()`); `:642-644` `newSessionTicketReceived(NewSessionTicket)`; `:647-662` `extensionsReceived(List<Extension>)` (EarlyData accept + **peer transport parameters** via `QuicTransportParametersExtension` instanceof — this is where GAP-1's push lands today, feeding `setPeerTransportParameters` `:913-967`). |
| Blocking connect | `:387-400` | `connect()` awaits `handshakeFinishedCondition` for `connectTimeout` ms; on timeout/failure `abortHandshake()` (`:447-451`) — **the client-only handshake deadline the SOW's DoS item refers to**. |
| Retry handling | `:731-770` | `process(RetryPacket)`: `packet.validateIntegrityTag(...)` (`:732`, kwik-local `javax.crypto`, agent15-free), `getCryptoStream(Initial).reset()` (`:742`), re-`generateInitialKeys()` (`:747`), and **re-sends the cached `originalClientHello` object** (`:759-760`) — an agent15 `ClientHello` retained at `:159/:213`. |
| Version negotiation (compatible) | `:683-700` | `process(InitialPacket)` → `handleVersionNegotiation` → `quicVersion.setVersion(...)` + `connectionSecrets.recomputeInitialKeys()` mid-handshake; `verifyVersionNegotiation` (`:1018-1032`) checks the `version_information` transport param after the fact. |
| HANDSHAKE_DONE | `:779-794` | `process(HandshakeDoneFrame)`: HandshakeState → `Confirmed`, discard Handshake PnSpace + keys. No engine notification exists today; the engine's `tryReceiveHandshakeDone()` must be added here. |
| Misc agent15 API surface | `:1267-1285` `addNewSessionTicket(NewSessionTicket)` / `getNewSessionTickets()`; `:1315-1317` `getServerCertificateChain()` → `tlsEngine.getServerCertificateChain()`; `:1324-1352` `trustAnyServerCertificate()` / `setTrustManager(X509TrustManager)` → `tlsEngine.setTrustManager` + `setHostnameVerifier`; builder: `cipherSuite(TlsConstants.CipherSuite)` (`:1644-1647`), `sessionTicket(...)` (`:1570-1579`), client cert/keymanager plumbing (`:1686-1719`). |

### 1.2 Path 2 — server engine construction and callbacks (`ServerConnectionImpl.java`)

Class declares `implements ServerConnection, TlsStatusEventHandler` (`:86`), field
`private final TlsServerEngine tlsEngine` (`:97`).

| Site | Lines | What it does today |
|---|---|---|
| Engine construction | `:142-149` | `tlsServerEngineFactory.createServerEngine(new TlsMessageSender(), this)` — the injected factory (constructor param `:129`) originates in `ServerConnectorImpl`/`ServerConnectionFactory` (§1.6). `addSupportedCiphers(...)` with the three QUIC-legal suites hardcoded. |
| Push send half | `:691-726` | Inner `TlsMessageSender implements ServerMessageSender`: `send(ServerHello)` → Initial `CryptoStream` (`:693-697`), `send(EncryptedExtensions/CertificateMessage/CertificateVerifyMessage/FinishedMessage)` → Handshake `CryptoStream` (`:700-719`), `send(NewSessionTicketMessage)` → App `CryptoStream` (`:722-725`). |
| Buffered-CH handoff | `:158-163`, `:518-524` | `bufferedInitialCrypto.setTlsEngine(tlsEngine)` + `setSender(sender)`; `postProcessCrypto` replays candidate-buffered messages. NOTE: in the live flow `ServerConnectionCandidate` passes `cryptoStream = null` to `createNewConnection` (`ServerConnectionCandidate.java:302`) and instead replays the raw Initial packets on the connection thread (`ServerConnectionThread.java:91-93`), so `bufferedInitialCrypto` is non-null only for callers that pass one (`ServerConnectionFactory.createNewConnection` javadoc `:69-78`). Both routes must be preserved or consciously collapsed (§2.3). |
| Status callbacks | `:279-283` `earlySecretsKnown()` (0-RTT via agent15 `TrafficSecrets`); `:286-294` `handshakeSecretsKnown()` (post-Step-D: `currentEncryptionLevel = Handshake` only); `:297-333` `handshakeFinished()` — the server's **transport orchestration block**: `sender.enableAppLevel()` (`:302`), discard Handshake PnSpace + keys (`:310-311`), `sendHandshakeDone(...)` (`:314`), `connectionState = Connected` (`:315`), HandshakeState → `Confirmed` (`:317-325`), `ConnectionEstablishedEvent` (`:326`), `startApplicationProtocolConnection` (`:328-331`), `connectionIdManager.handshakeFinished()` (`:332`); `:340-341` `newSessionTicketReceived` (no-op); `:344-405` `extensionsReceived(...)` — the biggest single block: ALPN selection against `ApplicationProtocolRegistry` (`:347-368`), `tlsEngine.addServerExtensions(ALPN)` (`:360`), **per-protocol config merge** `configure(apFactory, ...)` (`:363`, → `configuration.merge` + `streamManager.initialize` `:407-422`), peer transport-param validation `validateAndProcess` (`:373-386`), building the **server's own transport parameters** (`:388-400`), `tlsEngine.setSelectedApplicationLayerProtocol` (`:401`), `tlsEngine.addServerExtensions(new QuicTransportParametersExtension(...))` (`:402`), `setSessionData`/`setSessionDataVerificationCallback` (`:403-404`, RFC 9369 ticket-version binding). |
| `isEarlyDataAccepted()` | `:452-463` | agent15 callback for 0-RTT accept — dies with 0-RTT (doc-§3.3 supersession note). |
| HANDSHAKE_DONE / errors | `:588-592` server treats received HANDSHAKE_DONE as PROTOCOL_VIOLATION (unchanged); `quicError(TlsProtocolException)` inherited from base (`QuicConnectionImpl.java:858-871`) maps agent15 `ErrorAlert` → `0x100+alert`. |
| Compatible VN | `:630-643` | `validateAndProcess`: version switch mid-CH-processing + `recomputeInitialKeys()` (see §0 item 3). |

### 1.3 Path 3 — `CryptoStream.java` message parsing/dispatch (confirmed §3.3 property, per crypto-seam doc §1.2/§11 item 1)

- agent15 receive half: `tlsMessageParser.parseAndProcessHandshakeMessage(msgBuffer, tlsEngine, tlsProtectionType)`
  (`:203`, also `:209` buffered variant against the 60-line stub engine `:351-410`), typed dispatch
  `sendTo(HandshakeMessage, TlsEngine)` (`:337-349`, 8-way instanceof cascade), buffer-mode
  machinery for the candidate (`:169-199`), `quicExtensionsParser` hook (`:214-224`) that
  recognizes the transport-params codepoint inside CH/EE.
- **kwik-owned (agent15-free) machinery that survives**: CRYPTO reassembly `add(CryptoFrame)` via
  `ReceiveBufferImpl` + `MAX_STREAM_GAP` DoS bound (`:106-164`), the **TLS-record framing reader**
  (`:123-145` — reads the 1-byte msg type + 3-byte length itself, agent15 not involved) and its
  `maxMessageSize` per-level anti-DoS caps (`:132`, `:226-246`), and the entire **send half**:
  `write(byte[])` (`:289-293` — already byte-oriented!), `sendFrame` frame slicing (`:295-320`),
  `retransmitCrypto` (`:322-325`), `reset()` (`:327-331`).
- `tlsProtectionType` (`:61`, `:89-92`) exists only to be passed to agent15's parser — dies.

### 1.4 Path 4 — `HandshakeState` transitions

`HandshakeState.java:21-51`: `Initial, HasHandshakeKeys, HasAppKeys, Completed, Confirmed`, with
ordinal-based `transitionAllowed` (`:40-42`), `hasNoHandshakeKeys` / `hasOnlyHandshakeKeys` /
`isNotConfirmed` / `isConfirmed` predicates. **Writers** (complete list, grep-verified):
client `HasHandshakeKeys` (`QuicClientConnectionImpl.java:603-604`), client `HasAppKeys`
(`:629-630`), client `Confirmed` (`:781-782`), server `Confirmed`
(`ServerConnectionImpl.java:318-319`). **`Completed` has zero writers anywhere in the tree** —
it is dead state today (a finding for the §6 mapping). **Readers**: the
`handshakeStateListeners` list (`QuicConnectionImpl.java:136-138`), whose only registrant is
`RecoveryManager` (`RecoveryManager.java:122, 213, 227, 255, 334, 570-576` — PTO suppression
before handshake keys, client anti-deadlock probing while unconfirmed, loss-detector reset on
`Confirmed`). The state machine itself is agent15-free; only its *triggers* are agent15 callbacks.

### 1.5 Path 5 — TLS extensions: where QUIC transport parameters are added/read

- `QuicTransportParametersExtension.java` — `extends tech.kwik.agent15.extension.Extension`
  (`:51`); imports `TlsProtocolException`, `DecodeErrorException` (`:21-23`). Its
  `serialize()` writes the **full TLS extension including the 2-byte codepoint + 2-byte length
  header** (`:114-122`); `parse(ByteBuffer, Role, Logger)` likewise consumes the 4-byte header
  first (`:238-244`). The engine's `setLocalQuicTransportParameters` /
  `QuicTransportParametersConsumer` traffic in **extension-value bytes only**
  (`QuicTLSEngine.java:203-208, 220-228`; **[SPIKE]** — a bare 3-byte varint TP body was accepted
  and delivered verbatim, 3 bytes in → 3 bytes out). A value-only encode/parse pair is required
  (§3.4-owned; §2.4 defines the boundary).
- Added client-side: `tlsEngine.add(tpExtension)` `QuicClientConnectionImpl.java:545`; read
  client-side: `extensionsReceived` `:653-659`. Added server-side:
  `tlsEngine.addServerExtensions(...)` `ServerConnectionImpl.java:402`; read server-side:
  `extensionsReceived` `:373-386`. Read in CH/EE parsing: `CryptoStream.quicExtensionsParser`
  (`:214-224`).
- ALPN: agent15 `ApplicationLayerProtocolNegotiationExtension` added at
  `QuicClientConnectionImpl.java:546` and `ServerConnectionImpl.java:360` → becomes
  `SSLParameters.setApplicationProtocols` (spike-verified working, including server-side JSSE
  selection: offered `[proto-b, proto-a]` vs server `[proto-a, proto-b]` → `proto-a`).
- `EarlyDataExtension` (`QuicClientConnectionImpl.java:548`) — dies with 0-RTT.

### 1.6 Path 6 — pre-connection server paths (`ServerConnectionCandidate` / `ServerConnectorImpl` / `ServerConnectionFactory`)

- `ServerConnectionFactory.java`: holds and threads the `TlsServerEngineFactory`
  (`:46, :53-66, :79-87`) into every `ServerConnectionImpl`. Becomes the natural carrier for the
  server `SSLContext` + connection-TLS config instead (§2.2).
- `ServerConnectorImpl.java`: field `:80`; constructs the factory from cert files or a
  `KeyStore` in the `Builder` (`:602-608`), threads it at `:139-140`, `dispose()` at `:480`. The
  Builder's `withCertificate`/`withKeyStore` (`:538-562`) are the public server-credential API.
- `ServerConnectionCandidate.java`: imports agent15 `TlsProtocolException`, `ClientHello`
  (`:21-22`). Uses a buffer-mode `CryptoStream` (`:108, :132-133`) purely to answer **"do the
  buffered Initial packets contain a complete first message, and is it a ClientHello?"**
  (`checkClientHelloComplete`, `:256-275` — checks `getBufferedMessages().get(0) instanceof ClientHello`).
  This runs on the **shared ≤10-thread pool** (`:116, :151`,
  `ServerConnectorImpl.java:148-151`) and performs **no certificate work**. Its Initial-packet
  decryption uses a throwaway `ConnectionSecrets` (`:366-371`) — stays legacy per crypto-seam
  OQ-4; **the candidate stage needs no engine and must not get one** (an engine per unaccepted
  candidate would be a DoS-amplification gift; cf. crypto-seam §5.2.3).
- `ServerConnectorImpl.sendConnectionRefused` (`:378-392`) — legacy Initial path, zero §3.3 change
  (already confirmed by crypto-seam §6.1.2).

### 1.7 API-surface stragglers (agent15 types in public API, not handshake-drive logic)

These are inventory items 3/§3.6-boundary inputs, listed here so "every touch point" is honest:

| File | agent15 surface | Disposition (see §3.3 table) |
|---|---|---|
| `QuicClientConnection.java:138` | `Builder.cipherSuite(TlsConstants.CipherSuite)` | Public API change — OQ-P1 |
| `QuicSessionTicket.java:27,33` + `QuicSessionTicketImpl.java` (whole file) | `NewSessionTicket`, `TlsConstants.CipherSuite` | Deleted with 0-RTT/tickets (doc-§3.3 note) — OQ-P2 |
| `ConnectionTerminatedEvent.java:145-146` | `alertFromValue(int)` → `TlsConstants.AlertDescription` (pretty-printing TLS alerts in close events) | Trivially replaceable by a local alert-name table; schedule in §3.3 Stage D |
| `CertificateSelector.java:43-64` | returns `CertificateWithPrivateKey` | Dies with the client-cert callback — JSSE `KeyManager` does selection inside the engine |
| `ConnectionSecrets.java:22-23` | `TrafficSecrets` (only remaining user: `computeEarlySecrets`, `:163-167`) | Dies with 0-RTT (doc-§3.3 note) |
| `cli/KwikCli.java:285-291`, `cli/InteractiveShell.java:21` | `TlsConstants.CipherSuite` builder calls; `ByteUtils` | Follows whatever OQ-P1 decides; `ByteUtils` is a one-line hex util swap |

---

## 2. Target shape

### 2.1 The pull loop, precisely (engine semantics verified against source + spike + JGDMS reference)

Engine facts the driver is built on (all verified, not paraphrased from the SOW):

- `getHandshakeBytes(KeySpace)` **throws `IllegalStateException` if the argument is not the
  engine's current send key space** (`QuicTLSEngineImpl.java:437-440`) — the driver must ask
  `getCurrentSendKeySpace()` first, exactly as `QuicEngineMtlsTest.transfer` does
  (`QuicEngineMtlsTest.java:421-448`).
- The engine **kickstarts lazily**: the client's ClientHello is produced by the first
  `getHandshakeBytes` call (`produceNextHandshakeMessage` → `conContext.kickstart()`,
  `QuicTLSEngineImpl.java:450-455`). There is no `startHandshake()`; §1.1's kickoff block reduces
  to config + one pull.
- `getHandshakeBytes` returns null when nothing is pending, and **also serves post-handshake
  data**: the server's NewSessionTicket bytes surface through the same call
  (`QuicTLSEngineImpl.java:441-442`, `"|| !conContext.outputRecord.isEmpty() // session ticket"`)
  in `ONE_RTT` space — the driver must keep draining after completion, not stop at
  `isTLSHandshakeComplete()`.
- `consumeHandshakeBytes(KeySpace, ByteBuffer)` runs everything inline — message parsing, trust
  checks (GAP-3: `getDelegatedTask()` permanently returns null while `useDelegatedTask()` is
  true; the driver must never block-loop on `NEED_TASK`), remote-params delivery **[SPIKE: the
  `QuicTransportParametersConsumer` fires synchronously inside the consume call, both roles]**,
  and response production into the output record.
- `isTLSHandshakeComplete()` never becomes true from CRYPTO alone; the transport must drive
  `tryMarkHandshakeDone()` (server, after sending the HANDSHAKE_DONE frame it decides to send) and
  `tryReceiveHandshakeDone()` (client, on receiving it) — crypto-seam §11 item 22, re-confirmed
  by the spike (the pump stalls at `NEED_SEND_HANDSHAKE_DONE`/`NEED_RECV_HANDSHAKE_DONE` without
  them). Wrong-role calls throw `IllegalStateException` (`QuicTLSEngine.java:449-483`).
- `setOneRttContext(QuicOneRttContext)` is **mandatory** before any ONE_RTT encrypt/decrypt even
  when `keysAvailable(ONE_RTT)` is true (crypto-seam §11 item 22; Step B's
  `HandshakeShortHeaderPacketRealEngineRoundTripTest` is the in-repo proof and fixture).
- Handshake failure surfaces as `QuicTransportException` from `consumeHandshakeBytes`, carrying
  the wire-ready error code (`getErrorCode()`; TLS alerts arrive pre-encoded as `0x100+alert`) —
  replaces `quicError(TlsProtocolException)` (`QuicConnectionImpl.java:858-871`).

**Driver placement.** kwik is event-driven and single-threaded per connection on the receive
side (client: the `receiver-loop` thread, `QuicClientConnectionImpl.java:474-521`; server: the
per-connection `ServerConnectionThread`). The natural shape is a small
`HandshakeDriver` (new class, `tech.kwik.core.crypto` or `impl`) owned by `QuicConnectionImpl`,
with one entry point invoked from exactly three places:

1. **Inbound CRYPTO**: `CryptoStream.add(CryptoFrame)` (via `process(CryptoFrame ...)`,
   `QuicConnectionImpl.java:430-444`) — after reassembly yields contiguous bytes, feed
   `port.consumeHandshakeBytes(toKeySpace(level), bytes)` instead of the agent15 parse, then run
   a **drive step**.
2. **Kickstart**: client `connect()` (replacing `startHandshake()`, after config §2.2) runs one
   drive step to emit the CH; the server needs no kickstart (its first drive step happens when
   the replayed candidate Initial packets deliver CH bytes on the connection thread).
3. **HANDSHAKE_DONE frame events**: client `process(HandshakeDoneFrame ...)` adds
   `port.tryReceiveHandshakeDone()`; the server's completion step calls
   `port.tryMarkHandshakeDone()` immediately before `sendHandshakeDone(...)`
   (`ServerConnectionImpl.java:314`).

A **drive step** = loop: `space = port.getCurrentSendKeySpace(); buf = port.getHandshakeBytes(space)`;
while non-null/non-empty, `getCryptoStream(levelOf(space)).write(bytes)` — the byte-level
`CryptoStream.write(byte[])` at `:289-293` already exists and already handles framing into
CRYPTO frames, retransmission, and flushing; then evaluate state transitions (§6 mapping table):
`keysAvailable(HANDSHAKE)` → client/server `HasHandshakeKeys` actions; `keysAvailable(ONE_RTT)` →
`setOneRttContext` + `HasAppKeys` actions + server `sender.enableAppLevel()`;
`isTLSHandshakeComplete()` → the residual transport orchestration currently in
`handshakeFinished()` (§1.1/§1.2), including the server HANDSHAKE_DONE send and the client's
`handshakeFinishedCondition.countDown()`. Since every drive step runs on the connection's single
receive/processing thread, no new locking is introduced; the sender thread's only engine contact
remains the already-landed `encryptPacket` path (`SenderImpl.java:444`), and the engine is
internally synchronized.

`EncryptionLevel ↔ KeySpace` for CRYPTO: `Initial↔INITIAL`, `Handshake↔HANDSHAKE`, `App↔ONE_RTT`
via the existing `QuicTlsPort.toKeySpace` (`QuicTlsPort.java:283-295`); the reverse direction
(`levelOf(KeySpace)` for routing pulled bytes to the right `CryptoStream`) is a new 3-case switch
— note this is the first place a reverse mapping is needed (crypto-seam §4.1 explicitly declined
to spec one because §3.2 didn't need it; §3.3 does, and it should live beside `toKeySpace`).

### 2.2 Per-connection port construction and config flow

Nothing constructs a `QuicTlsPortImpl` in production today (crypto-seam §11 item 21 — the
`tlsPort` fields on `QuicConnectionImpl:124-135`, `SenderImpl:106`, `PacketParser:38` are
threaded but permanently null). Target:

**Client** (`QuicClientConnectionImpl` constructor replacing `:205-236`):
`QuicTlsPortImpl.forClient(sslContext, host, port)` (`QuicTlsPortImpl.java:78-82` — the
`peerHost/peerPort` advisory args carry SNI/session-cache hints), then in the replaced
`startHandshake()`:

| Today (agent15) | Target (port/JSSE) |
|---|---|
| `setServerName(host)` `:528` | `createEngine(peerHost, peerPort)` + (for verification) `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` — replaces `setHostnameVerifier` `:1347` |
| `addSupportedCiphers(cipherSuites)` `:529` | `SSLParameters.setCipherSuites(...)` with JSSE names mapped from the builder's list (or drop the knob — OQ-P1) |
| `startHandshake(secp256r1, sigSchemes)` `:558` | nothing — JSSE defaults govern groups/schemes; JGDMS constraint policy arrives via the `SSLContext` (SOW §6.4) |
| client cert callback `:565-578` + `CertificateSelector` | the `SSLContext`'s `KeyManager` (JSSE selects in-engine); builder cert/key pair → a synthesized single-entry `KeyManager`, or deprecate (OQ-P1) |
| `tlsEngine.add(tpExtension)` `:545` | `port.setLocalQuicTransportParameters(valueOnlyBytes)` **before the kickstart pull** |
| `extensionsReceived` params push `:653-659` | `port.setRemoteQuicTransportParametersConsumer(cache-then-apply)` registered at construction (GAP-1); the callback fires inside the consume of the EE bytes **[SPIKE]**, i.e. on the receiver thread, before any 1-RTT application frame of that or any later datagram can be processed — the GAP-1 "ordered barrier" is satisfied by same-thread ordering provided the cached bytes are applied at callback time or immediately after the consume returns, never deferred cross-thread (§2.4) |
| `trustAnyServerCertificate` / `setTrustManager` `:1324-1352` | fold into `SSLContext` construction (trust-all TM or custom TM into `ctx.init`) |
| — | `port.versionNegotiated(QUIC_V1/V2-of-originalVersion)` once, at construction (one-shot; see OQ-P4 for the compatible-VN consequence) |

Plus a new builder input: **`Builder.sslContext(SSLContext)`** (or equivalent) so JGDMS can hand
in the `AuthManager`-backed context directly — gated by
`QuicTlsPortImpl.isQuicCompatible(sslContext)` (`:66-68`; requires TLSv1.3 + DirtyChai B1's
`X509ExtendedTrustManager` relaxation). The existing keystore/trust-store builder options become
convenience wrappers that build an `SSLContext` internally. API shape = OQ-P1.

**Server** (`ServerConnectionFactory`/`ServerConnectorImpl`): replace the
`TlsServerEngineFactory` field/plumbing (§1.6) with an `SSLContext` + a per-server TLS config
holder (ALPN protocol list from `ApplicationProtocolRegistry`, `needClientAuth` flag — §4). Each
`ServerConnectionImpl` constructor calls `QuicTlsPortImpl.forServer(sslContext)`
(`QuicTlsPortImpl.java:89-93`), sets `SSLParameters` (protocols=TLSv1.3, ALPN list,
`setNeedClientAuth(true)` when demanded), registers the remote-params consumer, calls
`versionNegotiated(...)`, and — critically — **sets local transport parameters before the first
CH byte is consumed** (§2.3). `ServerConnectorImpl.Builder` gains `withSslContext(...)`;
`withCertificate`/`withKeyStore` (`:538-562`) become wrappers.

### 2.3 The server ordering problem (new, spike-found) and its resolution options

Today the server computes its transport parameters *during* CH processing
(`extensionsReceived:388-402`), after (a) ALPN selection and (b) the per-protocol
`configure(apFactory, ...)` merge (`:363`, `:407-422`) that can change
`maxOpenPeerInitiated*Streams` / buffer sizes — i.e. the advertised transport params can depend
on which ALPN the client asked for. With the engine, **[SPIKE]** the EE (with the
transport-params extension) is fixed when `consumeHandshakeBytes(CH)` returns; setting local
params after that is fatal (`0x016d`), and `getApplicationProtocol()` only becomes readable
*after* the same consume call. So per-ALPN transport parameters cannot be reproduced by simply
reordering calls. Options:

- **(a) Static params (recommended first cut):** compute server transport parameters from
  `ServerConnectionConfig` alone (as `initTransportParameters` `:424-438` mostly already does —
  the ALPN-dependent delta is only the `configuration.merge(protocolSettings)` effect), set them
  before consume; keep the per-protocol merge for **local runtime enforcement**
  (`streamManager.initialize(configuration)`) which is still applied after consume via
  `getApplicationProtocol()`. Consequence: the *advertised* limits are per-server, the *enforced*
  limits stay per-protocol; advertising less than enforcing is safe, advertising more is a
  flow-control-generosity change, not a security hole. Zero new parsing of untrusted input.
- **(b) Candidate-stage CH pre-scan:** the candidate already reassembles the full CH byte-exactly
  (§1.6); a small hand-written scanner could extract the ALPN list (and even the client transport
  params) before the connection/engine is created, restoring exact per-ALPN advertisement.
  Cost: new hand-written parser over attacker-controlled bytes on the accept path — exactly the
  surface §7.3a's hardening pass exists to police. Defer unless (a)'s regression matters.
- Decision = **OQ-P3** (Peter: is per-ALPN transport-param advertisement a capability anyone
  uses? Upstream kwik added it for multi-protocol servers; JGDMS runs one protocol).

Same-cause corollary: the server's ALPN response, session-data binding
(`setSessionData`/`setSessionDataVerificationCallback` `:403-404`) and `MissingExtensionAlert` /
`NoApplicationProtocolAlert` throws (`:351, :366, :377`) all move **inside** the engine: JSSE
selects ALPN (no-overlap → engine raises `no_application_protocol` itself — verify in Stage B
gate), absent transport params → engine raises `0x016d` itself **[SPIKE run 1]**, and RFC 9369
ticket-version binding dies with tickets (doc-§3.3 note). `extensionsReceived` as a method disappears
entirely; its `validateAndProcess` peer-param logic re-homes to the params-consumer path (§2.4).

The candidate's `checkClientHelloComplete` (`:256-275`) is rebuilt agent15-free: keep the
buffer-mode `CryptoStream` reassembly + kwik's own framing reader (§1.3 — already reads msg type
+ 3-byte length itself) and replace "parse into `ClientHello`" with "first complete message has
type `0x01`" (+ the existing `maxMessageSize` Initial cap of 3000 bytes, `CryptoStream.java:231`).
No agent15, no engine, no new parsing depth at the candidate stage.

### 2.4 §3.3 ↔ §3.4 / §3.5 boundary, defined precisely

- **§3.3 owns** (because the handshake cannot complete without them — engine hard-fails
  otherwise): registering the remote-params consumer (both roles), calling
  `setLocalQuicTransportParameters` at the right time (client: before kickstart; server: before
  first consume), caching the consumer's bytes, and invoking kwik's existing parameter
  *processing* (`setPeerTransportParameters` client `:913-967` / `validateAndProcess` server
  `:630-656`) from the cached bytes at the consumer-fire point.
- **§3.4 owns**: the value-only encode/decode themselves (today's `serialize()`/`parse()` are
  header-inclusive, §1.5 — §3.3 may interim-adapt by slicing 4 bytes, but the clean codec, the
  version-codepoint question, GAP-1's negative test "params delayed vs first app frame", and the
  formal ordered-barrier audit are §3.4 deliverables). Note the spike's thread finding shrinks
  GAP-1's barrier to a same-thread discipline (§2.2), which §3.4 should verify and document, not
  re-derive.
- **§3.5 boundary redrawn (SOW correction §7 item 4):** §3.3 *itself* deletes
  `earlySecretsKnown`/`isEarlyDataAccepted`/`EarlyDataExtension`/session-ticket wiring, because
  the callbacks and their secret source (`TrafficSecrets`) die with the engines. What remains for
  §3.5 afterwards is only the **positive construction-time guards** STD-010 §6.2 requires
  (`max_early_data_size = 0` assertion, ZERO_RTT send-path assertion) and the
  `ConnectionSecrets`/`ZeroRttPacket` 0-RTT machinery removal (which reverses crypto-seam
  §6.1.1's retention — see the doc-§3.3 supersession note for why that's a supersession, not a contradiction).
- **§3.6 owns**: `module-info.java` (`requires tech.kwik.agent15` removal), the `canRead` startup
  probe, and nothing else — §3.3's Stage D gate is "the residual agent15 reference list equals
  exactly the §3.6 removal list" (doc-§3.1/§3.2 tables).

### 2.5 Retry and Version Negotiation

- **Retry integrity**: `RetryPacket` is agent15-free (kwik-local `javax.crypto` with the RFC 9001
  §5.8 fixed keys). The SOW places `signRetryPacket`/`verifyRetryPacket` re-pointing under §3.3;
  since it is not needed for agent15 removal and both implementations are static-key/stateless,
  recommend **deferring the re-point to Inc 4** (where Retry is exercised) as a small,
  independent diff. OQ-B4.
- **Client CH-retransmit after Retry** (`:759-760` writes the cached agent15 `ClientHello`
  object): the driver caches the **raw CH bytes** it pulled at kickstart and rewrites those after
  `getCryptoStream(Initial).reset()`. RFC 9002 §6.3 requires the same CH; the engine has no
  "re-emit CH" API short of `restartHandshake()` (which resets TLS state — wrong tool; it exists
  for Version Negotiation, `QuicTLSEngine.java:210-218`). Byte-caching is the correct mechanism;
  note it also removes the `originalClientHello` field (`:159`).
- **Version Negotiation packets / `restartHandshake()`**: unchanged scope — Inc 4, not §3.3's
  first landing. **Compatible VN**: recommend removal (OQ-P4, §0 item 3).

---

## 3. The delete-vs-repoint boundary for agent15

### 3.1 Dies in §3.3 (no longer referenced when Stage D completes)

- `TlsClientEngine`/`TlsClientEngineFactory`/`ClientMessageSender` + the four `send(...)`
  overrides; `TlsServerEngine`/`TlsServerEngineFactory`/`ServerMessageSender`/`TlsMessageSender`;
  `TlsStatusEventHandler` (both `implements` clauses and all 7 callback methods × 2 roles);
  `TlsEngine` (incl. `QuicConnectionImpl.getTlsEngine()` abstract, `:996`, and
  `CryptoStream`'s engine field/stub);
- `TlsMessageParser`, `ProtectionKeysType`, `handshake.*` message types, `extension.Extension`
  hierarchy uses in `CryptoStream`/candidate/connections; `InternalErrorAlert`,
  `MissingExtensionAlert`, `NoApplicationProtocolAlert`, `ErrorAlert` +
  `quicError(TlsProtocolException)`;
- `NewSessionTicket` + `QuicSessionTicket`/`QuicSessionTicketImpl` + builder `sessionTicket(...)`
  + `earlySecretsKnown`/`isEarlyDataAccepted`/`EarlyDataExtension`/`computeEarlySecrets`/
  `TrafficSecrets` (doc-§2.4 and doc-§3.3 note);
- `CertificateWithPrivateKey` + `CertificateSelector` + `setClientCertificateCallback`;
- `TlsConstants` uses in: cipher-suite lists (`:529`, `ServerConnectionImpl:143-149`), signature
  schemes (`:82, :555-558`), `ConnectionTerminatedEvent.alertFromValue` (local table replaces),
  `QuicClientConnection.Builder.cipherSuite` (per OQ-P1);
- `TlsProtocolException` throughout (`QuicConnectionImpl.process(CryptoFrame)` catch `:436-439`
  → catches `QuicTransportException`; candidate's `checkClientHelloComplete` signature).

### 3.2 Waits for §3.6

**Target: zero agent15 types referenced after §3.3 Stage D** in `core/src/main` — §3.6 then only
deletes `requires tech.kwik.agent15;` (`module-info.java:2`), the Gradle dependency, and adds the
`canRead` probe. The Stage D gate is the grep proving that zero (excluding comments). Outside
`core`: `cli`'s two files follow OQ-P1's API decision in the same stage; test sources
(11 files, §1 header) are migrated per-stage as their production counterparts change.

**If OQ-P1 resolves to "keep source compatibility"** (not recommended), then
`TlsConstants.CipherSuite` in `QuicClientConnection.Builder` survives §3.3 and §3.6 cannot
complete — flagged so the dependency is explicit: **§3.6's `requires` removal is hostage to the
OQ-P1 API decision.**

### 3.3 Supersession note: crypto-seam §6.1.1's 0-RTT retention

Crypto-seam §6.1.1 (and §11 item 14) mandated retaining `computeEarlySecrets` +
`Aes256Gcm`/`ChaCha20`/`BaseAeadImpl` so Step D would not "silently break kwik's live, tested
0-RTT support." That was correct *for a world where the agent15 engines still run the handshake*
(they still do, at `b8a7715f`). §3.3 removes the only object that can supply
`computeEarlySecrets`' `TrafficSecrets` argument, and the SOW excludes 0-RTT by construction
(§3.5, STD-010 §6.2 normative MUST). So when §3.3 Stage D lands: `computeEarlySecrets` loses its
last caller and is deleted; `ZeroRttPacket` becomes undecryptable server-side (correct,
fail-closed — the server should drop/never-derive, which is what "no early keys exist" gives for
free) and unusable client-side (`connect(earlyData)` path removed); whether
`Aes256Gcm`/`ChaCha20`/`BaseAeadImpl` then shrink again (Initial is always AES-128) is a small
follow-up cleanup, **not** to be done inside §3.3's diffs (keep the WARN-style separation of
concerns: one authority-removal per reviewable step). Record this as a planned amendment to the
crypto-seam doc's file-survival table, contingent on §3.3 landing — not as an error in it.

---

## 4. Server client-auth (mTLS) wiring — the fork's mission

Cross-checked against `QuicEngineMtlsTest` (the working two-engine SPIFFE reference):

- **Demand**: `SSLParameters.setNeedClientAuth(true)` on the server engine before the handshake
  (`QuicEngineMtlsTest.java:280-289` — set together with `setApplicationProtocols` and
  `setProtocols({"TLSv1.3"})`, then one `setSSLParameters` call). In kwik: done in
  `ServerConnectionImpl`'s port construction block (§2.2), driven by a new server-side config
  knob. **kwik has no client-auth API anywhere today** (grep-verified: zero hits for
  needClient/wantClient in core) — the knob is new API. Recommended shape: a
  `ServerConnectionConfig` boolean (default **true** for this fork? — OQ-P5; JGDMS always wants
  it, but upstream-kwik-compatible default is false) plus pass-through when the caller supplies
  `SSLParameters`/`SSLContext` directly.
- **Receive/validate**: nothing kwik-side. The CertificateRequest is produced by JSSE inside
  `getHandshakeBytes` pulls; the client's Certificate/CertificateVerify are consumed inside
  `consumeHandshakeBytes`; validation runs **inline** in that call (GAP-3), dispatching to
  whatever `X509ExtendedTrustManager` the `SSLContext` carries — for JGDMS, `AuthManager`/
  `FilterX509TrustManager` via DirtyChai B2's 3-arg adapter (`checkClientTrusted`, SOW §6.1). The
  SPIFFE trust manager plugs in at **`SSLContext` construction in JGDMS**
  (`QuicEngineMtlsTest.serverSslContext()`, `:107-112` — `Utilities.getServerSSLContextInfo`),
  not anywhere in kwik: kwik's only obligation is to accept a caller-supplied `SSLContext`
  unmodified (SOW §4 "auth-agnostic") and to surface the result.
- **Surface the result**: `port.getSession().getPeerCertificates()` (mirrors
  `QuicEngineMtlsTest:149-166`). kwik's existing `getServerCertificateChain()`
  (`QuicClientConnectionImpl.java:1315-1317`) re-points to the session; add the server-side
  equivalent (`ServerConnection` has none today — JGDMS's `ServerEndpoint` layer will need the
  client's chain/principal for the Subject; expose `SSLSession` or the chain — OQ-B2).
- **Rejection path**: an untrusted client SVID surfaces as a fatal alert →
  `QuicTransportException` out of `consumeHandshakeBytes` on the server's connection thread →
  connection close with the engine-encoded `0x100+bad_certificate`-class code
  (`QuicEngineMtlsTest.testUntrustedClientSvidRejectedByServerTrustCheck`, `:177-199`, proves
  the engine-pair behavior; kwik Stage C's negative test mirrors it over real transport).
- **Engine-pair mechanics already proven** by that test: construction gated by TLSv1.3
  (`isQuicCompatible`), mandatory registered params-consumer + non-empty-or-empty-but-set local
  params, `versionNegotiated(QUIC_V1)`, pull loop keyed by `getCurrentSendKeySpace`, and the
  HANDSHAKE_DONE stall-then-advance step (`driveHandshake:386-400`) — the kwik driver replicates
  each of these against real transport instead of an in-memory pump.
- **Predecessor status** (SOW §6.1): B1/B2/B3 verified in DirtyChai trunk `98bcc58115f`; the
  human-written DirtyChai mTLS-server functional test (ADVICE item D) remains outstanding —
  `QuicEngineMtlsTest` lives in JGDMS and covers the behavior, but the SOW still wants the
  DirtyChai-side test before Inc 3 is called validated. Unchanged by this document; restated so
  Stage C's gate references it.

---

## 5. Server handshake-completion deadline (DoS)

**Thread-model correction to the SOW (see §0 item 2).** Verified placement of work:

- Candidate stage (shared ≤10 pool, `ServerConnectorImpl.java:148-151`): Initial decrypt +
  CH-completeness only; engine-free before and after §3.3; bounded by the candidate's own 30s
  cleanup task (`ServerConnectionCandidate.java:135-137`) and `MINIMUM_NON_FINAL_CRYPTO_LENGTH`.
  No cert work ever runs here. The SOW's "require cert validation off the shared pool" is
  **already the architecture**; keep it true by never constructing an engine pre-acceptance.
- Connection stage: all `consumeHandshakeBytes` (hence all trust-manager work, incl. a hanging
  CRL/OCSP fetch) runs on that connection's dedicated `ServerConnectionThread`. A hostile peer
  pins **its own** thread, not the pool. Residual risks the deadline must bound: (i) unbounded
  count of half-open connections each holding a platform thread + engine; (ii) a handshake kept
  alive indefinitely by resetting the idle timer with ack-eliciting handshake-space packets
  (`idleTimer.packetProcessed()` fires on every processed packet,
  `QuicConnectionImpl.java:405-420` — the idle timeout, set from CH-time params at
  `ServerConnectionImpl.java:646`, is **not** a handshake deadline); (iii) a trust-manager hang
  that outlives the peer.
- **Concrete design**: schedule a one-shot deadline on the connection's existing per-connection
  `scheduler` (`QuicConnectionImpl.java:155, 960-973`) at `ServerConnectionImpl` construction;
  duration from a new `ServerConnectionConfig.handshakeCompletionTimeout()` (generous default —
  mirror JGDMS P1/F2's read-progress-deadline default per the SOW; suggest 30s); cancel it in the
  completion step (where `connectionState = Connected`); on fire, if
  `handshakeState.isNotConfirmed()`: `immediateCloseWithError(CONNECTION_REFUSED or
  APPLICATION_ERROR-class code, "handshake deadline exceeded")` → existing close path stops the
  sender and (via `closeCallback`) deregisters. A close can't unblock a thread stuck *inside* a
  hanging trust manager (risk iii) — that thread leaks until the fetch times out; document that
  the real mitigation for (iii) is JGDMS-side (no network-fetching revocation on this path /
  socket timeouts on the fetcher), and the deadline bounds (i)+(ii) fully. Timer ownership,
  abort path, and test (a client that completes CH then stalls, sending periodic PINGs — assert
  close at deadline despite idle-timer resets) = Stage C gate items.

---

## 6. HandshakeState reconciliation

**Recommendation: mapped pair, kwik's `HandshakeState` remains the transport-side authority;
engine state is never stored, only sampled at drive steps.** Rationale: (a) kwik's enum encodes
*transport* facts (`Confirmed` = HANDSHAKE_DONE sent/received — a frame event) consumed by
`RecoveryManager` for PTO/loss decisions (§1.4) on other threads via listener/volatile; the
engine's enum encodes *TLS-driver* facts (`NEED_SEND_CRYPTO` etc.) that are only meaningful
mid-drive-step; (b) a single authority would force either the recovery machinery onto engine
polling (cross-thread reads of a state the engine mutates inside its own locks — new race
surface) or the engine's states into kwik's ordinal-based `transitionAllowed` lattice (they
don't order). Mapping table (all transitions fire inside a drive step on the connection thread,
under the existing `handshakeStateLock` idiom):

| Engine observation (sampled in drive step) | kwik transition + orchestration re-fired |
|---|---|
| `keysAvailable(HANDSHAKE)` first true | → `HasHandshakeKeys`; client: `currentEncryptionLevel = Handshake`, post-processing discard of Initial keys/PnSpace (`QuicClientConnectionImpl:600-620` body, kept verbatim); server: `currentEncryptionLevel = Handshake` |
| `keysAvailable(ONE_RTT)` first true | `port.setOneRttContext(...)` (mandatory, §2.1) then → `HasAppKeys`; server: `sender.enableAppLevel()` |
| `isTLSHandshakeComplete()` first true | client: `connectionState = Connected`, countdown latch (`:623-639` residue); server: `tryMarkHandshakeDone()` → send HANDSHAKE_DONE → discard Handshake keys/PnSpace → `Connected` → **`Confirmed`** → events + app-protocol start (`:297-333` residue, order preserved) |
| (client) HANDSHAKE_DONE frame received | `tryReceiveHandshakeDone()` + → `Confirmed` + discard Handshake keys/PnSpace (`:779-794`, kept) |

Notes: (1) `HandshakeState.Completed` is dead today (no writer, §1.4) — either start using it
for the client's `isTLSHandshakeComplete`-but-not-yet-DONE window (it models exactly
`NEED_RECV_HANDSHAKE_DONE`, during which RFC 9001 permits 1-RTT sends) or delete it; recommend
**use it**, since `RecoveryManager:227`'s `isNotConfirmed` PTO logic already distinguishes that
window. Board should check the ordinal lattice still holds (`Completed` < `Confirmed` — it does).
(2) Race analysis: transitions are single-writer (connection thread); readers are
`RecoveryManager` (volatile, listener-driven — unchanged pattern) and the sender thread's
key-availability checks, which already fail soft via `QuicKeyUnavailableException` → drop
(`PacketParser.java:81-107`, `SenderImpl` drop-on-unavailable). The one genuinely new ordering
obligation: `setOneRttContext` must happen-before any sender-thread ONE_RTT `encryptPacket`;
enforced by doing it in the same drive step that precedes `enableAppLevel()`/`HasAppKeys` (the
sender only attempts App-level sends after `enableAppLevel`, `ServerConnectionImpl:302` /
client `sender.enableAllLevels()` at `:191` — client side must therefore gate App sends on
`HasAppKeys` as it implicitly does today via key absence; Stage A gate asserts the port throws
rather than NPEs if violated). (3) `getHandshakeState()` is still consulted *within* a drive
step (e.g., distinguishing stall-vs-done, mirroring `driveHandshake:386-400`), just never stored.

---

## 7. SOW §3.3 corrections found (code- or spike-verified)

1. **[SPIKE]** Server local transport params must be set before `consumeHandshakeBytes(CH)`;
   "route local params through `setLocalQuicTransportParameters`" (SOW §3.4) silently misses
   that this inverts the server's current compute-during-CH flow and kills per-ALPN param
   advertisement (§2.3, OQ-P3).
2. **[SPIKE]** Remote-params consumer fires synchronously inside `consumeHandshakeBytes` (both
   roles) — GAP-1's cache-plus-barrier shrinks to a same-thread application discipline (§2.2/§2.4).
3. The slowloris claim's thread model is wrong: cert validation will run on the per-connection
   `ServerConnectionThread`, not the shared ≤10 pool; the pool is only exposed at the engine-free
   candidate stage. The deadline is still needed, the "move validation off the pool" half is
   already true (§5).
4. §3.5's 0-RTT/ticket strip is not adjacent-later work — §3.3 forces it (dead callbacks, dead
   `TrafficSecrets` source); boundary redrawn in §2.4, crypto-seam §6.1.1 superseded per doc-§3.3 note.
5. `versionNegotiated` one-shot (engine) vs kwik's mid-handshake compatible-VN switch — SOW lists
   `versionNegotiated(...)` as a simple drive call; it is actually a structural exclusion of
   RFC 9369 compatible negotiation (OQ-P4).
6. SOW §3.3's file list omits `CryptoStream.java` (now confirmed here as §3.3's, per crypto-seam
   §11 item 1), `ServerConnectionThread.java` (drive-step host), `QuicSessionTicket(-Impl)`,
   `CertificateSelector.java`, `ConnectionTerminatedEvent.java`, `QuicClientConnection.java`
   (builder API), and the `cli` subproject — all inventoried in §1.
7. `deriveInitialKeys` is not part of the §3.3 drive set at all **[SPIKE — handshake completes
   without it]**; the SOW's §3.2 list includes it, but after crypto-seam OQ-4 nothing production
   calls it. Keep on the port (harmless, mirrors the engine) but expect zero callers.
8. SOW §7.1's claim "construction is one static client site + one injected server factory, both →
   build an SSLContext and `createEngine()`" understates the server side: the factory chain
   (`ServerConnectorImpl.Builder` → `TlsServerEngineFactory` → `ServerConnectionFactory` →
   `ServerConnectionImpl`) plus the candidate's engine-free CH check are four coordinated sites,
   and the Builder's public credential API changes shape (§2.2/§2.3).
9. The engine emits post-handshake NST bytes through `getHandshakeBytes(ONE_RTT)`
   (`QuicTLSEngineImpl.java:441-442`) — no SOW mention; drivers that stop pulling at completion
   will strand JSSE's resumption tickets (harmless for JGDMS if resumption is dropped, but the
   drive loop should drain anyway).

---

## 8. Staged breakdown (A→D checkpoint pattern), estimates, blast radius

Prerequisite state: crypto-seam Steps A–D are on `master`; the codebase compiles and is green
(997/994/0/3) but **cannot complete a live handshake past Initial** (null `tlsPort`,
crypto-seam §11 item 21). §3.3 is what restores a connectable kwik.

**Stage A — HandshakeDriver core + CryptoStream byte pipe + client path (4–6 d).**
New `HandshakeDriver` (§2.1); `CryptoStream` receive half → `consumeHandshakeBytes` (keep
reassembly/framing/caps; delete parser/dispatch/stub/buffer-mode-parse — buffer mode itself
survives for the candidate, §2.3); client construction → `forClient` + config mapping (§2.2
table); client callbacks deleted, orchestration residues re-fired per §6 table; Retry
CH-byte caching; error mapping → `QuicTransportException.getErrorCode()`.
*Gate (independently verifiable):* client `connect()` completes to `Confirmed` against a
test-harness peer built from a raw second engine over real UDP loopback packets (fixture
precedent: `HandshakeShortHeaderPacketRealEngineRoundTripTest`'s pump + `FakeQuicTlsPort` for
unit level), plus unit tests for the drive-step state table; full suite green with server-side
tests temporarily pinned to legacy paths only where they must be.

**Stage B — server path (5–7 d).**
`ServerConnectionFactory`/`ServerConnectorImpl`/Builder → `SSLContext` carrier;
`ServerConnectionImpl` port construction with **params-before-consume** ordering (§2.3 option a);
candidate CH-completeness rebuilt agent15-free; `extensionsReceived` decomposed (ALPN → JSSE,
params → consumer path, per-protocol merge → post-consume runtime-only); server completion step
with `tryMarkHandshakeDone`.
*Gate:* loopback kwik-client ↔ kwik-server handshake green (SOW Inc 1 milestone);
`getSession().getPeerCertificates()` populated both ends (server-auth-only);
no-ALPN-overlap and missing-params negative cases produce the engine's own fatal codes;
anti-amplification/Retry paths still pass existing tests (SOW §7.3b checkpoint opens here, closes
Inc 4).

**Stage C — mTLS + deadline (3–5 d).**
`needClientAuth` config + `SSLParameters` pass-through; server peer-identity exposure (OQ-B2);
handshake-completion deadline per §5; positive + negative mTLS tests mirroring
`QuicEngineMtlsTest` over real transport (SPIFFE-shaped SVIDs if cheap, else plain X.509 pos/neg
with the SPIFFE run deferred to JGDMS integration); slowloris test (stalling PINGing client
closed at deadline).
*Gate:* SOW Inc 3's acceptance criteria minus interop: client-auth required and enforced
(wrong/absent cert → rejected), deadline in force, candidate stage demonstrably engine-free
(code inspection + no engine construction before `createNewConnection`).

**Stage D — agent15 decommission + API surface (3–5 d).**
Delete §3.1's list: tickets/0-RTT wiring, `CertificateSelector`, `ConnectionTerminatedEvent`
alert table, builder/API changes per OQ-P1, `cli` follow-through; test-suite migration of the 11
agent15-importing test files (largest single test cost: `QuicClientConnectionImplTest` /
`ServerConnectionImplTest` mock `TlsStatusEventHandler` flows extensively — port-mock or
real-engine fixtures per crypto-seam OQ-6's per-file policy).
*Gate:* repo-wide grep: agent15 references = exactly {`module-info.java:2`, Gradle dependency}
(the §3.6 removal list); whole-reactor build green; full suite at (new) baseline with a written
delta accounting (expected losses: ticket/0-RTT tests, agent15-mock tests — each named, none
silent).

**Estimate: 15–23 days** (≈3–4.5 weeks) for Stages A–D. Consistent with the SOW §7.2 lines it
replaces (pull loop 5–8 d + setter mapping inside 3–5 d + `CryptoStream` byte pipe 3–5 d +
Inc-1 bring-up 3–5 d + part of the mTLS 5–8 d), *provided* OQ-P1/P3/P4 resolve to the
recommended (capability-trimming) options; each "keep the capability" answer adds real work
(per-ALPN pre-scan ≈ +3–4 d incl. hardening; compatible-VN preservation ≈ unbounded until a
design exists — it may not have one). Risks that push high: the 11-file test migration
ballooning (mitigant: Step B/C/D of the crypto seam already built the real-engine fixtures), and
live-loopback flakiness during Stage B bring-up (mitigant: the JGDMS pump loop as an oracle for
"engines fine, transport at fault").

### Blast radius (production)

| File | Stage | Nature |
|---|---|---|
| `crypto/CryptoStream.java` | A | rewrite receive half; delete parser/dispatch/stub (~200 of 419 lines) |
| new `HandshakeDriver` (+ `levelOf`) | A | new, ~150-250 lines |
| `impl/QuicClientConnectionImpl.java` | A (+D api) | ctor, startHandshake, 7 callbacks, Retry, HandshakeDone, builder |
| `impl/QuicConnectionImpl.java` | A | `tlsPort` populate, `getCryptoStream` signature, `getTlsEngine` removal, error mapping, CryptoFrame catch |
| `impl/HandshakeState.java` | A | `Completed` decision only (§6 note 1) |
| `server/impl/ServerConnectionImpl.java` | B | ctor, callbacks, `extensionsReceived` decomposition, completion step |
| `server/ServerConnectionFactory.java`, `server/impl/ServerConnectorImpl.java` | B | SSLContext carrier + Builder API |
| `server/impl/ServerConnectionCandidate.java` | B | agent15-free CH check |
| `server/impl/ServerConnectionThread.java` | B | drive-step hookup only (likely zero-diff if driver is invoked from CryptoStream path) |
| `tls/QuicTransportParametersExtension.java` | A/B interim slice-adapter; real codec §3.4 | |
| `send/SenderImpl.java`, `packet/PacketParser.java` | A/B | pass real port (mostly zero-diff — already threaded) |
| `QuicSessionTicket.java`, `impl/QuicSessionTicketImpl.java`, `client/CertificateSelector.java` | D | deleted |
| `ConnectionTerminatedEvent.java`, `QuicClientConnection.java`, `crypto/ConnectionSecrets.java` (`computeEarlySecrets`), `cli/*` | D | trims per §3.1 |

Explicitly untouched: the nine kept transport packages (`ack`,`cc`,`cid`,`frame`,`recovery`,
`receive`,`stream` wholly; `packet`/`send` beyond the pass-through lines); `QuicTlsPort(-Impl)`
(one possible addition: `levelOf`); everything the crypto seam already settled.

---

## 9. Open questions

### Peter must decide

- **OQ-P1 (API surface).** Public builder API: replace agent15-typed knobs
  (`cipherSuite(TlsConstants.CipherSuite)`, `sessionTicket(...)`, cert/key-manager trio) with (i)
  a first-class `sslContext(SSLContext)` + optional `SSLParameters`, keeping thin convenience
  wrappers (recommended — matches JGDMS use and the fork's DirtyChai-only posture), or (ii)
  parallel kwik-local enums preserving source shape for upstream-tracking? Note §3.6 is hostage
  to this (§3.2).
- **OQ-P2 (resumption).** Drop kwik's `QuicSessionTicket` machinery entirely and rely on JSSE's
  internal session cache for (non-0-RTT) resumption — accepting that RFC 9369 ticket-version
  binding (`setSessionData`, `ServerConnectionImpl:403-404`) is lost with it — or disable
  resumption outright for the first cut (SOW §3.5 already leans "leave out")? Recommend: delete
  API, leave JSSE cache at defaults, revisit if JGDMS wants resumption.
- **OQ-P3 (per-ALPN transport params).** Accept §2.3 option (a)'s capability regression
  (advertised params per-server, enforced limits still per-protocol)? Recommended yes; option
  (b)'s CH pre-scan is the fallback if not.
- **OQ-P4 (compatible version negotiation).** Accept removal of RFC 9369 compatible-VN
  (mid-handshake V1↔V2 switch, `VersionChangeUnconfirmed` machinery) — server serves the version
  of the client's Initial, client's `preferredVersion` knob dies; full VN via `restartHandshake`
  stays Inc 4? (Engine one-shot `versionNegotiated` + EE-fixed-at-consume make the current
  mechanism unimplementable without engine changes, which are advise-only DirtyChai territory.)
- **OQ-P5 (client-auth default).** New server `needClientAuth` knob: default true (fork's
  raison d'être, fails closed for JGDMS) or false (upstream-compatible, JGDMS sets it)? Recommend
  true-by-default with an explicit opt-out, documented as a deliberate divergence.
- **OQ-P6 (deadline default).** Handshake-completion deadline default value (suggest 30 s,
  mirroring JGDMS P1/F2's posture) and whether it should also bound the candidate stage's 30 s
  cleanup constant (`ServerConnectionCandidate:137`) under one config item.

### Board should verify

- **OQ-B1.** The §6 mapping table against `RecoveryManager`'s four predicates — especially that
  reviving `Completed` for the client's `NEED_RECV_HANDSHAKE_DONE` window doesn't change PTO
  behavior mid-migration, and that no listener assumes `HasAppKeys` implies peer-1-RTT-receive
  readiness.
- **OQ-B2.** The right server-side peer-identity exposure for JGDMS (`SSLSession` handle vs
  cert-chain accessor on `ServerConnection`/`ApplicationProtocolConnection`) — needs a look at
  what STD-010's `ServerEndpoint` layer will consume, before Stage C fixes the shape.
- **OQ-B3.** Spike generalization: the ordering results (§2.3) were produced on one engine build
  at one TP encoding; board should confirm `QuicTLSEngineImpl.consumeHandshakeBytes`'s EE
  production is unconditionally eager (source suggests yes — EE is emitted into the output
  record during CH handling) rather than dependent on some configuration this spike didn't hit.
- **OQ-B4.** Retry sign/verify: agree to defer the port re-point to Inc 4 (§2.5) despite the
  SOW's §3.3 placement — the current `javax.crypto` implementation is agent15-free, static-key,
  and tested; two implementations won't coexist as authorities (sign and verify never both run
  on one end for the same packet).
- **OQ-B5.** Candidate CH-completeness via framing-only ("first complete message has type 0x01")
  — confirm this is not a meaningful weakening vs today's full agent15 CH parse as an
  accept-path gate (the full parse happens later, in-engine, on the connection's own thread; the
  candidate check exists only to avoid creating connections for garbage). Interaction with
  §7.3a's fuzz targets should be recorded there.
- **OQ-B6.** Whether the drive loop must bound bytes pulled per step (the JGDMS pump uses an
  8-iteration cap per transfer; an unbounded `while` against a misbehaving engine would spin —
  trust boundary here is the engine, but a belt-and-braces cap costs nothing).

---

## 10. Spike record

`/tmp/.../scratchpad/hsdriver-spike/DriverSeamOrderingSpike.java` (scratch only, not committed
anywhere): two real `QuicTLSEngine` instances over a throwaway EC keystore, TLSv1.3, ALPN
`[proto-b, proto-a]` vs `[proto-a, proto-b]`, value-only 3-byte transport params both sides,
`versionNegotiated(QUIC_V1)` both, no `deriveInitialKeys`. Run 1 (server local params set after
CH consume, before first pull): client fatal
`QuicTransportException: missing_extension` (0x016d) on consuming EE — EE fixed at consume time.
Run 2 (params set before consume): `HANDSHAKE_CONFIRMED` both ends via
`tryMarkHandshakeDone`/`tryReceiveHandshakeDone`; both consumers fired synchronously inside their
respective `consumeHandshakeBytes` calls (`insideConsume=true` both); server
`getApplicationProtocol()` = `proto-a` immediately after CH consume;
`getCurrentSendKeySpace()` = `INITIAL` at that point (SH rides INITIAL space); 3-byte params
delivered verbatim both directions.
