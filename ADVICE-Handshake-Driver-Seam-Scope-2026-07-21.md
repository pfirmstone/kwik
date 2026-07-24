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

**Board review outcome (2026-07-21, three seats: fact-check/security-RFC/architecture):**
unanimous **APPROVE WITH CHANGES**. Nine blocking (MUST-FIX) corrections, all board-verified,
folded into the sections below; OQ-B1–OQ-B6 (board-level questions) are now ANSWERED; OQ-P1–OQ-P6
(Peter-level questions) carried board recommendations, all **ACCEPTED by Peter in full (2026-07-21)** —
see §9. Full numbered correction log: §11.

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
`b8a7715f` (board nit, §11 item 22: one of the 15 is `module-info.java`'s `requires
tech.kwik.agent15;`, not an `import` — the count is otherwise accurate and unchanged); **2 files**
outside core (`cli/KwikCli.java`, `cli/InteractiveShell.java`); **11 test
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
| Version negotiation (compatible) | `:683-700` | `process(InitialPacket)` → `handleVersionNegotiation` → `quicVersion.setVersion(...)` + `connectionSecrets.recomputeInitialKeys()` mid-handshake; `verifyVersionNegotiation` (`:1017-1032`) checks the `version_information` transport param after the fact. |
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

**Board addition (§11 item 4): non-agent15-importing consumers of deleted API.** These files do
not import `tech.kwik.agent15` themselves — they call kwik's *public* 0-RTT/ticket API surface,
which dies with §3.1's ticket/0-RTT deletions — so they sit outside the 15-file agent15-import
count above but are real blast radius, found independently missing from the original inventory:

| File | Public surface consumed | Disposition |
|---|---|---|
| `interop/src/main/java/tech/kwik/interop/InteropClient.java:191-206,253-275` | `getNewSessionTickets`/`sessionTicket`/`connect(earlyDataRequests)` | Breaks when ticket/0-RTT API dies; Stage D delta accounting names the interop-runner capability losses (resumption, zerortt test cases — joining keyupdate) |
| `samples/src/main/java/tech/kwik/sample/echo/EchoClientUsing0RTT.java:86-126` | same 0-RTT connect surface | Sample dies/needs rewrite with 0-RTT |
| `h09/src/main/java/tech/kwik/h09/client/Http09Client.java:192-193` | `connect(List.of(StreamEarlyData))` | Same |
| `QuicClientConnection.java:41-65` | public `connect(List<StreamEarlyData>)` + `StreamEarlyData` | The API surface itself; dies with tickets/0-RTT (§3.1) |

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
- `isTLSHandshakeComplete()` never becomes true from CRYPTO alone **on the server** — server-side
  it returns true only at `HANDSHAKE_CONFIRMED` (`QuicTLSEngineImpl.java:866-883`), and the sole
  transition into that state is `tryMarkHandshakeDone()` itself (`:829-844`); the transport must
  drive `tryMarkHandshakeDone()` (server, after sending the HANDSHAKE_DONE frame it decides to
  send). **On the client it does become true from CRYPTO alone** — `NEED_RECV_HANDSHAKE_DONE` is
  entered inside the pull that drains the client's Finished (`:457-465`) — and the transport then
  drives `tryReceiveHandshakeDone()` (client, on receiving the frame). (Board correction 1, §11
  item 1 — the original text conflated the two roles, which is a deadlock on the server side: see
  the §6 mapping table fix.) crypto-seam §11 item 22, re-confirmed by the spike (the pump stalls at
  `NEED_SEND_HANDSHAKE_DONE`/`NEED_RECV_HANDSHAKE_DONE` without them). Wrong-role calls throw
  `IllegalStateException` (`QuicTLSEngine.java:449-483`).
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
CRYPTO frames, retransmission, and flushing. **Loop bound (board correction, OQ-B6 answered, §11
item 15): cap the pull loop at ~64 iterations per drive step** (generous vs. the JGDMS pump's
8-iteration cap); treat an empty-but-non-null buffer as terminal (not distinct from null); on cap
breach, close the connection with `INTERNAL_ERROR` (fail-closed) — never silently `break`. Then
evaluate state transitions (§6 mapping table): `keysAvailable(HANDSHAKE)` → client/server
`HasHandshakeKeys` actions; `keysAvailable(ONE_RTT)` → `setOneRttContext` + `HasAppKeys` actions
(server `sender.enableAppLevel()` does **not** fire here — board correction 2, §11 item 2 — it
moves to the completion step below); completion — client: `isTLSHandshakeComplete()` first true;
server: `getHandshakeState() == NEED_SEND_HANDSHAKE_DONE` observed post-pull, then attempt
`tryMarkHandshakeDone()` (board correction 1, §11 item 1; the original text used
`isTLSHandshakeComplete()` for both roles, which is circular on the server) — → the residual
transport orchestration currently in `handshakeFinished()` (§1.1/§1.2), including server
`sender.enableAppLevel()` immediately before the HANDSHAKE_DONE send, and the client's
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
| `extensionsReceived` params push `:653-659` | `port.setRemoteQuicTransportParametersConsumer(cache-then-apply)` registered at construction (GAP-1); the callback fires inside the consume of the EE bytes **[SPIKE]**, i.e. on the receiver thread, before any 1-RTT application frame of that or any later datagram can be processed — the GAP-1 "ordered barrier" is satisfied by same-thread ordering provided the cached bytes are applied at callback time or immediately after the consume returns, never deferred cross-thread (§2.4). **Board preference (§11 item 18): run `setPeerTransportParameters`/`validateAndProcess` directly INSIDE the params-consumer callback**, not just "apply the cache" afterward — invalid peer params then abort at the exact protocol point via `processRemoteQuicTransportParameters:823-826`, resolving the doc's earlier two-phrasings ambiguity between "cache-then-apply" and "process at consume." |
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
  before consume. **Nit (§11 item 23): "static" is not quite literal** — the server TPs also
  include per-connection connection IDs (`ServerConnectionImpl:395-399`), which are knowable at
  construction time (before consume) but are not connection-independent bytes; "static" means
  "independent of ALPN/per-protocol config," not "identical across connections." Keep the
  per-protocol merge for **local runtime enforcement**
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

**OQ-B5 ANSWERED (§11 item 14):** framing-only CH check is adequate — the full parse still runs
once, in the engine, on the connection thread; net effect is a *reduction* of attacker-reachable
parse surface on the shared pool, not a weakening. Conditions: keep
`InitialPacketMinimumSizeFilter`/anti-dribble/3000-byte caps as-is; record **both** parse surfaces
(this framing-only candidate reader, and the engine's `consumeHandshakeBytes` CH parse) as §7.3a
fuzz targets.

### 2.4 §3.3 ↔ §3.4 / §3.5 boundary, defined precisely

- **§3.3 owns** (because the handshake cannot complete without them — engine hard-fails
  otherwise): registering the remote-params consumer (both roles), calling
  `setLocalQuicTransportParameters` at the right time (client: before kickstart; server: before
  first consume), and invoking kwik's existing parameter *processing*
  (`setPeerTransportParameters` client `:913-967` / `validateAndProcess` server `:630-656`)
  **directly inside the consumer callback itself** (board preference, §11 item 18 — not a
  separate "cache, then apply later" step; invalid peer params then abort at the exact protocol
  point via `processRemoteQuicTransportParameters:823-826`, resolving the two-phrasings ambiguity
  between §2.2's "cache-then-apply" framing and this one).
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
  independent diff. **OQ-B4 ANSWERED (§11 item 13):** the deferral is coherent, no dual-authority
  hazard — both implementations are stateless fixed-key per RFC 9001 §5.8; `QuicTlsPort.java:244-255`
  sits unwired today, and its javadoc (`:277-279`) already documents the local implementation.
  **Condition:** Inc 4's re-point must delete kwik's local fixed-key implementation in the same
  diff (no two authorities coexisting even briefly).
- **Client CH-retransmit after Retry** (`:759-760` writes the cached agent15 `ClientHello`
  object): the driver caches the **raw CH bytes** it pulled at kickstart and rewrites those after
  `getCryptoStream(Initial).reset()`. RFC 9002 §6.3 requires the same CH; the engine has no
  "re-emit CH" API short of `restartHandshake()` (which resets TLS state — wrong tool; it exists
  for Version Negotiation, `QuicTLSEngine.java:210-218`). Byte-caching is the correct mechanism;
  note it also removes the `originalClientHello` field (`:159`).
- **Version Negotiation packets / `restartHandshake()`**: unchanged scope — Inc 4, not §3.3's
  first landing. **Compatible VN**: removal (OQ-P4, §0 item 3; ACCEPTED by Peter 2026-07-21 — board
  recommendation detailed in §9's OQ-P4 entry and §11 item 6, including disposal of the
  `version_information` transport parameter, which the SOW-derived scope above did not address).

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
  `quicError(TlsProtocolException)`.
  **Board correction (§11 item 3): `getTlsEngine()` and the `TlsProtocolException`
  catch/error-mapping narrowing cannot delete in Stage A** — both are still reached through the
  still-live server engine until Stage B replaces server construction
  (`QuicConnectionImpl.java:565,995`; `ServerConnectionImpl.java:221-224,159,518-524`;
  `CryptoStream.java:190,337-349` dispatch; `QuicConnectionImpl.java:430-444,858-871`). These move
  wholesale into Stage B (§8), alongside the `CryptoStream` parser/dispatch/stub deletion (also
  still needed by `ServerConnectionCandidate.java:265-269`'s buffered-CH typed parse until Stage B
  rebuilds it agent15-free, §2.3);
- `NewSessionTicket` + `QuicSessionTicket`/`QuicSessionTicketImpl` + builder `sessionTicket(...)`
  + `earlySecretsKnown`/`isEarlyDataAccepted`/`EarlyDataExtension`/`computeEarlySecrets`/
  `TrafficSecrets` (doc-§2.4 and doc-§3.3 note);
- `CertificateWithPrivateKey` + `CertificateSelector` + `setClientCertificateCallback`;
- `TlsConstants` uses in: cipher-suite lists (`:529`, `ServerConnectionImpl:143-149`), signature
  schemes (`:82, :555-558`), `ConnectionTerminatedEvent.alertFromValue` (local table replaces),
  `QuicClientConnection.Builder.cipherSuite` (per OQ-P1);
- `TlsProtocolException` throughout (`QuicConnectionImpl.process(CryptoFrame)` catch `:436-439`
  → catches `QuicTransportException`; candidate's `checkClientHelloComplete` signature; per the
  Stage-B-move note above, this narrowing lands in Stage B, not Stage A);
- **Board addition (§11 item 4):** the non-agent15-importing consumers of the ticket/0-RTT API
  listed in §1.7's second table (`interop/InteropClient.java`, `samples/EchoClientUsing0RTT.java`,
  `h09/Http09Client.java`, `QuicClientConnection.connect(List<StreamEarlyData>)`/`StreamEarlyData`)
  — these break when the above dies even though they carry no `agent15` import themselves, and
  were not in the original §3.1 accounting;
- **Board addition, compatible-VN (§11 item 6, OQ-P4 board recommendation, ACCEPTED by Peter 2026-07-21):** if
  OQ-P4 resolves as recommended, the `version_information` transport parameter dies both
  directions (server send `ServerConnectionImpl.java:393`; validation
  `ServerConnectionImpl.java:630-643` and `QuicClientConnectionImpl.java:1017-1032`), and so does
  the `VersionChangeUnconfirmed` machinery in `packet/ServerRolePacketParser.java` — the latter
  was previously absent from this document's blast radius entirely. See §9 OQ-P4 and §11 item 6.

### 3.2 Waits for §3.6

**Target: zero agent15 types referenced after §3.3 Stage D** in `core/src/main` — §3.6 then only
deletes `requires tech.kwik.agent15;` (`module-info.java:2`), the Gradle dependency, and adds the
`canRead` probe. The Stage D gate is the grep proving that zero (excluding comments), enumerated
exactly per §11 item 5 (the original "residue" claim in §3.6/§8 undercounted the removal set —
see §8 Stage D and §11 item 5 for the corrected list, which is more than just the `module-info`
line). Outside `core`: `cli`'s two files follow OQ-P1's API decision in the same stage; test
sources (11 files, §1 header) are migrated **per-stage** as their production counterparts change
— this is the reading that governs; §8's old Stage D text claimed the 11-file migration as a
Stage D bulk job, which contradicted this sentence and is corrected in §8 (board correction 3,
§11 item 3).

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
  **Nit: the pool is effectively 1-thread, not 10.** `ServerConnectorImpl.java:149-151`
  constructs it `new ThreadPoolExecutor(1, maxSharedExecutorThreads, ..., new
  LinkedBlockingQueue<Runnable>(), ..., new ThreadPoolExecutor.DiscardPolicy())` — an unbounded
  `LinkedBlockingQueue` means `ThreadPoolExecutor` only grows past `corePoolSize=1` when the
  queue *rejects* a task, which an unbounded queue never does, so `maximumPoolSize` is
  unreachable and `DiscardPolicy` is dead code. Reframe the DoS exposure here as **queue-growth
  and latency under load** (candidates pile up behind the single worker), not thread-pinning.
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
  socket timeouts on the fetcher), and the deadline bounds (i)+(ii) fully. **OQ-P6 addition
  (accepted 2026-07-21, §9): the deadline bounds half-open *lifetime*, not *concurrency* — kwik
  has no connection cap today.** A companion config item, `ServerConnectionConfig
  .maxConcurrentHandshakes()` (or equivalent), enforced at the point a candidate is accepted into
  a full connection (`ServerConnectionCandidate`/`ServerConnectorImpl`, §1.6), rejects or defers
  acceptance once the in-flight (not-yet-`Confirmed`) connection count is at cap — a second,
  independent bound alongside the per-connection timer, not a substitute for it. Timer ownership,
  the cap's enforcement point, abort path, and test (a client that completes CH then stalls,
  sending periodic PINGs — assert close at deadline despite idle-timer resets; a concurrency test
  asserting the cap is enforced) = Stage C gate items.

**Board addition (§11 item 17, advisory):** the deadline is part of the **AUTH story**, not
merely an availability control — it bounds a stalling cert-less/untrusted client, not just a
slow-but-honest one. The security seat separately verified the mTLS failure chain end-to-end and
found it **fail-closed with no swallow point**, and that the engine's pre-`HANDSHAKE_CONFIRMED`
1-RTT decrypt refusal (`QuicTLSEngineImpl.decryptPacket:348-353`) makes pre-auth app-data ingress
**impossible by construction** — no redundant kwik-side defense is needed on top of it.

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
| `keysAvailable(ONE_RTT)` first true | `port.setOneRttContext(...)` (mandatory, §2.1) then → `HasAppKeys`. **`sender.enableAppLevel()` does NOT fire here** (board correction 2, §11 item 2 — see the completion row below) |
| `isTLSHandshakeComplete()` first true (**client only** — board correction 1, §11 item 1) | client: `connectionState = Connected`, **→ `HandshakeState.Completed`** (note 1's OQ-B1-endorsed revival — the window is exactly `NEED_RECV_HANDSHAKE_DONE`), countdown latch (`:623-639` residue) |
| `getHandshakeState() == NEED_SEND_HANDSHAKE_DONE` observed after a consume/pull (**server** trigger; board correction 1, §11 item 1 — replaces the original "`isTLSHandshakeComplete()` first true" for the server half, which was circular: see Note (4) below) | server: `sender.enableAppLevel()` (board correction 2, §11 item 2 — moved here from the `keysAvailable(ONE_RTT)` row) → attempt `tryMarkHandshakeDone()`, and iff it returns true, run the completion residue → send HANDSHAKE_DONE → discard Handshake keys/PnSpace → `Connected` → **`Confirmed`** → events + app-protocol start (`:297-333` residue, order preserved) |
| (client) HANDSHAKE_DONE frame received | `tryReceiveHandshakeDone()` + → `Confirmed` + discard Handshake keys/PnSpace (`:779-794`, kept) |

Notes: (1) `HandshakeState.Completed` is dead today (no writer, §1.4) — either start using it
for the client's `isTLSHandshakeComplete`-but-not-yet-DONE window (it models exactly
`NEED_RECV_HANDSHAKE_DONE`, during which RFC 9001 permits 1-RTT sends) or delete it; recommend
**use it**, since `RecoveryManager:227`'s `isNotConfirmed` PTO logic already distinguishes that
window. **OQ-B1 ANSWERED (§11 item 10):** the ordinal lattice still holds (`Completed` <
`Confirmed`) and reviving `Completed` is confirmed predicate-neutral — every `RecoveryManager`
read was traced (`RecoveryManager.java:213,227,255,334,570-576`); all four predicates
(`hasNoHandshakeKeys`/`hasOnlyHandshakeKeys`/`isNotConfirmed`/`isConfirmed`) are identical at
`Completed` vs `HasAppKeys`, and `RecoveryManager` is the sole listener registrant
(`SenderImpl.java:152`). Endorsed.
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
(4) **Board correction 1 (§11 item 1), found independently by two seats:** the original table's
server trigger — "`isTLSHandshakeComplete()` first true" — was circular. Server-side
`isTLSHandshakeComplete()` returns true **only** at `HANDSHAKE_CONFIRMED`
(`QuicTLSEngineImpl.java:866-883`), and the only transition into `HANDSHAKE_CONFIRMED` is
`tryMarkHandshakeDone()` itself (`:829-844`) — a driver waiting on the flag before calling the
function that sets it deadlocks. The corrected server trigger (table row above) observes
`getHandshakeState() == NEED_SEND_HANDSHAKE_DONE` and then attempts `tryMarkHandshakeDone()`,
equivalently: just attempt it after every consume/pull and run the completion residue iff it
returns true — the JGDMS `QuicEngineMtlsTest` drive-loop pattern. The client half of the row (and
of the §2.1 bullet) was correct as originally written and is unchanged.
(5) **Board correction 2 (§11 item 2), security seat:** the original table fired
`sender.enableAppLevel()` at `keysAvailable(ONE_RTT)` first-true. The server derives its 1-RTT
keys while producing its own Finished (`Finished.java:849-857`) — **before** the client's
Certificate/CertificateVerify/Finished are consumed, i.e. before the SPIFFE trust manager runs —
so firing `enableAppLevel()` there opens a 0.5-RTT send window to an unauthenticated peer that
current kwik does not have and does not want. Fix: `setOneRttContext(...)` stays at
`keysAvailable(ONE_RTT)`; `enableAppLevel()` moves to the server **completion** step, immediately
before `sendHandshakeDone` — which is where `ServerConnectionImpl.java:302` already puts it
today, so the corrected table now matches current kwik ordering rather than regressing it.

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

**Stage A — HandshakeDriver core + port-driven client path, added ALONGSIDE the legacy
machinery (5–7 d, of which the raw-engine UDP loopback harness — effectively a mini QUIC
server, the fattest single Stage A item — is its own estimate line, ≈2–3 d; board item §11-19).**
New `HandshakeDriver` (§2.1); `CryptoStream` receive half gains the `consumeHandshakeBytes`
byte-pipe path for port-driven connections **while the legacy parser/dispatch/stub path
remains** — board correction 3 (§11 item 3): Stage A as originally scoped deleted three things
Stage B still references — (a) the buffered-CH typed parse used by
`ServerConnectionCandidate.java:265-269`, (b) `getTlsEngine()`
(`QuicConnectionImpl.java:565,995`; `ServerConnectionImpl.java:221-224,159,518-524` +
`CryptoStream.java:190,337-349` dispatch), (c) the `TlsProtocolException` catch/mapping
(`QuicConnectionImpl.java:430-444,858-871`) that the still-live server engine throws through
until B — a Step-C/D-class build break at the A/B boundary, three times over. All three
deletions move wholesale into Stage B. Client construction → `forClient` + config mapping
(§2.2 table); client callbacks deleted, orchestration residues re-fired per §6 table; Retry
CH-byte caching; client-side error handling consumes `QuicTransportException.getErrorCode()`
(the error-path *narrowing* — dropping the `TlsProtocolException` arm — waits for B). If
OQ-P4 resolves as recommended, the **client half** of the `version_information` TP removal
(validation at `QuicClientConnectionImpl.java:1017-1032`) lands here (§11 item 6). Client-side
tests migrate with their production counterparts (per-stage policy, §3.2).
*Gate (independently verifiable):* client `connect()` completes to `Confirmed` against a
test-harness peer built from a raw second engine over real UDP loopback packets (fixture
precedent: `HandshakeShortHeaderPacketRealEngineRoundTripTest`'s pump + `FakeQuicTlsPort` for
unit level), plus unit tests for the drive-step state table; **CH-byte-identity assertion on
the Retry re-send (RFC 9002 §6.3) as a named gate item (§11 item 19)**; full suite green with
server-side tests running on the still-present legacy paths.

**Stage B — server path + the deletions moved out of Stage A (7–10 d; the moved deletions and
the params-before-consume novelty are what put this stage at the range's high end, §11 item 9).**
`ServerConnectionFactory`/`ServerConnectorImpl`/Builder → `SSLContext` carrier;
`ServerConnectionImpl` port construction with **params-before-consume** ordering (§2.3 option a);
candidate CH-completeness rebuilt agent15-free; `extensionsReceived` decomposed (ALPN → JSSE,
params → consumer path, per-protocol merge → post-consume runtime-only); server completion step
per the corrected §6 table (`NEED_SEND_HANDSHAKE_DONE` → `enableAppLevel()` →
`tryMarkHandshakeDone`, §11 items 1–2); **the three deletions deferred from Stage A** (legacy
`CryptoStream` parser/dispatch/stub + buffered-CH typed parse, `getTlsEngine()` removal,
`TlsProtocolException` catch/mapping narrowing — §11 item 3); if OQ-P3 resolves as recommended,
the enforced-vs-advertised clamp is a named Stage B work item (post-consume merge may never
lower an enforced limit below its EE-advertised value, §11 item 16/OQ-P3); if OQ-P4 resolves as
recommended, the **server half** of the `version_information` TP removal (send
`ServerConnectionImpl.java:393`, validation `ServerConnectionImpl.java:630-643`) **plus the
`VersionChangeUnconfirmed` machinery in `packet/ServerRolePacketParser.java`** — previously
absent from this document's blast radius entirely — lands here (§11 item 6). Server-side tests
migrate with their production counterparts (per-stage policy, §3.2).
*Gate:* loopback kwik-client ↔ kwik-server handshake green (SOW Inc 1 milestone);
`getSession().getPeerCertificates()` populated both ends (server-auth-only);
no-ALPN-overlap and missing-params negative cases produce the engine's own fatal codes; **an
HRR (HelloRetryRequest) case in the gate's negative tests** (OQ-B3's closure condition, §11
item 12); **the client-rejects-untrusted-server negative test** (post-migration this is only
observable over transport — silent coverage loss otherwise; §11 item 20, held through Stage C);
**egress ordering negative test (correction 2, §6 note 5/§11 item 2): "server emits no 1-RTT
bytes before the client's Finished is consumed"** — assert no datagram carrying ONE_RTT-space
bytes leaves the server before `enableAppLevel()` fires in the completion step. This is the
**sole** egress defense for that ordering: unlike ingress, the engine backstops nothing here
(`encryptPacket` has no pre-auth gate — only `decryptPacket` refuses ONE_RTT decrypt
pre-`HANDSHAKE_CONFIRMED`, `QuicTLSEngineImpl.java:348-353`), so a regression in the completion
step's call order would not be caught by the engine and must be caught by this test;
anti-amplification/Retry paths still pass existing tests (SOW §7.3b checkpoint opens here, closes
Inc 4).

**Inc H — adversarial hardening (1–2 weeks, SOW §7.3a-mandated) sequences HERE, between Stage B
and Stage C, unless Peter explicitly waives the SOW's ordering** (§11 item 8). It is *excluded*
from the A–D estimate below. Both CH parse surfaces — the candidate's framing-only reader and
the engine's `consumeHandshakeBytes` — are recorded as its fuzz targets (OQ-B5, §11 item 14).

**Stage C — mTLS + deadline (3–5 d).**
`needClientAuth` config + `SSLParameters` pass-through, **including the OQ-P5 rider (§9): a
caller-supplied `SSLParameters` carrying an explicit `setNeedClientAuth(false)` must be a
deliberate, documented opt-out — never a silent result of merging caller-supplied params with
the fork's true-by-default**; server peer-identity exposure (OQ-B2);
handshake-completion deadline per §5, **including the OQ-P6 concurrent-handshaking-connections
cap** (a companion bound on in-flight-handshake count, distinct from the deadline's per-connection
*lifetime* bound — §5, §9 OQ-P6); **positively disabling TLS resumption per OQ-P2 (§9)** — the
driver declines to act on NST bytes and explicitly invalidates any session before reuse, verified
by a STD-010-style positive-assertion test, alongside the STD-010 0-RTT guards below; positive +
negative mTLS tests mirroring
`QuicEngineMtlsTest` over real transport (SPIFFE-shaped SVIDs if cheap, else plain X.509 pos/neg
with the SPIFFE run deferred to JGDMS integration); slowloris test (stalling PINGing client
closed at deadline).
*Gate:* SOW Inc 3's acceptance criteria minus interop: client-auth required and enforced
(wrong/absent cert → rejected, and the OQ-P5 explicit-opt-out rider observably documented rather
than silently mergeable), deadline in force, **concurrent-handshake cap enforced (OQ-P6)**,
candidate stage demonstrably engine-free
(code inspection + no engine construction before `createNewConnection`), **and a
STD-010-style positive-assertion test proving resumption does not occur (OQ-P2)**.
**Co-requisite (board
correction 7, §11 item 7): STD-010 §6.2's positive 0-RTT guards — the `max_early_data_size=0`
assertion and the ZERO_RTT send-path assertion (§3.5's work items) — gate the Inc 3 acceptance
milestone alongside this stage's own items; engine-absence is explicitly insufficient per
STD-010.** The Inc 3 milestone is not met until those guards exist, even though building them
stays §3.5's scope.

**Stage D — agent15 decommission + API surface (3–6 d; the original 3–5 d was honest only by
under-counting — under the old bulk-migration reading the honest figure was 5–8 d; with the
per-stage test-migration policy now adopted (§11 item 3) the stage shrinks back to a residue
carrier).**
Delete §3.1's list: tickets/0-RTT wiring (**explicitly excluding `ZeroRttPacket`, which
survives — it is §3.5's, §11 item 24**), `CertificateSelector`, `ConnectionTerminatedEvent`
alert table, builder/API changes per OQ-P1, `cli` follow-through; **the non-agent15-importing
consumers of the dying public API (§1.7 second table, §11 item 4): `interop/InteropClient.java`'s
resumption/0-RTT drivers, `samples/EchoClientUsing0RTT.java`, `h09/Http09Client.java`, and the
public `QuicClientConnection.connect(List<StreamEarlyData>)` + `StreamEarlyData` surface**; if
OQ-P4 resolves as recommended, the API knob `Builder.preferredVersion`
(`QuicClientConnection.java:111`) dies here (§11 item 6). Test migration in this stage is only
the residue not claimed by A–C under the per-stage policy (§3.2) — the heavyweight
`QuicClientConnectionImplTest`/`ServerConnectionImplTest` `TlsStatusEventHandler`-mock rework
belongs to Stages A/B with their production counterparts (port-mock or real-engine fixtures per
crypto-seam OQ-6's per-file policy).
*Gate:* repo-wide grep proving zero agent15 references in sources, with the §3.6 residue
enumerated **exactly** (board correction 5, §11 item 5 — the original "{`module-info.java:2`,
Gradle dependency}" claim was wrong by count): `core/module-info.java`'s two `requires` lines;
**four** build.gradle deps (`core/build.gradle:75`, `cli/build.gradle:9`,
`interop/build.gradle:10`, `qlog/build.gradle:6` — qlog's is declared-but-unused); and the
`ext.agent15_version = '3.3'` pin in
`buildSrc/src/main/groovy/buildlogic.java-common-conventions.gradle:52`. Whole-reactor build
green; full suite at (new) baseline with a written delta accounting (expected losses: ticket/
0-RTT tests, agent15-mock tests, the compatible-VN tests if OQ-P4 resolves as recommended —
`ServerConnectionImplTest.java:271-289`, `QuicClientConnectionImplTest.java:616-630`, replaced
by a server-serves-offered-version assertion (§11 item 6) — and the interop-runner capability
losses: **resumption and zerortt test cases, joining keyupdate** (§11 item 4) — each named,
none silent).

**Estimate: 18–28 engineering-days** (A 5–7 + B 7–10 + C 3–5 + D 3–6) for Stages A–D — board
correction 9 (§11 item 9), replacing this document's original 15–23 d, which understated Stage A
(the raw-engine UDP harness now carries its own line) and Stage B (which inherits the moved
deletions and the params-before-consume novelty), and mis-stated Stage D (see its header).
**Inc H (1–2 weeks) is separate and additional** — sequenced between Stages B and C unless
Peter waives the SOW ordering (§11 item 8). Consistent with the SOW §7.2 lines the stages
replace (pull loop 5–8 d + setter mapping inside 3–5 d + `CryptoStream` byte pipe 3–5 d +
Inc-1 bring-up 3–5 d + part of the mTLS 5–8 d); note also SOW §7.2's separate "TP re-home +
strip 0-RTT/tickets 2–4 d" line is **absorbed** by Stages A/B (TP re-home) and D (ticket/0-RTT
strip) — it must not be counted again on top of this estimate (double-count guard, §11 item
21). All of this holds *provided* OQ-P1/P3/P4 resolve to the recommended (capability-trimming)
options; each "keep the capability" answer adds real work (per-ALPN pre-scan ≈ +3–4 d incl.
hardening; compatible-VN preservation ≈ unbounded until a design exists — it may not have one).
Risks that push high: the test-migration load in Stages A/B ballooning (mitigant: Step B/C/D of
the crypto seam already built the real-engine fixtures), and live-loopback flakiness during
Stage B bring-up (mitigant: the JGDMS pump loop as an oracle for "engines fine, transport at
fault").

**Decision-gate sequencing (board correction 8, §11 item 8):** OQ-P1 must be pinned **before
Stage A starts**; OQ-P3 and OQ-P4 **before Stage B**; OQ-P5 and OQ-P6 **before Stage C**. All
six ACCEPTED by Peter 2026-07-21 (§9).

### Blast radius (production)

| File | Stage | Nature |
|---|---|---|
| `crypto/CryptoStream.java` | A (byte-pipe added) / B (legacy parser/dispatch/stub deleted, ~200 of 419 lines — §11 item 3) | receive-half rewrite split across the A/B boundary |
| new `HandshakeDriver` (+ `levelOf`) | A | new, ~150-250 lines |
| `impl/QuicClientConnectionImpl.java` | A (+D api) | ctor, startHandshake, 7 callbacks, Retry, HandshakeDone, builder |
| `impl/QuicConnectionImpl.java` | A (`tlsPort` populate, `getCryptoStream` signature) / B (`getTlsEngine` removal, error-mapping narrowing, CryptoFrame catch — §11 item 3) | split across the A/B boundary |
| `impl/HandshakeState.java` | A | `Completed` decision only (§6 note 1) |
| `server/impl/ServerConnectionImpl.java` | B | ctor, callbacks, `extensionsReceived` decomposition, completion step |
| `server/ServerConnectionFactory.java`, `server/impl/ServerConnectorImpl.java` | B | SSLContext carrier + Builder API |
| `server/impl/ServerConnectionCandidate.java` | B | agent15-free CH check |
| `server/impl/ServerConnectionThread.java` | B | drive-step hookup only (likely zero-diff if driver is invoked from CryptoStream path) |
| `tls/QuicTransportParametersExtension.java` | A/B interim slice-adapter; real codec §3.4 | |
| `send/SenderImpl.java`, `packet/PacketParser.java` | A/B | pass real port (mostly zero-diff — already threaded) |
| `QuicSessionTicket.java`, `impl/QuicSessionTicketImpl.java`, `client/CertificateSelector.java` | D | deleted |
| `ConnectionTerminatedEvent.java`, `QuicClientConnection.java`, `crypto/ConnectionSecrets.java` (`computeEarlySecrets`), `cli/*` | D | trims per §3.1 |
| `packet/ServerRolePacketParser.java` (`VersionChangeUnconfirmed` machinery) | B (iff OQ-P4 → drop) | board addition, §11 item 6 — previously absent from this table |
| `interop/InteropClient.java`, `samples/EchoClientUsing0RTT.java`, `h09/Http09Client.java` | D | non-agent15-importing consumers of dying public 0-RTT/ticket API (§1.7 second table, §11 item 4) |

Explicitly untouched: the nine kept transport packages (`ack`,`cc`,`cid`,`frame`,`recovery`,
`receive`,`stream` wholly; `packet`/`send` beyond the pass-through lines); `QuicTlsPort(-Impl)`
(one possible addition: `levelOf`); everything the crypto seam already settled.

---

## 9. Open questions

### Peter must decide

All six are **RESOLVED — Peter accepted every board recommendation in full (2026-07-21).** The
board recommendation attached to each (recorded below, §11 item 16) is now Peter's ruling; the
per-OQ entries below are marked ACCEPTED. Sequencing (§11 item 8): OQ-P1 before Stage A starts;
OQ-P3/OQ-P4 before Stage B; OQ-P5/OQ-P6 before Stage C. (OQ-P2 mechanism — **`SSLSessionContext
.setSessionCacheSize(0)` is struck from consideration**: per the JSSE contract, size `0` means
*unlimited* cache, not disabled, so this "option" would fail open and must not be implemented.
`jdk.tls.server.newSessionTicketCount=0` remains a candidate but is a **JVM-global** system
property — a poor fit for a library that may share a process with other TLS consumers; use only
with that caveat understood. The **preferred mechanism** is the driver declining to act on NST
bytes plus explicit session invalidation before any reuse; the accepted requirement is resumption
"disabled" as a positive assertion, verified by a STD-010-style positive-assertion test — that
test, not the choice of mechanism, is the arbiter of "disabled.")

- **OQ-P1 (API surface).** Public builder API: replace agent15-typed knobs
  (`cipherSuite(TlsConstants.CipherSuite)`, `sessionTicket(...)`, cert/key-manager trio) with (i)
  a first-class `sslContext(SSLContext)` + optional `SSLParameters`, keeping thin convenience
  wrappers (recommended — matches JGDMS use and the fork's DirtyChai-only posture), or (ii)
  parallel kwik-local enums preserving source shape for upstream-tracking? Note §3.6 is hostage
  to this (§3.2).
  **Board rec — ACCEPTED by Peter 2026-07-21 (gates Stage A):** option (i) — `sslContext(SSLContext)` + optional
  `SSLParameters`, keeping `withCertificate`/`withKeyStore`/`noServerCertificateCheck` as thin
  wrappers. The enum option still conflicts on every upstream merge anyway and adds a permanent
  mapping to maintain.
- **OQ-P2 (resumption).** Drop kwik's `QuicSessionTicket` machinery entirely and rely on JSSE's
  internal session cache for (non-0-RTT) resumption — accepting that RFC 9369 ticket-version
  binding (`setSessionData`, `ServerConnectionImpl:403-404`) is lost with it — or disable
  resumption outright for the first cut (SOW §3.5 already leans "leave out")? Recommend: delete
  API, leave JSSE cache at defaults, revisit if JGDMS wants resumption.
  **Board rec — ACCEPTED by Peter 2026-07-21 — STRENGTHENED beyond this document's original recommendation, on
  a real finding:** delete the ticket API **and positively disable TLS resumption** for the
  first cut — do not leave the JSSE cache at defaults. JSSE's TLS 1.3 PSK resumption carries the
  original client identity forward **without re-running the trust manager**
  (`PreSharedKeyExtension.canRejoin:446-459` checks that the principal exists, never
  re-validates), so a resumed session can outlive a short-lived SVID's validity window.
  **Mechanism — `SSLSessionContext.setSessionCacheSize(0)` struck (fail-open hazard): per the
  JSSE contract, `0` means *unlimited* cache size, not "disabled," so this option would silently
  fail open and is removed from consideration entirely.**
  `jdk.tls.server.newSessionTicketCount=0` remains a candidate mechanism but is a **JVM-global**
  system property — a poor fit for a library that may share a process with other TLS consumers;
  document that caveat wherever it's used. **Preferred mechanism:** the driver declines to act on
  NST bytes surfaced via `getHandshakeBytes(ONE_RTT)` (§0 item 9/§7 item 9) and explicitly
  invalidates any session before it could be reused. The requirement is "disabled" as a
  **positive assertion**, STD-010-style, with a positive-assertion test (attempt resumption,
  assert it does not occur) as the arbiter — see the Stage C work item, §8.
- **OQ-P3 (per-ALPN transport params).** Accept §2.3 option (a)'s capability regression
  (advertised params per-server, enforced limits still per-protocol)? Recommended yes; option
  (b)'s CH pre-scan is the fallback if not.
  **Board rec — ACCEPTED by Peter 2026-07-21 (gates Stage B):** accept — the regression is operational only —
  **with** the clamp stated as a named Stage B work item: enforced limits must be ≥ advertised
  (the post-consume merge may never lower a limit below its EncryptedExtensions-advertised
  value).
- **OQ-P4 (compatible version negotiation).** Accept removal of RFC 9369 compatible-VN
  (mid-handshake V1↔V2 switch, `VersionChangeUnconfirmed` machinery) — server serves the version
  of the client's Initial, client's `preferredVersion` knob dies; full VN via `restartHandshake`
  stays Inc 4? (Engine one-shot `versionNegotiated` + EE-fixed-at-consume make the current
  mechanism unimplementable without engine changes, which are advise-only DirtyChai territory.)
  **Board rec — ACCEPTED by Peter 2026-07-21 (gates Stage B):** drop compatible-VN **and drop the
  `version_information` transport parameter in both directions** (board correction 6, §11 item
  6): keeping the TP advertised (`ServerConnectionImpl.java:393` sends [v1,v2]) while deleting
  the validation (`ServerConnectionImpl.java:630-643`,
  `QuicClientConnectionImpl.java:1017-1032`) would violate RFC 9368's MUSTs. Dropping the TP is
  fully spec-legal for an endpoint not implementing RFC 9368, with zero downgrade surface since
  no version-switch mechanism remains. Inc 4's full-VN work brings the TP back. Stage
  assignment of the removal diff: client half → Stage A, server half (incl.
  `VersionChangeUnconfirmed` in `packet/ServerRolePacketParser.java`) → Stage B,
  `Builder.preferredVersion` → Stage D; dying tests named in Stage D's delta accounting (§8).
- **OQ-P5 (client-auth default).** New server `needClientAuth` knob: default true (fork's
  raison d'être, fails closed for JGDMS) or false (upstream-compatible, JGDMS sets it)? Recommend
  true-by-default with an explicit opt-out, documented as a deliberate divergence.
  **Board rec — ACCEPTED by Peter 2026-07-21 (gates Stage C):** default **true**, and it has teeth:
  `CLIENT_AUTH_REQUIRED` is the *only* JSSE setting where a cert-less client fails closed
  (`CertificateMessage.java:1127-1139`); with "want", an empty chain silently continues
  unauthenticated — precisely the mission failure. Riders: a caller-supplied `SSLParameters`
  carrying an explicit `setNeedClientAuth(false)` must be a deliberate, documented opt-out —
  never a silent merge result; and JGDMS's `ServerEndpoint` should treat
  `SSLPeerUnverifiedException` as fatal (defense in depth).
- **OQ-P6 (deadline default).** Handshake-completion deadline default value (suggest 30 s,
  mirroring JGDMS P1/F2's posture) and whether it should also bound the candidate stage's 30 s
  cleanup constant (`ServerConnectionCandidate:137`) under one config item.
  **Board rec — ACCEPTED by Peter 2026-07-21 (gates Stage C):** 30 s default, **plus a
  concurrent-handshaking-connections cap alongside it** — the deadline bounds half-open
  *lifetime*, not *concurrency*, and kwik has no connection cap today.

### Board should verify — all six ANSWERED by the 2026-07-21 review (§11 items 10–15)

- **OQ-B1.** The §6 mapping table against `RecoveryManager`'s four predicates — especially that
  reviving `Completed` for the client's `NEED_RECV_HANDSHAKE_DONE` window doesn't change PTO
  behavior mid-migration, and that no listener assumes `HasAppKeys` implies peer-1-RTT-receive
  readiness.
  **ANSWERED (§11 item 10):** mapped-pair + reviving `Completed` confirmed predicate-neutral —
  every `RecoveryManager` read traced (`RecoveryManager.java:213,227,255,334,570-576`); all four
  predicates identical at `Completed` vs `HasAppKeys`; sole listener registrant is
  `RecoveryManager` (`SenderImpl.java:152`). Endorsed. (Also recorded at §6 note 1.)
- **OQ-B2.** The right server-side peer-identity exposure for JGDMS (`SSLSession` handle vs
  cert-chain accessor on `ServerConnection`/`ApplicationProtocolConnection`) — needs a look at
  what STD-010's `ServerEndpoint` layer will consume, before Stage C fixes the shape.
  **ANSWERED (§11 item 11):** expose a read-only `SSLSession` accessor on the server connection
  (surfaced to the `ApplicationProtocolConnection` context), **hard-gated on
  `HandshakeState.Confirmed`** — throw before; never partial. MUST NOT expose:
  `getHandshakeSession()`, the engine/port, the `SSLContext` or managers, or any setter.
  Identity is documented fixed-at-handshake (STD-010 §6.3 migration invariant). Matches the
  STD-010 draft (`:932-933`).
- **OQ-B3.** Spike generalization: the ordering results (§2.3) were produced on one engine build
  at one TP encoding; board should confirm `QuicTLSEngineImpl.consumeHandshakeBytes`'s EE
  production is unconditionally eager (source suggests yes — EE is emitted into the output
  record during CH handling) rather than dependent on some configuration this spike didn't hit.
  **ANSWERED — CLOSED in engine source (§11 item 12):** EE production at CH-consume is
  unconditional (`ClientHello.java:1226-1249`); the sole branch is HelloRetryRequest, which
  defers EE to the **second** CH consume — still consume-time — so "set local params before the
  FIRST consume" stands. Closure condition: an HRR case in Stage B's gate negative tests (§8).
- **OQ-B4.** Retry sign/verify: agree to defer the port re-point to Inc 4 (§2.5) despite the
  SOW's §3.3 placement — the current `javax.crypto` implementation is agent15-free, static-key,
  and tested; two implementations won't coexist as authorities (sign and verify never both run
  on one end for the same packet).
  **ANSWERED (§11 item 13):** deferral is coherent, no dual-authority hazard — both
  implementations are stateless fixed-key per RFC 9001 §5.8; `QuicTlsPort.java:244-255` sits
  unwired today and its javadoc (`:277-279`) already documents the local implementation.
  **Condition recorded:** Inc 4's re-point must delete kwik's local fixed-key implementation in
  the same diff. (Also recorded at §2.5.)
- **OQ-B5.** Candidate CH-completeness via framing-only ("first complete message has type 0x01")
  — confirm this is not a meaningful weakening vs today's full agent15 CH parse as an
  accept-path gate (the full parse happens later, in-engine, on the connection's own thread; the
  candidate check exists only to avoid creating connections for garbage). Interaction with
  §7.3a's fuzz targets should be recorded there.
  **ANSWERED (§11 item 14):** adequate — full parse still runs once, in the engine, on the
  connection thread; net *reduction* of attacker-reachable parse surface on the shared pool.
  Conditions: keep `InitialPacketMinimumSizeFilter`/anti-dribble/3000-byte caps; record **both**
  parse surfaces (candidate framing reader, engine consume) as §7.3a fuzz targets. (Also
  recorded at §2.3.)
- **OQ-B6.** Whether the drive loop must bound bytes pulled per step (the JGDMS pump uses an
  8-iteration cap per transfer; an unbounded `while` against a misbehaving engine would spin —
  trust boundary here is the engine, but a belt-and-braces cap costs nothing).
  **ANSWERED (§11 item 15):** cap the drive loop (~64 iterations, generous vs the JGDMS pump's
  8); treat empty-but-non-null buffers as terminal; on cap breach close with `INTERNAL_ERROR`
  (fail-closed) — never silently `break`. (Also recorded at §2.2.)

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

---

## 11. Board-review correction log (2026-07-21, three seats: fact-check / security-RFC / architecture)

Verdict: unanimous **APPROVE WITH CHANGES**. For traceability, every change the review made to
this document, numbered as cited throughout. Items 1–9 are the blocking (MUST-FIX) corrections,
all board-verified; 10–15 are the OQ-B answers; 16 records the OQ-P recommendations (all
**ACCEPTED by Peter 2026-07-21**); 17–25 are advisory corrections and nits.

**Blocking (MUST-FIX):**

1. **§6 mapping table, row 3, server half, was a deadlock — found independently by two seats.**
   The trigger "`isTLSHandshakeComplete()` first true → `tryMarkHandshakeDone()`" is circular:
   server-side `isTLSHandshakeComplete()` returns true only at `HANDSHAKE_CONFIRMED`
   (`QuicTLSEngineImpl.java:866-883`), and the only transition into that state is
   `tryMarkHandshakeDone()` itself (`:829-844`). Replaced with: observe
   `getHandshakeState() == NEED_SEND_HANDSHAKE_DONE` after consume/pull (equivalently, attempt
   `tryMarkHandshakeDone()` and run the completion residue iff it returns true — the JGDMS
   `QuicEngineMtlsTest` drive-loop pattern). Client half of the row stands. The §2.1 bullet was
   also role-corrected: "never true from CRYPTO alone" is server-only; the client completes from
   CRYPTO alone (`NEED_RECV_HANDSHAKE_DONE` entered inside the pull that drains its Finished,
   `:457-465`). (§2.1, §6 table + note 4.)
2. **Server `sender.enableAppLevel()` timing (security seat).** The table fired it at
   `keysAvailable(ONE_RTT)` first-true, but the server derives 1-RTT keys while producing its own
   Finished (`Finished.java:849-857`) — before client cert/CV/Finished, i.e. before the SPIFFE
   trust manager runs — opening a pre-auth 0.5-RTT send window current kwik does not have.
   Fixed: `setOneRttContext(...)` stays at `keysAvailable(ONE_RTT)`; `enableAppLevel()` moves to
   the server completion step, immediately before sendHandshakeDone — matching today's
   `ServerConnectionImpl.java:302` ordering. (§2.2, §6 table + note 5.)
3. **Stage A contained three build-breaking circularities at the A/B boundary** (the Step C/D
   failure class): it deleted the buffered-CH typed parse (`ServerConnectionCandidate.java:265-269`
   still uses it), `getTlsEngine()` (`QuicConnectionImpl.java:565,995`;
   `ServerConnectionImpl.java:221-224,159,518-524`; `CryptoStream.java:190,337-349`), and the
   `TlsProtocolException` catch/mapping (`QuicConnectionImpl.java:430-444,858-871`) — all still
   referenced by the live server engine until Stage B. Adjudicated resolution: those deletions
   move wholesale into Stage B; Stage A adds the port-driven client path alongside the legacy
   machinery. Also reconciled the internal contradiction between §3.2 ("tests migrate
   per-stage") and §8's old Stage D ("11-file migration"): per-stage governs; Stage D carries
   only residue. Stage scope text and estimates rewritten accordingly. (§3.1, §3.2, §8.)
4. **Blast radius missed non-agent15-importing consumers of deleted API — found by two seats:**
   `interop/src/main/java/tech/kwik/interop/InteropClient.java:191-206,253-275`
   (`getNewSessionTickets`/`sessionTicket`/`connect(earlyDataRequests)`),
   `samples/src/main/java/tech/kwik/sample/echo/EchoClientUsing0RTT.java:86-126`,
   `h09/src/main/java/tech/kwik/h09/client/Http09Client.java:192-193`
   (`connect(List.of(StreamEarlyData))`), and the public surface
   `QuicClientConnection.connect(List<StreamEarlyData>)` + `StreamEarlyData`
   (`QuicClientConnection.java:41-65`). Added to §1.7/§3.1/§8; interop-runner capability losses
   (resumption, zerortt — joining keyupdate) named in Stage D's delta accounting.
5. **§3.6 residue claim wrong by count.** The post-Stage-D agent15 removal set is:
   `core/module-info` requires (2 lines), **four** build.gradle deps (`core/build.gradle:75`,
   `cli/build.gradle:9`, `interop/build.gradle:10`, `qlog/build.gradle:6` —
   declared-but-unused), and the `ext.agent15_version = '3.3'` pin in
   `buildSrc/src/main/groovy/buildlogic.java-common-conventions.gradle:52`. Stage D's grep-gate
   now enumerates exactly this set. (§3.2, §8.)
6. **OQ-P4 must dispose of the `version_information` transport parameter.** Keeping the TP
   advertised (`ServerConnectionImpl.java:393`) while deleting the validation
   (`ServerConnectionImpl.java:630-643`, `QuicClientConnectionImpl.java:1017-1032`) would
   violate RFC 9368's MUSTs. Board recommendation: drop the TP both directions (fully legal for
   a non-RFC-9368 endpoint; zero downgrade surface; Inc 4 full-VN brings it back). Removal diff
   assigned per stage: client half → Stage A; server half → Stage B, including the
   `VersionChangeUnconfirmed` machinery in `packet/ServerRolePacketParser.java` (previously
   absent from the blast radius); `Builder.preferredVersion` (`QuicClientConnection.java:111`) →
   Stage D. Dying tests (`ServerConnectionImplTest.java:271-289`,
   `QuicClientConnectionImplTest.java:616-630`) named in Stage D's delta accounting with a
   replacement server-serves-offered-version assertion. (§2.5, §3.1, §8, §9 OQ-P4.)
7. **STD-010 §6.2's positive 0-RTT guards are a co-requisite of the Inc 3 acceptance milestone**
   (engine-absence is explicitly insufficient per STD-010): the `max_early_data_size=0`
   assertion and the ZERO_RTT send-path assertion gate the milestone even though they are §3.5's
   work. Stated in Stage C's gate language. (§8.)
8. **Decision-gate sequencing + Inc H.** OQ-P1 pinned before Stage A; OQ-P3/OQ-P4 before
   Stage B; OQ-P5/OQ-P6 before Stage C. SOW §7.3a's adversarial-hardening increment (Inc H,
   1–2 weeks) sequences between Stages B and C unless Peter waives the SOW ordering, and is
   excluded from the stage estimate. (§8, §9.)
9. **Estimate revised 15–23 d → 18–28 engineering-days for A–D** (A 5–7 + B 7–10 + C 3–5 +
   D 3–6): Stage B carries the moved deletions plus the params-before-consume novelty (high
   end); Stage D's original 3–5 d was honest only at 5–8 d under the bulk-migration reading and
   shrinks to a residue carrier under per-stage migration. Inc H separate. (§8.)

**OQ-B answers (10–15) and OQ-P recording (16):**

10. OQ-B1 ANSWERED — reviving `Completed` predicate-neutral; every `RecoveryManager` read traced
    (`RecoveryManager.java:213,227,255,334,570-576`); sole listener registrant
    `SenderImpl.java:152`. Endorsed. (§6 note 1, §9.)
11. OQ-B2 ANSWERED — read-only `SSLSession` accessor, hard-gated on `HandshakeState.Confirmed`;
    MUST-NOT-expose list recorded; identity fixed-at-handshake per STD-010 §6.3. (§9.)
12. OQ-B3 ANSWERED, CLOSED in engine source — EE production at CH-consume unconditional
    (`ClientHello.java:1226-1249`); sole branch HRR, still consume-time; HRR case added to
    Stage B's gate negative tests. (§8, §9.)
13. OQ-B4 ANSWERED — Retry re-point deferral to Inc 4 coherent, no dual-authority hazard;
    condition: Inc 4 deletes kwik's local fixed-key implementation in the same diff. (§2.5, §9.)
14. OQ-B5 ANSWERED — framing-only CH check adequate; keep existing caps/filters; both parse
    surfaces recorded as §7.3a fuzz targets. (§2.3, §9.)
15. OQ-B6 ANSWERED — drive-loop cap ~64, empty-but-non-null terminal, cap breach →
    `INTERNAL_ERROR`, fail-closed. (§2.2, §9.)
16. OQ-P1–OQ-P6 recorded with board recommendations, all **ACCEPTED by Peter 2026-07-21** — including the
    STRENGTHENED OQ-P2 (positively disable TLS resumption: JSSE PSK resumption re-admits the
    original identity without re-running the trust manager,
    `PreSharedKeyExtension.canRejoin:446-459`), OQ-P5's fail-closed `CLIENT_AUTH_REQUIRED`
    evidence (`CertificateMessage.java:1127-1139`) with its two riders, and OQ-P6's added
    concurrent-handshaking-connections cap. (§9.)

**Advisory corrections and nits:**

17. §5: the deadline is part of the AUTH story (bounds a stalling cert-less client), not just
    availability; the security seat verified the mTLS failure chain fail-closed end-to-end with
    no swallow point, and pre-auth app-data ingress impossible by construction
    (`QuicTLSEngineImpl.decryptPacket:348-353` refuses 1-RTT decrypt before
    `HANDSHAKE_CONFIRMED` — stricter than RFC 9001 requires). (§5.)
18. §2.2/§2.4: run `validateAndProcess`/`setPeerTransportParameters` **inside** the
    params-consumer callback (invalid peer params abort at the exact protocol point via
    `processRemoteQuicTransportParameters:823-826`), resolving the cache-then-apply vs
    process-at-consume two-phrasings ambiguity. (§2.2, §2.4.)
19. Stage A gate: the raw-engine UDP harness named as its own estimate line (a mini QUIC
    server — the fattest Stage A item), and the CH-byte-identity Retry re-send assertion
    (RFC 9002 §6.3) added as a named gate item. (§8.)
20. Stage B/C gate: client-rejects-untrusted-server negative test added — post-migration it is
    only observable over transport; silent coverage loss otherwise. (§8.)
21. Estimate mapping: SOW §7.2's "TP re-home + strip 0-RTT/tickets 2–4 d" line reconciled
    against the stages that absorb it (double-count guard). (§8.)
22. §1 header nit: of the "15 files importing agent15", one is `module-info.java`'s `requires`,
    not an import. (§1.)
23. §2.3 option (a) nit: server TPs include per-connection CIDs (`ServerConnectionImpl:395-399`)
    — knowable at construction, but not connection-independent bytes; "static" means
    ALPN-independent, not identical-across-connections. (§2.3.)
24. Stage D's phrase "tickets/0-RTT wiring" explicitly excludes `ZeroRttPacket` — that survives;
    it is §3.5's. (§8.)
25. Interop nit (record only, no action): kwik drops (not buffers) early 1-RTT packets arriving
    before server confirmation — RFC 9001 §5.7 says an endpoint MAY store them; dropping is
    safe and spec-legal.
