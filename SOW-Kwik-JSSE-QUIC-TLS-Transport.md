# SOW — Kwik fork: drive the QUIC transport with the JDK's JSSE QUIC-TLS engine

- **Date:** 2026-07-06
- **Repo:** `github.com/pfirmstone/kwik` (fork of `github.com/ptrd/kwik`; `upstream` remote tracked)
- **Status:** Scope of work / planning. Describes the work to be done; no implementation here.
- **Runtime target:** DirtyChai (OpenJDK 27 fork) **only** — same posture as JGDMS. Not portable to
  stock OpenJDK (see §6).
- **License:** LGPL-3.0 / GPL-3.0 (inherited from kwik). Retain upstream copyright, `LICENSE.txt`,
  `LICENSE-LESSER.txt`, and add a NOTICE crediting Peter Doornbosch and marking this a derivative.

---

## 1. Objective

Replace kwik's bundled TLS 1.3 stack (**agent15**) with the JDK's **JSSE QUIC-TLS engine**
(`jdk.internal.net.quic.QuicTLSEngine`, added by JEP 517), keeping kwik's mature RFC 9000/9002
transport. The result is a **bidirectional** (client + server) QUIC transport whose TLS handshake,
key schedule, packet AEAD, and certificate validation are performed by the JDK engine — so that
JGDMS's existing **JSSE-based SPIFFE/X.500 mutual-auth** (`AuthManager` / `FilterX509TrustManager`
/ `SubjectCredentials`) is reused unchanged, and **traffic secrets never leave the engine**.

Why this fork rather than the alternatives (verified in the JGDMS ADVICE series):
- **Build from scratch:** ~30k LOC of RFC 9000/9002 (framing, streams, flow control, loss detection,
  congestion control, accept loop). Kwik already has all of it.
- **Kwik + agent15 as-is:** agent15 has **no server-side client-cert auth**, is JSSE-incompatible
  (loses JGDMS auth reuse), and is self-described as not security-reviewed.
- **Kwik transport + JSSE engine (this SOW):** reuses kwik's transport, keeps JSSE auth, gets
  server-mTLS from the engine, and keeps secrets encapsulated. The two projects' gaps are
  complementary — kwik has the transport but no server-mTLS TLS; the JDK engine has server-mTLS TLS
  but no server transport.

---

## 2. The cut (RFC 9001 boundary)

RFC 9001 gives a clean TLS↔transport seam: TLS owes the transport exactly three things —
1. **CRYPTO handshake bytes** per encryption level,
2. **keys / packet protection**, and
3. **QUIC transport parameters** (carried in a TLS extension).

Everything else is transport. The fork keeps the transport and re-points those three things at the
JDK engine. Confirmed against this fork's source: the agent15 dependency is concentrated in
crypto, connection orchestration, transport-params, and session-tickets; the transport machinery
(`ack`, `cc`, `cid`, `frame`, `packet`, `recovery`, `send`, `receive`, `stream`) does **not** import
agent15 and is kept as-is.

---

## 3. Work items

### 3.1 Isolation port (do this first)

Define **one** internal interface in the fork — e.g. `tech.kwik.core.tls.QuicTlsPort` — that wraps
`jdk.internal.net.quic.QuicTLSEngine`. **All** re-pointed kwik code talks to the port, never to
`jdk.internal.net.quic` types directly. Rationale: when OpenJDK publishes a public QUIC-TLS API
(JEP 517 flags this as future work), conversion is a single-file swap, and the transport becomes
unit-testable against a mock port.

### 3.2 Crypto seam — delegate AEAD to the engine

- **Files:** `core/.../crypto/ConnectionSecrets.java`, `core/.../crypto/CryptoStream.java`.
- **Today:** kwik pulls raw traffic secrets from agent15 (`getClientHandshakeTrafficSecret()` …),
  derives its own AEAD keys via HKDF, and builds its own `Aes128Gcm` / `Aes256Gcm` /
  `ChaCha20Poly1305` ciphers to protect packets.
- **Change:** delete the key-derivation and AEAD construction; delegate packet protection to the
  engine via the port: `encryptPacket` / `decryptPacket` / `computeHeaderProtectionMask` /
  `getHeaderProtectionSampleSize` / `getAuthTagSize` / `deriveInitialKeys` / `keysAvailable` /
  `discardKeys`. **Raw secrets are never requested** — this is the security point of the fork.
- **Dependency cleanup:** `at.favre.lib.hkdf` likely drops (engine derives keys). `io.whitfin.siphash`
  stays (stateless retry token / connection-ID, transport-side). Verify before removing from
  `module-info`.

### 3.3 Handshake-driver seam — push callbacks → engine pull model

- **Files:** `core/.../impl/QuicConnectionImpl.java`, `core/.../impl/QuicClientConnectionImpl.java`,
  `core/.../server/impl/ServerConnectionImpl.java` (+ `ServerConnectionCandidate.java`,
  `ServerConnectorImpl.java`, `server/ServerConnectionFactory.java`).
- **Today:** kwik reacts to agent15's **push** callbacks (`TlsStatusEventHandler.earlySecretsKnown` /
  `handshakeSecretsKnown` / `handshakeFinished`, plus `MessageProcessor`), and constructs the TLS
  engine via `TlsClientEngineFactory.createClientEngine(...)` (static) and an injected
  `TlsServerEngineFactory` on the server.
- **Change:** drive the engine's **pull** model through the port: feed inbound CRYPTO frames to
  `consumeHandshakeBytes(KeySpace, ByteBuffer)`, pull outbound with `getHandshakeBytes(KeySpace)`,
  poll `getHandshakeState()` / `isTLSHandshakeComplete()`, and drive `tryMarkHandshakeDone()`
  (server) / `tryReceiveHandshakeDone()` (client) and `versionNegotiated(...)`. Replace both engine
  construction sites (client and server) with port construction over the JDK engine. This is the
  largest and trickiest item; scope it by reading the two connection state machines first.
- **GAP-3 (delegated tasks):** the engine's `getDelegatedTask()` is a no-op returning `null` while
  `useDelegatedTask()` returns `true`. The driver **MUST NOT** block-loop on `NEED_TASK`; trust work
  (e.g. cert validation) runs inline. Acceptable on the virtual-thread model — but write the driver
  knowing no task will ever be handed back.

### 3.4 Transport-parameter seam

- **File:** `core/.../tls/QuicTransportParametersExtension.java`.
- **Change:** route local params through `setLocalQuicTransportParameters(ByteBuffer)` and register a
  consumer via `setRemoteQuicTransportParametersConsumer(...)`.
- **GAP-1:** the engine has **no getter** for the peer's transport parameters (push-only). The fork
  must **cache** the consumer callback's bytes when it fires; do not expect to query them later.

### 3.5 Key-space mapping and 0-RTT exclusion

- Map kwik's encryption levels to the engine `KeySpace`: `INITIAL`, `HANDSHAKE`, `ONE_RTT`, `RETRY`.
- **No 0-RTT.** The engine refuses `ZERO_RTT` (`keysAvailable(ZERO_RTT) → false`,
  `consumeHandshakeBytes(ZERO_RTT,…)` throws). Strip / disable early-data and the 0-RTT session-ticket
  path on both client and server (`QuicSessionTicket.java`, `impl/QuicSessionTicketImpl.java`). The
  port's key-space type should not even offer a `ZERO_RTT` value. (Non-0-RTT session resumption is
  optional — decide separately; default: leave out for the first cut.)

### 3.6 Module descriptor

- `core/.../module-info.java`: remove `requires tech.kwik.agent15;`. The module reads
  `jdk.internal.net.quic` via DirtyChai's **qualified export** (see §6) — no `requires` is needed for
  it. Keep the module name **`tech.kwik.core`** stable: DirtyChai's `module-info` names this module as
  the export target, so the two must agree.

---

## 4. Out of scope / non-goals

- Building any RFC 9000/9002 transport machinery from scratch (reuse kwik's).
- Exposing raw traffic secrets from the JDK engine (the whole point is to **not** do this).
- Portability to stock OpenJDK (DirtyChai runtime only — §6).
- 0-RTT / early data (excluded by construction).
- SPIFFE/X.500 identity logic — that stays in **JGDMS**. This transport is auth-agnostic: it uses the
  configured JSSE `SSLContext`/engine, which carries whatever trust managers JGDMS installs.
- Upstreaming to `ptrd/kwik` (keep the door open — track the `upstream` remote — but not now).

---

## 5. Deliverables (suggested increments)

| Inc | Deliverable |
|---|---|
| 0 | Fork builds on the DirtyChai JDK; agent15 removed; `QuicTlsPort` wired over `QuicTLSEngine`. |
| 1 | INITIAL+HANDSHAKE handshake completes client↔server over loopback; engine does AEAD; `getSession().getPeerCertificates()` populated both ends. |
| 2 | ONE_RTT application data; streams carry payload end-to-end. |
| 3 | Server accept loop with **client-auth required**; SPIFFE/X.500 positive **and** negative (wrong/absent identity → rejected). |
| 4 | Interop against ≥1 other QUIC implementation (JDK HTTP/3 client and/or upstream kwik); Retry + Version-Negotiation paths. |

---

## 6. Runtime, dependency, and DirtyChai coupling

- **DirtyChai side (settled; humans implement per DirtyChai's advise-only policy):** trust-dispatch
  relaxation **B1** (`SSLContextImpl.isUsableWithQuic()` accepts any `X509ExtendedTrustManager`),
  **B2** (QUIC trust dispatch routes custom managers through the standard 3-arg `SSLEngine`-adapter),
  **B3** (server-block fail-secure final `else`) — all done — plus **one line** in DirtyChai's
  `module-info.java`: add `tech.kwik.core` to `exports jdk.internal.net.quic to java.net.http;`. No
  driver facade is built; the fork compiles against `jdk.internal.net.quic.QuicTLSEngine` directly and
  versions in lockstep with DirtyChai.
- **Every type on the engine's SPI signatures lives in `jdk.internal.net.quic`** (verified:
  `QuicVersion`, `QuicTransportException`, `QuicKeyUnavailableException`, `QuicOneRttContext`,
  `QuicTransportParametersConsumer`, `QuicTLSContext`), so the single qualified export covers the whole
  surface — no sibling-package exports needed.
- **Stock-JDK caveat:** even with the engine exported, a stock OpenJDK rejects custom (non-SunJSSE)
  trust managers at `isUsableWithQuic`; only DirtyChai's B1/B2/B3 admits JGDMS's SPIFFE `AuthManager`.
  Hence DirtyChai-only, like JGDMS.

---

## 7. Effort estimate and risks

### 7.1 Handshake-glue coupling — scoped (2026-07-06): clean rewrite, not deep entanglement

The §3.3 concern ("clean rewrite vs deep entanglement") was resolved by reading the connection state
machines. **It is a clean, delete-dominant rewrite** because kwik and the JDK engine use opposite
integration models:

- kwik drives agent15 as a **message-object** API — `CryptoStream` parses raw CRYPTO into typed TLS
  messages (`TlsMessageParser`) and dispatches them (`tlsEngine.received(ClientHello, …)`).
- the JDK `QuicTLSEngine` is **byte-oriented** — feed `consumeHandshakeBytes(KeySpace, ByteBuffer)`,
  pull `getHandshakeBytes(KeySpace)`; it parses/produces handshake messages internally.

So the TLS-message machinery is **deleted**, not adapted. Evidence: the `TlsStatusEventHandler`
callbacks (`ServerConnectionImpl` :279–349, `QuicClientConnectionImpl` :582–641) are short and split
cleanly — the secret-computation lines are deleted (engine holds keys), and the residual **transport**
orchestration in `handshakeFinished` (enable app level, discard handshake keys, send HANDSHAKE_DONE,
`connectionState = Connected`, state-listener + event emission, start application protocol) is kept and
re-fired from the engine's pull model (`keysAvailable` / `isTLSHandshakeComplete`). The transport core
(`ack`, `cc`, `cid`, `frame`, `packet`, `recovery`, `send`, `stream`) does not touch agent15 at all;
coupling meets the transport at ~3 transition points only. `tlsEngine.add(...)` is TLS-extension config
(→ `SSLParameters`/transport-param setters), not CRYPTO feed. Construction is one static client site
(`QuicClientConnectionImpl.java:206`) + one injected server factory (`ServerConnectionImpl.java:142`),
both → build an `SSLContext` and `createEngine()`.

### 7.2 Estimate — ≈ 6–8 weeks to green bidirectional mTLS + basic interop

One developer comfortable with QUIC/TLS, after ramp:

| Work | Est. |
|---|---|
| Isolation port + engine construction; map ~12 agent15 setters → `SSLContext`/`SSLParameters` (client+server) | 3–5 d |
| `CryptoStream` → byte pipe (keep reassembly, delete TLS-message parsing) | 3–5 d |
| Handshake-driver pull loop (replace 5 callbacks × 2 roles; re-fire transitions; NEED_TASK inline; HANDSHAKE_DONE) | 5–8 d |
| Delete `ConnectionSecrets` AEAD/HKDF; delegate to engine `encrypt/decrypt/HP` in the packet path | 3–5 d |
| Transport-params re-home (+GAP-1 cache); strip 0-RTT/early-data/tickets | 2–4 d |
| Bring-up: loopback client↔server handshake green (Inc 1) | 3–5 d |
| mTLS pos/neg + interop vs JDK HTTP/3 client (Inc 3–4) | 5–8 d |

Risk is concentrated in the middle ~2–3 weeks (crypto + driver seam). **Mitigant keeping it at the low
end:** the JDK engine's pull state machine is documented and already has a reference driver — the JDK's
own HTTP/3 client drives the identical engine. **What could push it to 2–3 months:** interop /
loss-recovery interactions with the re-pointed key-space transitions surfacing subtle handshake bugs
(handshakes are iterative), or a config setter with no clean `SSLParameters` equivalent. No structural
entanglement to fight — the residual risk is iteration, not architecture. Estimate covers the transport
fork only (excludes the DirtyChai one-line export and the JGDMS `Endpoint`/`ServerEndpoint` SPI on top),
and assumes QUIC/TLS familiarity — add ramp time otherwise.

### 7.3 Standing risks

- **Engine API instability:** `jdk.internal.net.quic` is JEP-517-fresh internal API. Mitigated by the
  §3.1 isolation port + DirtyChai lockstep; converts to the OpenJDK public API when published.
- **Upstream drift:** the untouched transport packages merge cleanly from `upstream`; divergence is
  confined to the TLS seam. Merge upstream transport/security fixes periodically.
- **License:** LGPLv3 obligations travel with the fork; keep it out of GPLv2 `java.base` (it lives in
  JGDMS userspace).

---

## 8. References

- **JGDMS:** `JGDMS-STD-010-QUIC-JERI-Transport-v0.1-DRAFT.md` (transport standard),
  `SOW-QUIC-JERI-Transport.md`, `ADVICE-quic-tls-exposure-2026-06-30.md`,
  `ADVICE-quic-tls-dirtychai-locations-2026-07-05.md`, `ADVICE-quic-facade-interface-2026-07-05.md`,
  `SOW-DirtyChai-QUIC-TLS-Investigation.md`.
- **Standards:** RFC 9000 (QUIC), RFC 9001 (TLS for QUIC), RFC 9002 (loss/congestion),
  RFC 8446 (TLS 1.3), JEP 517.
