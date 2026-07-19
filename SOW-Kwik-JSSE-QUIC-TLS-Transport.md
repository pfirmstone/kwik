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
agent15 directly.

**Caveat — `packet` is not untouched.** `packet` does not *import* agent15, but it *consumes* the
`Aead` objects that `ConnectionSecrets` (being deleted, §3.2) produces: `QuicPacket` calls
`aeadEncrypt` / `createHeaderProtectionMask` etc. against those objects. `packet` is therefore part
of the crypto-seam change surface, not untouched transport — see §3.2 for the re-architecture this
implies.

---

## 3. Work items

### 3.1 Isolation port (do this first)

Define **one** internal interface in the fork — e.g. `tech.kwik.core.tls.QuicTlsPort` — that wraps
`jdk.internal.net.quic.QuicTLSEngine`. **All** re-pointed kwik code talks to the port, never to
`jdk.internal.net.quic` types directly. Rationale: when OpenJDK publishes a public QUIC-TLS API
(JEP 517 flags this as future work), conversion is a single-file swap, and the transport becomes
unit-testable against a mock port.

**Gradle toolchain wiring — landed 2026-07-19 (commit `97abfce1`, branch
`build/quic-tls-port-gradle-toolchain-v2`).** The already-merged `QuicTlsPort`/`QuicTlsPortImpl`
production code and both test suites (`QuicTlsPortMockTestabilityTest`,
`QuicTlsPortImplRealEngineTest`) were, until now, only verified by hand-invoking `javac`/`java`
directly against the DirtyChai image. `core/build.gradle` now pins a real Gradle toolchain
(`languageVersion = 27`) resolved via `gradle.properties`' `org.gradle.java.installations.paths`
(gitignored — machine-local, each dev/CI box needs its own copy pointing at its own DirtyChai
build) so `./gradlew --offline --no-daemon clean :kwik:test --tests "tech.kwik.core.tls.*"` builds
and runs both suites for real — 31/31 green.

Empirical finding along the way, relevant to any future work near `jdk.internal.net.quic`:
javac's `--release N` cross-compilation mode cannot see `jdk.internal.net.quic` **at any release
value, including 27** (DirtyChai's own version, not just a lower one). `--release` compiles
against `ct.sym` stub API data for that release rather than the real `jrt` image, and `ct.sym`
does not carry DirtyChai's qualified-export patch (`qualified exports jdk.internal.net.quic to
java.net.http tech.kwik.core`, confirmed via `java --describe-module java.base`). So `core`'s
`JavaCompile` tasks force `options.release` back to `null` after configuring the toolchain — this
is now a hard constraint on how `core` may ever be compiled, not just a convenience setting.

This is a first step toward §3.6, not §3.6 itself: `module-info.java` is untouched (still no
`requires tech.kwik.agent15` removal, still no `requires jdk.internal.net.quic` — correctly, since
the qualified export doesn't need one), and agent15 wiring is untouched. **Known gap, left
deliberately unfixed:** bumping only `core` to language level 27 breaks Gradle's variant-aware
dependency resolution for `qlog`/`interop`/`cli`/`samples`/`h09`, all of which depend on
`project(':kwik')` — a whole-reactor `./gradlew build` (what CI runs) now fails at those five
dependency edges ("looking for a library compatible with JVM runtime version 11, but 'project
:kwik' is only compatible with JVM runtime version 27 or newer"), even though `:kwik:compileJava`
and `:kwik:test` are green in isolation. Fixing that reactor-wide break would mean touching those
five subprojects' build files, which this task scoped out ("only core should need to change") —
left as an open follow-up decision (bump them too, or call `java.disableAutoTargetJvm()`) for
whoever picks up §3.6 in earnest.

**Reactor-wide toolchain bump — landed 2026-07-19 (commit `07f3b368`, branch
`build/bump-all-subprojects-jdk27`).** Picked "bump everyone" over `disableAutoTargetJvm()` per the
open decision above. The toolchain/`options.release=null` block moved from `core/build.gradle` up
into `buildlogic.java-common-conventions.gradle`, so all six subprojects (`kwik`, `kwik-qlog`,
`kwik-interop`, `kwik-cli`, `kwik-samples`, `kwik-h09`) now share the Java 27 toolchain; only the
`--add-exports jdk.internal.net.quic=ALL-UNNAMED` test flags stay core-specific. A genuine
`./gradlew --offline --no-daemon build` (matching `.github/workflows/gradle.yml`) now clears
dependency resolution across the whole reactor — the JVM-11-vs-27 edge failure is gone — and
`:kwik:test --tests "tech.kwik.core.tls.*"` is still 31/31 green. One pre-existing, unrelated
failure surfaces once the full reactor is actually exercised: `CertificateSelectorTest` (2 of its 6
cases) fails under a real DirtyChai-27 JVM; reproduced identically against `core` alone at
`a5dd0916` (i.e. it predates this commit and isn't caused by it) — apparent JSSE
`X509KeyManagerImpl` issuer-DN-matching behavior difference between whatever JDK it last passed
under and DirtyChai 27. Left unfixed here as out of this task's scope; flagged for whoever picks
this up next. Separately, **`.github/workflows/gradle.yml` still provisions stock OpenJDK 17**, not
a DirtyChai build — since `jdk.internal.net.quic` only exists on DirtyChai, actual GitHub Actions
CI cannot build this reactor at all as currently configured, independent of this fix. Not addressed
here (no DirtyChai JDK artifact/publishing story exists yet) — flagged, not solved.

### 3.2 Crypto seam — RE-ARCHITECT the packet AEAD call sites onto the engine's split calls

**This is a re-architecture of `packet` + both packet parsers, not a deletion.** kwik and the
engine protect packets under **different shapes**: kwik's `QuicPacket` performs protection in
**two caller-driven steps** — payload `aeadEncrypt` (kwik computes the nonce and does the AEAD
call itself against secrets it derived) plus a separate `createHeaderProtectionMask` (kwik samples
the ciphertext and XORs the mask into the header itself) — whereas the engine also splits
protection into **two mandatory calls per direction**: `computeHeaderProtectionMask(...)` (header-
protection sampling/masking) must be called separately from `encryptPacket(...)` /
`decryptPacket(...)` (nonce handling + AEAD only — header protection is not fused into either
call; the engine's own `decryptPacket` javadoc requires protection removed from the header before
the call). `computeHeaderProtectionMask` is not an optional fallback for cases a fused call
doesn't fit — there is no fused call; it is mandatory on both directions, for every packet.
Reconciling kwik's two-step model with the engine's two-step model is a rewrite of `QuicPacket`
and both packet parsers — the call sites change shape, not just their source of keys.

- **Files:** `core/.../crypto/ConnectionSecrets.java`, `core/.../crypto/CryptoStream.java`,
  `core/.../packet/QuicPacket.java` (+ both packet parsers — see §2 caveat).
- **Today:** kwik pulls raw traffic secrets from agent15 (`getClientHandshakeTrafficSecret()` …),
  derives its own AEAD keys via HKDF, and builds its own `Aes128Gcm` / `Aes256Gcm` /
  `ChaCha20Poly1305` ciphers, then calls its own two-step protect/unprotect from `QuicPacket`.
- **Change:** delete the key-derivation and AEAD construction in `ConnectionSecrets`; re-point
  `QuicPacket`'s two-step call sites onto the engine's split calls via the port: `encryptPacket` /
  `decryptPacket` / `computeHeaderProtectionMask` / `getHeaderProtectionSampleSize` /
  `getAuthTagSize` / `deriveInitialKeys` / `keysAvailable` / `discardKeys`. **Raw secrets are never
  requested** — this is the security point of the fork.
- **KEY-UPDATE — explicit deletion, not adaptation.** The 1-RTT key-phase ratchet lives
  transport-side today: `KeyUpdateSupport` plus `ShortHeaderPacket`'s key-phase logic
  (`getKeyPhase`, `confirmKeyUpdateIfInProgress`, `computeNextApplicationTrafficSecret`). This
  machinery **MUST be deleted**, not re-pointed: the engine owns the key-update ratchet itself via
  `decryptPacket(KeySpace, packetNumber, keyPhase, …)` (per-packet key-phase-aware decrypt) plus
  `setOneRttContext(QuicOneRttContext)` (§3.3). **WARN:** if this item is read literally as "keep
  the transport, just re-point the AEAD calls," a developer will leave **two key-phase
  authorities racing** — kwik's own ratchet and the engine's — which is both a correctness hazard
  (disagreeing on which keys are current) and a secrecy hazard (stale/duplicate key material). The
  transport-side ratchet must be removed, full stop.
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
- **HANDSHAKE_DONE completion (empirically confirmed 2026-07-06 by the JGDMS `QuicEngineMtlsTest`
  engine-pair test).** `isTLSHandshakeComplete()` is NOT the same as `HANDSHAKE_CONFIRMED`: the
  server engine stays at `NEED_SEND_HANDSHAKE_DONE` (TLS complete, 1-RTT keys available) until the
  transport actually carries the QUIC HANDSHAKE_DONE frame — so the driver must issue
  `tryMarkHandshakeDone()` (server) / `tryReceiveHandshakeDone()` (client) as a real transport step,
  not merely poll TLS completion. Also confirmed by that test: construction is
  `new QuicTLSContext(sslContext).createEngine()` gated by `isQuicCompatible` (needs TLSv1.3); the
  engine rejects a handshake without the transport-parameters extension (`0x016d missing_extension`)
  — an empty `ByteBuffer.allocate(0)` + a registered `setRemoteQuicTransportParametersConsumer`
  suffices — and requires `versionNegotiated(QUIC_V1)`.
- **GAP-3 (delegated tasks):** the engine's `getDelegatedTask()` is a no-op returning `null` while
  `useDelegatedTask()` returns `true`. The driver **MUST NOT** block-loop on `NEED_TASK`; trust work
  (e.g. cert validation) runs inline. Acceptable on the virtual-thread model — but write the driver
  knowing no task will ever be handed back.
- **Omitted engine SPI methods — add to the driver seam (ADVICE enumeration):**
  - `setOneRttContext(QuicOneRttContext)` — supplies the engine's 1-RTT key-update context; gates
    **Inc 2** (ONE_RTT application data / key updates).
  - `restartHandshake()` — restarts the handshake after Version Negotiation; gates **Inc 4**
    (Version-Negotiation path).
  - `getCurrentSendKeySpace()` — the driver needs this to know which `KeySpace` to send the next
    outbound packet in.
  - `signRetryPacket(...)` / `verifyRetryPacket(...)` — Retry-**packet** integrity is
    **engine-owned**, driven through the port alongside the other handshake-drive calls. This is
    separate from the §3.2 SipHash retention: SipHash stays for **connection-ID** hashing
    (stateless CID generation) only, not for Retry-token/packet integrity, which the engine signs
    and verifies.
- **Server handshake-completion deadline (DoS) — Inc-3 acceptance criterion.** Because
  `getDelegatedTask()` is a permanent no-op (GAP-3), certificate validation (PKIX chain-path,
  possibly CRL/OCSP, plus SPIFFE-SAN matching) runs **inline on the handshake-drive thread**. kwik's
  existing DoS defenses don't cover this: `abortHandshake` is **client-only**; the server side has
  only `maxIdleTimeout` (idle timeout is not a handshake-completion deadline) plus
  pre-address-validation anti-amplification — neither bounds a stalled in-progress handshake. Initial
  packets are processed on a **shared ≤10-thread pool**, so a slow or hostile peer, or a slow trust
  manager (e.g. a hanging CRL/OCSP fetch), can pin that shared pool (slowloris-style). **Work item:**
  add a server-side handshake-completion deadline — generous, configurable, mirroring JGDMS P1's F2
  handshake read-progress-deadline design and default — that aborts a connection whose handshake has
  not completed within the window. **Also require** that certificate validation run per-connection
  (on its own virtual thread) rather than inline on the shared pool thread, so one slow trust manager
  cannot exhaust the pool for other connections. Both parts are an **Inc-3 acceptance criterion**.
- **Server client-auth wiring (the SPIFFE crux).** The server port must set
  `SSLParameters.setNeedClientAuth(true)` from the JGDMS `SSLContext`/config — agent15 had **no**
  server-side client-cert auth, and enabling it is the whole point of this fork. The DirtyChai mTLS
  server pos/neg test (ADVICE item D) is an **Inc-0/1 predecessor**: server mTLS is
  present-but-untested today (§6). End-to-end trace of the SPIFFE reuse this wiring depends on:
  `SSLContext(JGDMS AuthManager) → QuicTLSContext → engine → CertificateRequest → client
  Certificate → server checkClientTrusted (SPIFFE-SAN match)` — this trace's DirtyChai
  dependencies (B1/B2/B3) landed in trunk `98bcc58115f` (§6.1); the remaining predecessor is the
  functional mTLS-server test (ADVICE item D).

### 3.4 Transport-parameter seam

- **File:** `core/.../tls/QuicTransportParametersExtension.java`.
- **Change:** route local params through `setLocalQuicTransportParameters(ByteBuffer)` and register a
  consumer via `setRemoteQuicTransportParametersConsumer(...)`.
- **GAP-1:** the engine has **no getter** for the peer's transport parameters (push-only). The fork
  must **cache** the consumer callback's bytes when it fires; do not expect to query them later.
- **GAP-1 ordering barrier.** Applying the cached peer transport parameters is an **ordered
  barrier**: no stream creation, no flow-control admission, and no CID registration may proceed
  until the params cached from the `setRemoteQuicTransportParametersConsumer` callback have been
  applied. The limits seeded from those params include `StreamManager.setInitialMaxStreams*`,
  `FlowControl.updateInitialValues`, and `ConnectionIdManager`'s peer CID limit — all of them must
  see the real peer values, never a default/zero placeholder, before anything gated by them runs.
  **Add a negative test:** peer params delayed relative to the first application frame arriving —
  assert deterministic handling (block/queue until params land), never silently proceeding with
  default or zero limits in force.

### 3.5 Key-space mapping and 0-RTT exclusion

- Map kwik's encryption levels to the engine `KeySpace`: `INITIAL`, `HANDSHAKE`, `ONE_RTT`, `RETRY`.
- **No 0-RTT — fail-closed BY CONSTRUCTION, per STD-010 §6.2 (normative MUST), not by relying on
  engine refusal.** STD-010 §6.2 requires that the 0-RTT prohibition be enforced by the endpoint's
  own construction, independent of whether the underlying engine implements 0-RTT. Concretely: the
  fork **MUST assert `max_early_data_size = 0`** on the server (MUST NOT offer the `early_data`
  extension permitting non-zero early data) and **MUST refuse early-data key spaces on both ends
  regardless of engine support** — not merely because today's engine happens to refuse `ZERO_RTT`
  (`keysAvailable(ZERO_RTT) → false`, `consumeHandshakeBytes(ZERO_RTT,…)` throws). A future
  DirtyChai rebase could wire `early_data` and silently reopen the path if the fork relied on the
  engine's current absence-of-support instead of its own explicit guard.
- **JGDMS send-path invariant.** Independent of the above, the fork must guarantee the JERI
  invocation envelope — user `Subject`s plus the STD-006 §7.2 ACC reducing-domain block — is
  **never** placed in a `ZERO_RTT` key space's packets, as a positive send-path assertion. STD-010
  §6.2 is the normative owner of this requirement; cross-reference it directly rather than
  re-deriving the rule locally.
- Strip / disable early-data and the 0-RTT session-ticket path on both client and server
  (`QuicSessionTicket.java`, `impl/QuicSessionTicketImpl.java`). Keeping the port's key-space type
  with **no `ZERO_RTT` value** remains good code hygiene (a caller can't even construct the
  argument) but note it is **not** itself the STD's required construction-time guard — the explicit
  `max_early_data_size = 0` assertion and the send-path invariant above are what STD-010 §6.2
  actually requires; the enum omission is a defense-in-depth nicety on top. (Non-0-RTT session
  resumption is optional — decide separately; default: leave out for the first cut.)

### 3.6 Module descriptor

- `core/.../module-info.java`: remove `requires tech.kwik.agent15;`. The module reads
  `jdk.internal.net.quic` via DirtyChai's **qualified export** (see §6) — no `requires` is needed for
  it. Keep the module name **`tech.kwik.core`** stable: DirtyChai's `module-info` names this module as
  the export target, so the two must agree.
- **Module-name coupling diagnostic (build-time/startup assertion).** Add a startup check — a
  `Module.canRead(...)` probe against `jdk.internal.net.quic` — that **fails loudly**, naming the
  exact required export line, if the read is not granted. Without this, a cross-repo module-name
  mismatch between this fork's `tech.kwik.core` and DirtyChai's `module-info` export target
  surfaces only as an opaque `IllegalAccessError` deep in the crypto or handshake-drive seam; the
  probe converts that into a clear, actionable diagnostic at startup. **Do not rename or split
  `tech.kwik.core`** without a paired change to DirtyChai's `module-info` — record the exact
  required export line as a normative cross-repo dependency:
  `exports jdk.internal.net.quic to java.net.http, tech.kwik.core;` (see §6).

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
| 0 | Fork builds on the DirtyChai JDK; agent15 removed; `QuicTlsPort` wired over `QuicTLSEngine`; NOTICE file added (crediting Peter Doornbosch, marking derivative — see §7.3); DirtyChai B1/B2/B3 landed (trunk `98bcc58115f`, §6.1); the mTLS-server pos/neg test (ADVICE item D) remains a **predecessor**, not a parallel task (see §6); week-1 crypto-seam spike (§7.1) landed clean 2026-07-19 (commit `994aea8a`). |
| 1 | INITIAL+HANDSHAKE handshake completes client↔server over loopback; engine does AEAD; `getSession().getPeerCertificates()` populated both ends. |
| 2 | ONE_RTT application data; streams carry payload end-to-end; `setOneRttContext` wired (§3.3). |
| **H** | **Adversarial-input hardening pass on the kept transport** (new — before Inc 3 mTLS; see §7.3a): fuzz harness + line-by-line audit sign-off of the nine kept transport packages; anti-amplification / Retry / stateless-reset re-verification (server/impl driver rewrite). |
| 3 | Server accept loop with **client-auth required** (`SSLParameters.setNeedClientAuth(true)`); SPIFFE/X.500 positive **and** negative (wrong/absent identity → rejected); server handshake-completion deadline in force (§3.3 DoS item); anti-amplification re-verified. |
| 4 | Interop against ≥1 other QUIC implementation (JDK HTTP/3 client and/or upstream kwik); Retry + Version-Negotiation paths (`restartHandshake`, §3.3). |

---

## 6. Runtime, dependency, and DirtyChai coupling

### 6.1 DirtyChai side — B1/B2/B3: DONE and verified (mTLS-server test still outstanding)

**History note (why this section is emphatic):** an earlier draft of this SOW asserted B1/B2/B3
were "all done" as a bare claim; a board review found that FALSE against the then-current trunk.
They have since been implemented and are now **verified against DirtyChai trunk `98bcc58115f`**
(commit *"QUIC-TLS Exposure for JGDMS & Kwik #228"*). The lesson stands: cite verified source
state, not a self-report.

Verified current state (trunk `98bcc58115f`):

- **B1 — DONE.** `SSLContextImpl.isUsableWithQuic()` (`:486`) now returns
  `trustManager instanceof X509ExtendedTrustManager`. JGDMS's `AuthManager` (wrapped on
  `SSLContext.init()` as an `X509ExtendedTrustManager`) passes the gate, so the engine can be built
  from a JGDMS `SSLContext`.
- **B2 — DONE.** `CertificateMessage` routes a custom (non-`X509TrustManagerImpl`)
  `X509ExtendedTrustManager` through the standard 3-arg dispatch via a new `QuicTLSEngineFacadeImpl`
  adapter — on both the server client-cert path (`checkClientTrusted`, `:1232`) and the client
  server-cert path (`checkServerTrusted`, `:1296`). The old `"QUIC only supports SunJSSE trust
  managers"` throw is retired.
- **B3 — DONE (fail-open closed).** The server-side client-cert transport dispatch now ends in
  `else { throw new AssertionError("Unexpected transport type"); }` (`:1236-1238`), symmetric with
  the client-side block. An unrecognized transport can no longer fall through to
  `setPeerCertificates` unvalidated — it fails closed.

**Remaining Inc-0 predecessor.** The *code* relaxations are done; commit #228 did **not** add a
functional test. The one outstanding predecessor is the **DirtyChai mTLS-server pos/neg test
(ADVICE item D)** — server mTLS is now code-complete but **unexercised**. **Owner:** a human
DirtyChai maintainer (DirtyChai is advise-only for AI; humans write it per its `CLAUDE.md` policy).
This is no longer a blocking-code gate for the fork's design work, but Inc 3 (server-mTLS SPIFFE
pos/neg) should not be called validated end-to-end until that DirtyChai test exists. It is a much
smaller residual than the original B1/B2/B3 critical path (see §7.2). Also still pending on the
DirtyChai side: the one-line qualified export (§6.3), which #228 did not add.

### 6.2 Architecture decision (ratified 2026-07-06) — direct `jdk.internal.net.quic` + `QuicTlsPort`, facade override acknowledged

Peter has **ratified** keeping the **direct** dependency on `jdk.internal.net.quic` plus the
in-fork `QuicTlsPort` (§3.1), **overriding** the "facade-for-production" recommendation in
`ADVICE-quic-tls-dirtychai-locations-2026-07-05.md` (item C) and its detailed design in
`ADVICE-quic-facade-interface-2026-07-05.md`. This is recorded here as an **acknowledged override**,
not a silent contradiction of the ADVICE series — the ADVICE documents remain correct analysis of
the facade option; this SOW documents why the team chose not to take it.

**Rationale:**
- **(a) Hand-maintenance cost falls on the hardest-to-change repo.** A facade would have to be
  human-written in the advise-only DirtyChai repo: ~21 methods (per the ADVICE §3 enumeration) + 2
  re-declared enums (`KeySpace`, `HandshakeState`) + 2 facade-level exception types + a
  transport-parameters consumer interface + a factory + tests — a large hand-maintained surface
  landing on the one repo where AI cannot help write it and humans are the bottleneck.
- **(b) A facade relocates the coupling, it does not remove it.** The internal-type dependency
  still exists on the far side of the facade (DirtyChai itself still names `QuicVersion`,
  `QuicTransportException`, etc.) — it moves the coupling from this fork to DirtyChai, it does not
  eliminate it from the system.
- **(c) Direct dependency is acceptable here specifically because of lockstep ownership.**
  Depending on `jdk.internal` types is normally the thing to avoid — but here DirtyChai is the
  **sole runtime** this fork targets, and the team owns **both ends** of the version pin (fork and
  runtime), so the two can be versioned in lockstep rather than needing an abstraction boundary
  against an externally-changing dependency.
- **(d) `QuicTlsPort` already gives fork-side isolation.** The §3.1 port gives this fork's own code
  isolation from `jdk.internal.net.quic` types (all re-pointed code talks to the port, not the raw
  engine) and mock-testability, which was the practical benefit a facade would have offered to this
  side of the boundary anyway.

**Honest caveat — the port CONFINES, it does not SEVER, the internal-type dependency.** The port's
own method signatures still name `jdk.internal.net.quic` types directly — `QuicVersion`,
`QuicTransportException`, etc. appear in `QuicTlsPort`'s own contract, not just inside its
implementation. So upgrade coupling to the JEP-517-fresh internal API (§7.3 standing risk) is a
**retained risk, mitigated by lockstep versioning — not neutralized** by the port. Accordingly:
the earlier framing of "equivalent isolation" (as if the port matched what a facade would give) and
"single-file swap" (as if converting to a future public API were a one-line change even with
internal types in the port's own signatures) are **overclaims** and are softened here: the port
gives real fork-side isolation and testability (point d above), but it is not a severance of the
internal-API dependency, and a future conversion to a public QUIC-TLS API will need to touch the
port's own signatures, not just its implementation.

**Concrete instance — the confinement is a build/toolchain constraint on testing, not just an
upgrade-coupling risk.** Confirmed 2026-07-19 during §3.1 implementation: stock OpenJDK 25.0.3 does
not merely fail to *export* `jdk.internal.net.quic` — the package does not exist there at all
(`javac`: "package jdk.internal.net.quic does not exist", a compile-time absence, not an
access-control denial). Because `QuicTlsPort`'s own signatures name real `jdk.internal.net.quic`
types (point (d) above), even a hand-written mock/stub implementation (`FakeQuicTlsPort`,
`core/src/test/java/tech/kwik/core/tls/`) cannot be *compiled* outside a JDK that ships that
package — DirtyChai, or a future OpenJDK on the same JEP-517-track lineage. The stub's *runtime*
behavior is DirtyChai-independent (it never constructs a real engine, exercises no DirtyChai-specific
logic); the *toolchain* is not — tests against the port need a JDK with `jdk.internal.net.quic`
present to compile at all, regardless of what they exercise at runtime.

### 6.3 Export line and SPI surface

- DirtyChai side, now that B1/B2/B3 have landed (§6.1): **one line** still pending in DirtyChai's
  `module-info.java` — add `tech.kwik.core` to `exports jdk.internal.net.quic to java.net.http;`. No driver facade is built
  (§6.2); the fork compiles against `jdk.internal.net.quic.QuicTLSEngine` directly and versions in
  lockstep with DirtyChai.
- **Every type on the engine's SPI signatures lives in `jdk.internal.net.quic`** (verified:
  `QuicVersion`, `QuicTransportException`, `QuicKeyUnavailableException`, `QuicOneRttContext`,
  `QuicTransportParametersConsumer`, `QuicTLSContext`), so the single qualified export covers the whole
  surface — no sibling-package exports needed.
- **Stock-JDK caveat:** even with the engine exported, a stock OpenJDK rejects custom (non-SunJSSE)
  trust managers at `isUsableWithQuic`; only DirtyChai's B1/B2/B3 admits JGDMS's SPIFFE `AuthManager`.
  Hence DirtyChai-only, like JGDMS.

### 6.4 Algorithm-constraint re-imposition (inherited dependency)

JGDMS re-imposes TLS algorithm constraints in its own trust evaluation — Peter's ratified decision
(`ADVICE-quic-tls-dirtychai-locations-2026-07-05.md` §6): the JSSE-layer 3-arg adapter path carries
algorithm constraints too (belt-and-braces), but JGDMS's own re-imposition is **not contingent** on
that adapter and remains required regardless. This fork **inherits** that dependency unchanged: the
same `AuthManager` is reused for QUIC as for the existing TCP/TLS transport, so record here that the
algorithm-constraint re-imposition must not be dropped when the trust path is re-driven through
QUIC — it is a JGDMS-side obligation this fork's server client-auth wiring (§3.3) relies on staying
in place.

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

**Scope correction — this "clean rewrite" finding covers the handshake-DRIVER callback seam only,
not the crypto seam.** The analysis above verifies the callback/message-dispatch seam is clean
(delete-dominant, not deeply entangled) — that finding stands. It does **not** extend to the
crypto/AEAD/key-lifecycle seam (§3.2), which is a genuine re-architecture: kwik's two-step
protect/unprotect model vs. the engine's fused `encryptPacket`/`decryptPacket` calls is an
impedance mismatch the driver-seam analysis doesn't touch, and the key-update ratchet relocation
(§3.2) is a distinct correctness-sensitive deletion. "No structural entanglement to fight" (below,
§7.2) describes the driver seam; the crypto seam carries its own, separate risk.

**Week-1 spike (Inc 0/1) — empirically confirmed 2026-07-19 (commit `994aea8a`, branch
`spike/quic-tls-crypto-seam-week1`).** Drove one INITIAL packet round trip through two real
`QuicTLSEngine` instances (client encrypt, server decrypt) — not just on paper — with negative-path
verification: a flipped ciphertext byte and a flipped header/AAD byte both correctly threw
`AEADBadTagException`. **Result: PASSED.**

Two findings came out of it. (1) Header protection is **not** fused into
`encryptPacket`/`decryptPacket` — `computeHeaderProtectionMask` is a separate, mandatory call on
both directions, for every packet, not an optional fallback for cases a fused call doesn't fit;
see the §3.2 correction above. This does not change the order of magnitude of the crypto-seam
estimate (§7.2/§7.2a) — it corrects the API description, not a new risk. (2) INITIAL keys are
available with zero handshake state: `deriveInitialKeys()` succeeded on a bare, freshly-constructed
engine with no `SSLParameters`, no `versionNegotiated`, no transport-params wiring —
`keysAvailable(INITIAL)` returned `true` immediately, no CRYPTO bytes exchanged. Confirms the
transport can start feeding the engine INITIAL-space crypto as soon as it has the peer's connection
ID, independent of and prior to any handshake-driver wiring (§3.3). Tested at one CID length (8
bytes) only — a promising, not fully exhaustive, data point.

Gate cleared: the crypto-seam rewrite (§3.2) proceeds as scoped.

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
(handshakes are iterative), or a config setter with no clean `SSLParameters` equivalent — plus the
crypto-seam re-architecture and key-update relocation (§3.2), which carry their own risk beyond the
driver seam's (see §7.1 scope correction). Estimate covers the transport fork only (excludes the
DirtyChai one-line export and the JGDMS `Endpoint`/`ServerEndpoint` SPI on top), and assumes QUIC/TLS
familiarity — add ramp time otherwise.

### 7.2a Estimate correction — 6–8 weeks is a happy-path FLOOR; honest estimate is 8–12 weeks

The table above is a **floor**, not the estimate to plan against. Correcting it: **8–12 weeks**,
driven by three items the 6–8-week table above under-weights or omits —

- the crypto-seam **re-architecture** (§3.2: fused-vs-split reconciliation across `QuicPacket` and
  both packet parsers, not the "delete and delegate" framing the floor estimate assumed),
- **key-update relocation** (§3.2 KEY-UPDATE item: deleting `KeyUpdateSupport` +
  `ShortHeaderPacket`'s key-phase logic and reconciling with the engine's ratchet) — **≈ +5 d** on
  top of the floor table's crypto-seam line,
- the **untrusted-transport hardening pass** (new increment, §7.3a) — **1–2 weeks**, not present in
  the 6–8-week table at all.

This 8–12-week estimate is **conditional on the week-1 crypto-seam spike (§7.1) landing clean** —
if the spike surfaces a harder reconciliation than expected, re-scope before committing further.

**Explicitly EXCLUDED from this estimate** (both were already out of scope for the 6–8-week floor,
restated here so the correction doesn't get read as absorbing them):
- the **human DirtyChai mTLS-server test (ADVICE item D)** (§6.1; B1/B2/B3 have landed) — a
  separate repo, on advise-only human effort this SOW does not control the pace of;
- the **JGDMS `Endpoint`/`ServerEndpoint` SPI + STD-010 conformance work layered on top** —
  server-initiated streams, DGC in-band ack, execution-subject swap.

**State plainly:** 6–8 weeks (the floor) or 8–12 weeks (the honest estimate) both yield an
**mTLS-authenticated QUIC byte pipe** — a **prerequisite**, not the JERI transport itself. The
`Endpoint`/`ServerEndpoint` SPI and STD-010 conformance work is a separate, subsequent effort.

### 7.3 Standing risks

- **Engine API instability:** `jdk.internal.net.quic` is JEP-517-fresh internal API. Mitigated by the
  §3.1 isolation port + DirtyChai lockstep; converts to the OpenJDK public API when published. Per
  §6.2, the port confines but does not sever this dependency — the port's own signatures still name
  internal types, so a future conversion touches the port's contract too, not just its
  implementation. This reaches test compilation as well, not only production builds — see §6.2's
  stock-OpenJDK-25.0.3 finding.
- **Upstream drift / merge conflicts.** The untouched transport packages merge cleanly from
  `upstream`. However, the **~15 agent15-touching seam files are expected to CONFLICT** on upstream
  merge and need manual reconciliation — only the transport core merges cleanly, not the TLS seam.
  Consider isolating the rewritten seam into as few files as possible (the §3.1 port already helps
  by concentrating the re-pointed code behind one interface) to shrink the conflict surface. Merge
  upstream transport/security fixes periodically (standing §7.3a task, below).
- **License:** LGPLv3 obligations travel with the fork; keep it out of GPLv2 `java.base` (it lives in
  JGDMS userspace).
- **NOTICE file — Inc-0 deliverable.** The header promises a NOTICE file crediting Peter Doornbosch
  and marking this a derivative work; it is not yet present. Treat it as an explicit **Inc-0**
  deliverable, not an implied housekeeping task to get to eventually.

### 7.3a Adversarial-input hardening pass on the kept transport (new increment, before Inc 3 mTLS)

The transport packages kept "as-is" (§2) are untouched by the TLS re-pointing, but they are not
therefore validated against an adversarial/untrusted peer — that is a distinct question this SOW
had not previously scoped. Add an explicit increment, scheduled **before Inc 3's client-auth work**
(see §5 Inc **H**):

- **(a) Structured fuzz harness** over `PacketParser.parseAndProcessPackets` and
  `QuicPacket.parseFrames`, run on the DirtyChai JDK: malformed frames, oversized varints,
  overlapping/duplicate stream frames, adversarial ACK ranges, spoofed CID frames. Highest-value
  target: `ReceiveBufferImpl`'s overlap arithmetic (`shrinkFrame`/`combine`).
- **(b) Written line-by-line audit sign-off** of the nine kept packages (`ack`, `cc`, `cid`,
  `frame`, `packet`, `recovery`, `send`, `receive`, `stream`) against a threat model, filed in the
  style of STD-010's `AUDIT-1..N` list.
- **(c) Standing task:** merge upstream security fixes into the kept transport packages on an
  ongoing basis (folds into the merge-drift mitigation above).

**This is a required AUDIT/proof, not a rewrite.** The parsers were spot-verified to fail closed
with real DoS defenses already in place — flow control, stream-count limits, a reassembly
memory-amplification bound, and bounded CIDs — so the hardening pass's job is to prove that
holds under adversarial input and document it, not to redesign the transport. **Budget 1–2 weeks**
(additive to the 6–8-week floor; already folded into the 8–12-week corrected estimate, §7.2a).

### 7.3b Anti-amplification re-verification (§3.3 / Inc 4 checkpoint)

The 3× anti-amplification limit, Retry/address-validation, and stateless-reset paths live in
`server/impl`, which **imports agent15 and is re-pointed** by this SOW's driver-seam work (§3.3) —
they are **not** covered by the "transport kept as-is" reassurance (§2), because `server/impl` is
explicitly part of the re-pointed set, not the kept set. Re-verify all three paths after the
server-package driver rewrite lands, and add a **spoofed-source-address amplification test** as
part of that re-verification. Make this an explicit checkpoint gating Inc 4 (interop/Retry/
Version-Negotiation), not an assumption carried over from the kept-transport list.

---

## 8. References

- **JGDMS:** `JGDMS-STD-010-QUIC-JERI-Transport-v0.1-DRAFT.md` (transport standard),
  `SOW-QUIC-JERI-Transport.md`, `ADVICE-quic-tls-exposure-2026-06-30.md`,
  `ADVICE-quic-tls-dirtychai-locations-2026-07-05.md`, `ADVICE-quic-facade-interface-2026-07-05.md`,
  `SOW-DirtyChai-QUIC-TLS-Investigation.md`.
- **Standards:** RFC 9000 (QUIC), RFC 9001 (TLS for QUIC), RFC 9002 (loss/congestion),
  RFC 8446 (TLS 1.3), JEP 517.
