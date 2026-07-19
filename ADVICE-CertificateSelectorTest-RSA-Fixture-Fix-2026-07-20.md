# ADVICE: Regenerate weak RSA test fixtures in `TestCertificates.java`

Status: **IMPLEMENTED.** Implemented on branch `fix/certselector-rsa-2048-fixtures`
(commit `b398c148`, in an isolated `git worktree` sibling of this repo checkout — this
document itself was amended in a follow-up commit on the same branch). A 3-reviewer board
approved this document's core approach ahead of implementation and found four corrections,
folded into the sections below (§4's script, §5's reasoning, §4's verification note, and
§7 open question 6) — see the "Board corrections" callouts inline.

## 1. Background (established, not re-derived here)

A prior investigation confirmed: `CertificateSelectorTest`
(`core/src/test/java/tech/kwik/core/client/CertificateSelectorTest.java`) has 2 of its 6 tests
fail under a real DirtyChai (custom OpenJDK 27 fork) JDK:

- `whenCertIssuerDnMatchesCertShouldBeSelected`
- `endEntitySignedBySubcaWithCaMatchingShouldBeSelected`

Root cause: DirtyChai enforces `jdk.certpath.disabledAlgorithms` (`RSA keySize < 1024`) on the
JDK's *default* `SunX509` `KeyManager` — a DirtyChai-specific hardening
(`sun.security.ssl.X509KeyManagerCertChecking`) that is out of scope for kwik and not to be
touched here. The test fixtures in
`core/src/test/java/tech/kwik/core/test/TestCertificates.java` use 512-bit RSA keys, so they get
silently filtered out of `chooseEngineClientAlias()` alias selection under DirtyChai. Stock
JDK 21/25 both pass; forcing `KeyManagerFactory.getInstance("NewSunX509")` reproduces the
identical failure on all three JDKs, proving this is enforcement logic newly promoted to the
*default* algorithm, not new logic.

This document scopes the fix: regenerate the weak fixtures at an adequate key size.

## 2. Exactly what needs to change

### 2.1 How the fixtures are stored

`TestCertificates.java` has **no external cert/key files and no runtime generation helper**.
Every cert and key is a hardcoded `private static String` field holding a base64-encoded DER
blob (X.509 cert, or PKCS#8-encoded private key), decoded on demand by two tiny helpers
(`inflateCertificate`, `inflatePrivateKey`). Each field's origin is documented in a one-line
`// generated with: openssl ...` comment immediately above it — these are comments only, not
checked-in scripts; nothing in the repo actually runs them.

### 2.2 Full inventory of the CA hierarchy (7 keypairs, 3 independent trees)

| # | Const field(s) | Subject (`-subj`) | Signed by | Key alg/size | Public getter? | Loaded into a test `KeyStore`? |
|---|---|---|---|---|---|---|
| 1 | `encodedCA1Cert` / `encodedCA1PrivateKey` | `/CN=SampleCA1` | self-signed (root) | RSA-512 | **none** | No — never loaded, only used offline to sign #4 and #6 |
| 2 | `encodedCA2Cert` / `encodedCA2PrivateKey` | `/CN=SampleCA2` | self-signed (root) | RSA-512 | **none** | No — never loaded, only used offline to sign #5 |
| 3 | `encodedsubCA1Cert` / `encodedSubCa1PrivateKey` | `/CN=SubCA` | CA1 | RSA-512 | cert: `getSubCACertificate1()`; key: **none** | **Yes** (test `endEntitySignedBySubcaWithCaMatchingShouldBeSelected`) |
| 4 | `encodedEndEntityCertificate1` / `...PrivateKey` | `/CN=endentity1` | CA1 | RSA-512 | `getEndEntityCertificate1()` / `Key()` | **Yes** (tests `whenCertIssuerDnMatchesCertShouldBeSelected`, `whenNoCertificateMatchesFallbackIsUsed`) |
| 5 | `encodedEndEntityCertificate2` / `...PrivateKey` | `/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2` | CA2 | RSA-512 | `getEndEntityCertificate2()` / `Key()` | **Yes** (tests `whenCertIssuerDnMatchesCertShouldBeSelected`, `whenNoCertIssuerDnMatchesNoCertShouldBeSelected`) |
| 6 | `encodedEndEntityCertificate1_1` / `...PrivateKey` | `/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity1_1` | SubCA (#3) | RSA-512 | `getEndEntityCertificate1_1()` / `Key()` | **Yes** (tests `endEntitySignedBySubcaWithCaMatchingShouldBeSelected`, `endEntitySignedByUnknownSubcaShouldNotBeSelected`) |
| 7 | `encodedEcEndEntityCertificate` / `...PrivateKey` | `/CN=SampleECRoot` | self-signed (root) | **EC secp256r1** | `getEcCErt()` / `getEcCertKey()` | Yes (test `worksWithEcToo`) — **already passes, do not touch** |

Verified with `openssl x509 -text` against the actual decoded `encodedCA1Cert` bytes: RSA
modulus is 512 bit and the signature algorithm is already `sha256WithRSAEncryption` — so there
is **no secondary weak-signature-algorithm problem** to fix alongside the key size; SHA-1 is not
in play anywhere in this hierarchy. (Spot-checked one cert; all were generated in the same
May-2024 batch with the same tool defaults per the comments, so this is treated as representative
of the whole set, not independently re-verified per cert.)

### 2.3 What's actually load-bearing for the two failing tests

Only certs that get loaded into a `KeyStore` and passed to `KeyManagerFactory` are subject to
DirtyChai's `X509KeyManagerCertChecking` filter. Cross-referencing the table above against
`CertificateSelector.selectCertificate()` (`core/src/main/java/tech/kwik/core/client/CertificateSelector.java`,
which does nothing more than delegate to `X509ExtendedKeyManager.chooseEngineClientAlias()`):

- **Load-bearing (must become ≥1024-bit, i.e. get bumped to 2048-bit RSA):** #3 SubCA, #4 EE1,
  #5 EE2, #6 EE1_1 — these are the four cert/key pairs actually placed in a `KeyStore` by
  `CertificateSelectorTest`, and #4+#5 are exactly what test 1 fails on, #3+#6 exactly what the
  other failing test fails on.
- **Not load-bearing but structurally required:** #1 CA1 and #2 CA2 root keys are never loaded
  into any JVM `KeyStore` in this test (no getter even exists for them), so they are inert with
  respect to DirtyChai's filter. However their *private keys* are the offline signers for #3/#4
  (CA1) and #5 (CA2) — you cannot produce new, validly-signed 2048-bit end-entity/sub-CA certs
  without also generating new CA1/CA2 keypairs to sign them with. Recommendation: regenerate all
  7... no, all **6 RSA** pairs together (leave EC, #7, untouched) as one consistent hierarchy,
  even though the CA1/CA2 root cert+key *constants* stored in the file are dead code from the
  Java call graph's point of view. Reasoning: leaving stale 512-bit root material sitting in the
  file, inert or not, is exactly the kind of thing that gets copy-pasted into a real fixture
  later; regenerating it costs nothing extra since the CA keys must be generated anyway to act as
  signers.

### 2.4 Files to touch

**Exactly one file**: `core/src/test/java/tech/kwik/core/test/TestCertificates.java`. Ten
`private static String` constants change (CA1 cert+key, CA2 cert+key, SubCA1 cert+key, EE1
cert+key, EE2 cert+key, EE1_1 cert+key), plus their doc comments update to reflect the new key
size in the `openssl genrsa ... 512` → `... 2048` comment. Nothing else needs to change — no new
getters are required to fix the two failing tests (`getSubCACertificate1Key()` doesn't exist
today and isn't needed today either; see open question 4).

`CertificateSelectorTest.java` itself does **not** need any code changes — it references
fixtures purely through `TestCertificates`'s existing getters, all of which keep their exact
signatures.

## 3. Exact-value dependency check

Read `CertificateSelectorTest.java` in full (all 6 test methods, `core/src/test/java/tech/kwik/core/client/CertificateSelectorTest.java`).
Findings:

- **No test asserts on exact serial number, fingerprint/hash, or raw PEM/DER byte content.**
- **One `equals()` check exists** (`endEntitySignedBySubcaWithCaMatchingShouldBeSelected`, line
  102: `assertThat(certificateWithKey.getCertificate()).isEqualTo(TestCertificates.getEndEntityCertificate1_1())`)
  but it's self-referential — both sides come from the same live `TestCertificates` call, not a
  hardcoded expected value — so it is immune to regeneration by construction.
- **No test asserts on validity dates.** Current certs run `-days 3650` from ~2024-05-20/21,
  expiring 2034-05-18/19/21 — comfortably valid, not close to expiring, and nothing checks
  `notBefore`/`notAfter`. This is *not* a live bug. Since the file is being touched anyway,
  regenerating with a fresh `-days 3650` window from the new generation date costs nothing and
  is worth doing as hygiene, but it is not required to fix the reported failures — flagging per
  the task brief's request to check for this category of issue, not because it's broken.
- **What DOES matter and must be preserved exactly:** the Distinguished Name strings. Tests do
  literal `X500Principal` comparisons — e.g. `new X500Principal("CN=SampleCA1")` compared against
  `endEntityCertificate.getIssuerX500Principal()`, and `assertThat(issuer1).isNotEqualTo(issuer2)`
  comparing CA1-derived vs CA2-derived issuers. `X500Principal` equality is structural
  (RFC 2253 canonical form) but **is** case-sensitive on attribute values. Every `-subj` string
  in section 2.2's table must be reproduced byte-for-byte on regeneration:
  `/CN=SampleCA1`, `/CN=SampleCA2`, `/CN=SubCA`, `/CN=endentity1`,
  `/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2`, `/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity1_1`. Get any
  of these wrong (case, spacing, RDN order/attributes) and a currently-passing test breaks
  silently. This is the single highest-risk step in the whole change and should be checked by
  decoding each new cert with `openssl x509 -text` (or `keytool -printcert`) and diffing the
  Subject/Issuer lines against this table before pasting the new base64 into the Java source.
- **Chain shape must be preserved**: CA1 self-signed root signs both EE1 (directly) and SubCA
  (which then signs EE1_1) — a 2-level chain for the `endEntitySignedBySubcaWithCaMatchingShouldBeSelected`
  /`endEntitySignedByUnknownSubcaShouldNotBeSelected` tests; CA2 self-signed root signs EE2
  directly — a 1-level chain. Get the CA used to sign each CSR wrong and the issuer chain breaks.

## 4. Concrete regeneration plan

**Mechanism: `openssl` CLI**, already present in this environment (`/usr/bin/openssl`,
OpenSSL 3.0.13) and `keytool` also available as a fallback. Recommending `openssl` over `keytool`
or a hand-rolled `sun.security.x509`/Java generator because:
- It's a drop-in continuation of the exact recipe already documented in every `// generated
  with:` comment in the file today — no new tooling convention introduced, comments stay literally
  true.
- `openssl x509 -req -CA ... -CAkey ...` cleanly expresses "sign this CSR with this specific CA
  key," which is the operation needed three times here (CA1→EE1, CA1→SubCA, CA2→EE2,
  SubCA→EE1_1); `keytool -gencert` can do this too but is clunkier for a 3-tier hierarchy.
- A one-off Java generator using `sun.security.x509` internals would touch exactly the kind of
  brittle internal API surface this project has been actively steering away from elsewhere
  (see memory: DirtyChai's own `X509KeyManagerCertChecking` work), for a throwaway artifact-
  generation script that doesn't need to be committed at all.

**Target**: RSA-2048 (replacing every `openssl genrsa ... 512`), signature algorithm unchanged
(already SHA-256, confirmed in §2.2). EC cert/key (#7) is untouched — already 256-bit EC, already
green.

**Commands** (run once, offline, in a scratch directory — not committed):

```sh
# Root CA1 (self-signed) — signs EE1 and SubCA1
openssl genrsa -out ca1.key 2048
openssl req -x509 -new -nodes -key ca1.key -out ca1-cert.pem -subj='/CN=SampleCA1' -days 3650

# Root CA2 (self-signed) — signs EE2
openssl genrsa -out ca2.key 2048
openssl req -x509 -new -nodes -key ca2.key -out ca2-cert.pem -subj='/CN=SampleCA2' -days 3650

# End-entity 1, signed by CA1
openssl genrsa -out ee1.key 2048
openssl req -key ee1.key -new -out ee1-cert.csr -subj='/CN=endentity1'
openssl x509 -req -in ee1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out ee1-cert.pem -days 3650 -CAcreateserial

# Sub-CA, signed by CA1 (reuse the serial file from CA1's -CAcreateserial step above so
# serials don't collide -- BOARD CORRECTION: -CAcreateserial names the serial file after the
# -CA argument's *basename*, i.e. "ca1-cert.srl" for -CA ca1-cert.pem, NOT "ca1.srl" as the
# original draft of this doc said (that filename is never produced by any prior step and
# -CAserial ca1.srl would fail with "unable to load 'ca1.srl'"). Verified by running the
# actual commands: the EE1 step above produces ca1-cert.srl, and that is the file to pass here.
openssl genrsa -out subca1.key 2048
openssl req -key subca1.key -new -out subca1-cert.csr -subj='/CN=SubCA'
openssl x509 -req -in subca1-cert.csr -CAkey ca1.key -CA ca1-cert.pem -out subca1-cert.pem -days 3650 -CAserial ca1-cert.srl

# End-entity 2, signed by CA2
openssl genrsa -out ee2.key 2048
openssl req -key ee2.key -new -out ee2-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity2'
openssl x509 -req -in ee2-cert.csr -CAkey ca2.key -CA ca2-cert.pem -out ee2-cert.pem -days 3650 -CAcreateserial

# End-entity 1_1, signed by SubCA
openssl genrsa -out ee1_1.key 2048
openssl req -key ee1_1.key -new -out ee1_1-cert.csr -subj='/C=NL/O=Kwik/OU=Kwik Dev/CN=endentity1_1'
openssl x509 -req -in ee1_1-cert.csr -CAkey subca1.key -CA subca1-cert.pem -out ee1_1-cert.pem -days 3650 -CAcreateserial
```

Then, per cert/key, convert to the same base64-DER form already used in the file and paste over
the matching constant, updating its doc comment's key size (512 → 2048):

```sh
# cert -> base64 DER, no PEM headers
openssl x509 -in ee1-cert.pem -outform der | base64 -w0

# private key -> PKCS8 DER -> base64 (matches inflatePrivateKey's PKCS8EncodedKeySpec expectation)
openssl pkcs8 -topk8 -inform PEM -in ee1.key -outform DER -nocrypt | base64 -w0
```

Re-wrap the base64 output to match the file's existing Java string-literal wrapping style for a
clean diff (cosmetic, not required for correctness). **Correction on implementation**: the
file's actual existing wrap width, measured directly off the pre-change constants, is 64
base64 characters per quoted line (not ~68 as originally estimated here) — the implementation
wraps at 64 to match exactly.

**Verification before considering the change done** (this belongs in the implementation step,
not this scope doc, but recording it here so the plan is concrete): after editing, decode every
new constant back out (`openssl x509 -text` / `openssl rsa -text`) and confirm (a) key size 2048,
(b) each Subject/Issuer DN matches §3's list exactly, (c) chain-of-trust verifies
(`openssl verify -CAfile ca1-cert.pem ee1-cert.pem` etc.), *then* run
`CertificateSelectorTest` under both a stock JDK and DirtyChai and confirm all 6 pass on both.

**BOARD CORRECTION — expected verification failure, do not chase it**: step (c) above verifies
cleanly for CA1→EE1 and CA2→EE2 (both single-hop, root-signs-leaf directly). It does **not**
verify cleanly for the SubCA→EE1_1 hop: `openssl verify -CAfile <ca1+subca1 chain> ee1_1-cert.pem`
fails with `error 79 at 1 depth lookup: invalid CA certificate`, because the SubCA certificate
(item #3 in §2.2) carries no `Basic Constraints CA:TRUE` extension, so OpenSSL's PKIX path
validator refuses to treat it as a valid intermediate CA. This is **pre-existing, not introduced
by this regeneration** — the 512-bit SubCA cert being replaced already lacked that extension
(confirmed by inspecting it before regenerating), and adding it now would be unrequested scope
expansion beyond a key-size bump, so it was deliberately left as-is. It is also functionally
harmless for the actual fix: DirtyChai's `X509KeyManagerCertChecking` does per-certificate
algorithm-constraint checking (the thing this whole fix is about), not full PKIX chain-path
validation, so `CertificateSelectorTest` is unaffected by this gap — confirmed by all 6 tests
passing. Treat this one `openssl verify` failure on this one hop as expected; verify the other
two chains (CA1→EE1, CA2→EE2) cleanly instead.

## 5. Blast radius

Repo-wide grep for `TestCertificates` (not limited to `core`, not limited to the two known test
files) turns up exactly two hits:

- `core/src/test/java/tech/kwik/core/client/CertificateSelectorTest.java` (the consumer)
- `core/src/test/java/tech/kwik/core/test/TestCertificates.java` (the fixture file itself)

`KeyStoreBuilder.java` (`core/src/test/java/tech/kwik/core/client/KeyStoreBuilder.java`), the
other class `CertificateSelectorTest` uses, is a generic in-memory `KeyStore` assembler — it
takes certs/keys as parameters and holds no fixture data of its own, so it needs no changes and
carries no risk. No other file in `core/src/test` or elsewhere in the reactor references any of
`TestCertificates`'s constants or getters. **Blast radius is confirmed to be exactly the 6 test
methods in `CertificateSelectorTest.java`, all of which are self-contained (in-memory `KeyStore`
built fresh per test, no shared static state, no external files) — regenerating the fixtures
cannot silently break anything currently passing outside this one file.**

**BOARD CORRECTION (reasoning, not conclusion)**: the paragraph above is right that nothing
*currently* consumes `TestCertificates` outside `CertificateSelectorTest`, but it understates
how it's reachable. `qlog/build.gradle` has
`testImplementation(project(':kwik').sourceSets.test.output)`, which puts the whole `core`
test-source output — including `TestCertificates` — on `qlog`'s test classpath. So the correct
statement is not "no path exists from `qlog` to `TestCertificates`" (structurally isolated); it's
"a path exists, but was checked and confirmed to have no consumer" — a grep across
`qlog/src/test` for `TestCertificates` (and for any other reference to `tech.kwik.core.test` or
`tech.kwik.core.client.CertificateSelector*`) turns up nothing. The conclusion (safe to
regenerate, blast radius contained to `CertificateSelectorTest.java`) is unchanged; only the
justification is corrected here, since "no path exists" and "path exists but is unused" are
different claims and the latter is what's actually true, and is what was re-verified before
implementing.

Worth noting for completeness (not a reason to change scope): tests
`whenNoCertIssuerDnMatchesNoCertShouldBeSelected`, `endEntitySignedByUnknownSubcaShouldNotBeSelected`,
and `whenNoCertificateMatchesFallbackIsUsed` currently pass on DirtyChai even though they load
512-bit RSA certs, apparently because they assert on a "not selected" / null outcome that's
satisfied whether the filtering fires or not (established behavior, not re-derived here). This
"weak assertion masks the underlying filtering" pattern is a separate, pre-existing test-design
property unrelated to fixture strength — see open question 5.

## 6. Effort / risk estimate

**Effort: small.** Roughly 1–2 hours of careful, mostly mechanical work: run ~15 openssl
invocations, base64-encode 12 artifacts (6 certs + 6 keys), hand-edit 10 constants (20 including
the 2 that already have no getter but still need updating) plus their comments in one file,
re-verify.

**Risk: low-but-not-zero, concentrated entirely in transcription accuracy, not in design.**

- Primary risk is manual base64/DN transcription error (wrong subject string, mismatched
  cert/key pair, wrong signer) — mitigated by the verification pass in §4, which should be done
  before trusting the edit, not "run the test suite and see."
- Secondary risk: touching the EC fixture (#7) by reflex during a file-wide sweep. It's already
  correct (EC-256, already green) and explicitly out of scope — worth a reviewer diff-check that
  `encodedEcEndEntityCertificate`/`encodedEcEndEntityCertificatePrivateKey` are byte-identical
  before and after.
- No architectural risk: this is pure test-fixture data, no production code path touched, no
  API surface changed, no other module affected (§5).

## 7. Open questions for the reviewer

1. **Scope of "which constants get regenerated."** I'm recommending all 6 RSA pairs (including
   CA1/CA2 root cert+key and the SubCA1 private key, none of which have a public getter and are
   never loaded into a JVM `KeyStore` — see §2.3) be regenerated together as one consistent
   hierarchy, on the grounds that CA1/CA2's private keys are structurally required as offline
   signers anyway and leaving stale 512-bit root material inert-but-present in the file is bad
   hygiene. Confirm this is the desired scope versus only touching the 4 strictly load-bearing
   pairs (EE1, EE2, SubCA1, EE1_1) and leaving CA1/CA2 physically stale in source.
2. **Key size: confirm 2048-bit RSA** is the intended target (not 3072/4096). 2048 clears
   DirtyChai's `RSA keySize < 1024` floor with large margin and is the "modern sane default" the
   task brief named; I see no reason these test-only fixtures need more.
3. **Tooling: confirm `openssl` CLI is acceptable** (matches the file's existing documented
   recipe verbatim) versus wanting a committed, re-runnable generator script so this doesn't
   bit-rot again the next time a disabled-algorithms floor moves. I lean towards *not* committing
   a generator — keeps the fixture file self-contained per its existing comment-only convention —
   but this is a real design choice, not a foregone one.
4. **Resist scope creep**: no new getter (e.g. `getSubCACertificate1Key()`) is needed to fix the
   two failing tests, and none is proposed. Confirm the implementer shouldn't add one "while
   they're in there."
5. **Validity window**: not a bug (no test depends on it, current certs are good until 2034), but
   since the file is being touched anyway, I'm proposing to just re-run with a fresh `-days 3650`
   window as free hygiene. Confirm that's welcome and not undesired scope-widening for what's
   meant to be a minimal, targeted fix.
6. **Not this task's problem, flagging only for triage**: three of the six tests in
   `CertificateSelectorTest` pass today on DirtyChai for reasons that look like assertion
   weakness rather than genuine correctness (§5) — worth a separate follow-up ticket to tighten
   those assertions so they'd actually catch a regression, but explicitly out of scope for this
   fix.

   **BOARD CORRECTION (factual, not scope)**: only 2 of the 3 pass for the "weak assertion"
   reason described above — `whenNoCertIssuerDnMatchesNoCertShouldBeSelected` and
   `endEntitySignedByUnknownSubcaShouldNotBeSelected`, both of which assert a null/no-match
   outcome that's satisfied whether or not DirtyChai's filtering actually fires. The third,
   `whenNoCertificateMatchesFallbackIsUsed`, passes for a *different* reason: its fallback path
   calls `keyManager.getClientAliases("RSA", null)`, a genuinely different
   `X509ExtendedKeyManager` method from `chooseEngineClientAlias()` (the one
   `X509KeyManagerCertChecking` patches) — DirtyChai's hardening simply doesn't touch that method,
   so this test isn't a weak-assertion case at all, it exercises an unpatched code path. Doesn't
   change the recommendation (still a candidate for a follow-up ticket, still out of scope here),
   just corrects which 2 of the 3 are "weak assertion" versus which 1 is "different method
   entirely."

## 8. Implementation record

Implemented on `fix/certselector-rsa-2048-fixtures`, commit `b398c148` (fixture regeneration),
in an isolated `git worktree` off `master` at `ba9615c5`. Followed §4's plan with the `-CAserial
ca1-cert.srl` fix from board finding #2, and left the extension-less SubCA cert as-is per board
finding #3. All 6 RSA keypairs regenerated (CA1, CA2, SubCA1, EE1, EE2, EE1_1); EC fixture
(`encodedEcEndEntityCertificate`/`encodedEcEndEntityCertificatePrivateKey`) confirmed
byte-identical before/after via `git diff`.

Verification performed:
- Decoded all 12 new base64-DER constants directly out of the edited Java source (not just the
  scratch `openssl` output) and confirmed 2048-bit RSA and exact Subject/Issuer DN match against
  §2.2/§3 for every cert; confirmed each key's RSA modulus matches its paired cert's modulus.
- `openssl verify` clean for CA1→EE1 and CA2→EE2; SubCA→EE1_1 fails with the expected, pre-existing
  `error 79` (see §4 board-correction note above) — reproduced against the pasted constants, not
  just the scratch files.
- `./gradlew --offline --no-daemon :kwik:test --tests "tech.kwik.core.client.CertificateSelectorTest"`
  under the DirtyChai JDK 27 toolchain: **6/6 tests pass**, including both previously-failing
  tests (`whenCertIssuerDnMatchesCertShouldBeSelected`,
  `endEntitySignedBySubcaWithCaMatchingShouldBeSelected`) and all 4 that were already passing.
- Same test class recompiled from source (classpath mode, `--release 21`, module-info excluded
  since gradle's build pins a JDK-27-only toolchain that stock JDKs can't satisfy) and run via
  the JUnit Platform Launcher API under both stock OpenJDK 21 and stock OpenJDK 25: **6/6 pass on
  both**, confirming no regression on non-DirtyChai JDKs.
- Broader `./gradlew --offline --no-daemon :kwik:test` (whole `core` module, 990 tests): 989
  pass, 1 skip (`ServerConnectorImplTest.afterCloseNoAdditionalThreadsShouldBePresent`,
  pre-existing and unrelated to this change), 0 failures.

This document was amended to IMPLEMENTED status, with the board corrections folded in, in a
follow-up commit on the same branch.
