/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.packet;

import jdk.internal.net.quic.QuicTLSEngine.KeySpace;
import jdk.internal.net.quic.QuicVersion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.StreamFrame;
import tech.kwik.core.impl.DecryptionException;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.test.TestCertificates;
import tech.kwik.core.tls.QuicTlsPort;
import tech.kwik.core.tls.QuicTlsPortImpl;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static tech.kwik.core.packet.HandshakeShortHeaderPacketRealEngineRoundTripTest.configureMinimal;
import static tech.kwik.core.packet.HandshakeShortHeaderPacketRealEngineRoundTripTest.pump;
import static tech.kwik.core.packet.HandshakeShortHeaderPacketRealEngineRoundTripTest.trustAllClientSide;

/**
 * Drives a REAL, engine-initiated ONE_RTT key-phase rollover through two real DirtyChai
 * {@code QuicTLSEngine}s and proves kwik's port-based {@link ShortHeaderPacket} path handles it
 * transparently -- closing the gap {@link KeyUpdateRatchetRemovalRealEngineRoundTripTest}'s class
 * javadoc used to declare impractical ("forcing the engine past its internal packet-count threshold"
 * would need ~80% of the AES-GCM confidentiality limit, i.e. ~6.7M packets).
 *
 * <p><b>How the rollover is made practical:</b> the DirtyChai JDK reads the
 * {@code jdk.quic.tls.keyLimits} security property ONCE, in {@code sun.security.ssl.QuicCipher}'s
 * static initializer (format {@code "AES/GCM/NoPadding <n>"}, lower-only clamp against the RFC 9001
 * §6.6 default of 2^23). This class's own static initializer sets it to {@value #LOWERED_LIMIT}
 * before any QUIC cipher class can possibly have loaded in this JVM, so the engine's autonomous
 * update trigger ({@code QuicKeyManager.maybeInitiateKeyUpdate}: initiate at
 * {@code numEncrypted >= 0.8 * confidentialityLimit}, gated by both endpoints having used the
 * current keys) fires after ~{@code 0.8 * } {@value #LOWERED_LIMIT} short-header packets instead of
 * millions.
 *
 * <p><b>JVM isolation (why this class runs in its own forked JVM):</b> because the property is
 * consumed once per JVM in a static initializer, this test is meaningless in a JVM where any other
 * test already touched QUIC ciphers (the lowered limit would silently not apply), and conversely it
 * would poison every OTHER real-engine test in a shared JVM (they would hit unexpected early
 * rollovers). It therefore runs ONLY in the dedicated Gradle {@code keyLimitsRolloverTest} task
 * (see {@code core/build.gradle}), which forks its own JVM containing exactly this class; the
 * regular {@code test} task explicitly excludes it. Gradle {@code Test} tasks always fork a
 * separate test JVM, so a dedicated task running only this class IS a dedicated JVM -- no
 * {@code forkEvery} games needed.
 *
 * <p><b>Fail-loudly guarantee:</b> if the property did NOT take effect (e.g. someone runs this class
 * in a shared/contaminated JVM after all), the tests here FAIL, they do not silently pass or skip:
 * <ul>
 *   <li>{@link #assertLoweredLimitTookEffect()} reads the effective AES-GCM confidentiality limit
 *       reflectively (the dedicated task passes {@code --add-opens java.base/sun.security.ssl=ALL-UNNAMED})
 *       and fails with a diagnosis if it isn't {@value #LOWERED_LIMIT}. If the reflective probe
 *       itself is unavailable, that alone does not fail anything -- because:</li>
 *   <li>behaviorally, each test fails anyway if no key-phase flip is observed within
 *       {@value #MAX_PACKETS} packets -- an actually-observed rollover at low volume is itself the
 *       proof the lowered limit was in effect (the untouched default would need ~6.7M packets).</li>
 * </ul>
 *
 * <p><b>What this proves:</b> (1) the initiating (client) engine really flips its key phase, observed
 * via the key-phase value the engine supplies to the {@code IntFunction} header generator inside
 * {@code encryptPacket} (surfaced as {@link ShortHeaderPacket#keyPhaseBit}); (2) the peer engine
 * transparently accepts post-rollover packets (its internal speculative next-key decrypt) and rolls
 * its own send keys -- bidirectional round-trip payload equality after the flip, with zero kwik-side
 * key-phase state anywhere; (3) a pre-rollover (old-phase) packet delivered late, after the flip,
 * still decrypts via the engine's one-generation-old key retention ({@code KeySeries.old} /
 * {@code canUseOldDecryptKey}, packet-number-ordering gated per RFC 9001 §6.5); (4) negative
 * control: a tampered post-rollover packet is still rejected, the new-phase keys don't weaken AEAD
 * integrity handling.
 *
 * <p>Reuses {@link HandshakeShortHeaderPacketRealEngineRoundTripTest}'s two-real-engine handshake
 * pump (including its {@code tryMarkHandshakeDone}/{@code tryReceiveHandshakeDone} bookkeeping and
 * mandatory {@code QuicOneRttContext}), with one addition: the cipher suite is pinned to
 * {@code TLS_AES_128_GCM_SHA256} so the lowered "AES/GCM/NoPadding" limit is guaranteed to be the
 * one governing the negotiated suite.
 */
class KeyLimitsRealRolloverRoundTripTest {

    /**
     * Lowered AES-GCM confidentiality limit. The engine self-initiates a key update at 80% of this
     * (i.e. at 52 encrypted packets), provided the peer has also used the current keys.
     */
    private static final int LOWERED_LIMIT = 64;

    /** Hard cap on pumped packets before declaring the lowered limit ineffective and failing. */
    private static final int MAX_PACKETS = 200;

    static {
        // Must happen before sun.security.ssl.QuicCipher's static initializer runs anywhere in this
        // JVM -- which is guaranteed here ONLY because the dedicated Gradle task runs this class,
        // and nothing else, in a fresh forked JVM. See class javadoc.
        Security.setProperty("jdk.quic.tls.keyLimits", "AES/GCM/NoPadding " + LOWERED_LIMIT);
    }

    private QuicTlsPort client;
    private QuicTlsPort server;

    @BeforeAll
    static void assertLoweredLimitTookEffect() {
        // Reflective effectiveness probe, for a clear diagnosis (rather than only a mysterious
        // "no rollover happened" behavioral failure later). Loading T13GCMWriteCipher here also
        // deterministically pins the moment the property is consumed -- after the static block
        // above, before any handshake. Guarded: if the probe itself is unavailable (JDK internals
        // moved, --add-opens missing), the behavioral check in each test still fails loudly on an
        // ineffective limit, so probe unavailability alone must not fail the suite.
        Long effective = null;
        try {
            Class<?> gcmWriteCipher = Class.forName("sun.security.ssl.QuicCipher$T13GCMWriteCipher");
            Field limitField = gcmWriteCipher.getDeclaredField("CONFIDENTIALITY_LIMIT");
            limitField.setAccessible(true);
            effective = (Long) limitField.get(null);
        }
        catch (ReflectiveOperationException | RuntimeException probeUnavailable) {
            System.err.println("[KeyLimitsRealRolloverRoundTripTest] reflective limit probe unavailable ("
                    + probeUnavailable + "); relying on behavioral rollover check only");
        }
        if (effective != null && effective != LOWERED_LIMIT) {
            fail("jdk.quic.tls.keyLimits did NOT take effect: effective AES-GCM confidentiality limit is "
                    + effective + ", expected " + LOWERED_LIMIT + ". The property is read once, in "
                    + "sun.security.ssl.QuicCipher's static initializer -- this almost certainly means QUIC "
                    + "cipher classes were initialized before this test class's static block ran, i.e. this "
                    + "class is running in a shared JVM with other QUIC tests instead of the dedicated "
                    + "keyLimitsRolloverTest task's forked JVM. Run it via './gradlew :kwik:keyLimitsRolloverTest'.");
        }
    }

    @BeforeEach
    void driveRealHandshakeToOneRttKeys() throws Exception {
        SSLContext clientCtx = SSLContext.getInstance("TLSv1.3");
        clientCtx.init(null, trustAllClientSide(), null);

        SSLContext serverCtx = SSLContext.getInstance("TLSv1.3");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        X509Certificate serverCert = TestCertificates.getEndEntityCertificate1();
        PrivateKey serverKey = TestCertificates.getEndEntityCertificate1Key();
        keyStore.setKeyEntry("server", serverKey, new char[0], new X509Certificate[]{ serverCert });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        serverCtx.init(kmf.getKeyManagers(), null, null);

        client = QuicTlsPortImpl.forClient(clientCtx, "localhost", 4433);
        server = QuicTlsPortImpl.forServer(serverCtx);

        configureMinimal(client);
        configureMinimal(server);
        pinAesGcmCipherSuite(client);
        pinAesGcmCipherSuite(server);
        client.setOneRttContext(() -> -1L);
        server.setOneRttContext(() -> -1L);

        byte[] dcid = new byte[8];
        new SecureRandom().nextBytes(dcid);
        client.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));
        server.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));

        boolean bothComplete = false;
        for (int round = 0; round < 20 && !bothComplete; round++) {
            pump(client, server);
            pump(server, client);
            bothComplete = client.isTLSHandshakeComplete() && server.isTLSHandshakeComplete();
        }

        assertThat(client.isTLSHandshakeComplete()).as("client handshake complete").isTrue();
        assertThat(server.isTLSHandshakeComplete()).as("server handshake complete").isTrue();
        assertThat(client.keysAvailable(KeySpace.ONE_RTT)).as("client ONE_RTT keys").isTrue();
        assertThat(server.keysAvailable(KeySpace.ONE_RTT)).as("server ONE_RTT keys").isTrue();
    }

    /**
     * The lowered limit is keyed on the transformation name "AES/GCM/NoPadding"; pin the negotiated
     * suite to an AES-GCM one so the lowered limit is guaranteed to govern this connection
     * (TLS_CHACHA20_POLY1305_SHA256 would use the untouched ChaCha20 default instead).
     */
    private static void pinAesGcmCipherSuite(QuicTlsPort port) {
        SSLParameters p = port.getSSLParameters();
        p.setCipherSuites(new String[]{ "TLS_AES_128_GCM_SHA256" });
        port.setSSLParameters(p);
    }

    // ---- rollover driver -------------------------------------------------------------------------

    /** Everything the tests need to know about the state right after the observed key-phase flip. */
    private static class RolloverState {
        /** Wire bytes of a phase-0 client packet (pn {@link #stashedPn}) generated pre-flip but never delivered. */
        byte[] stashedPhase0Wire;
        long stashedPn;
        /** Client packet number at which the engine flipped the key phase (expected ~52 for limit 64). */
        long flipPn;
        long nextClientPn;
        long nextServerPn;
        byte[] dcid;
    }

    /**
     * Pumps client->server ShortHeaderPackets until the client engine self-initiates a key update,
     * observed as the key phase the engine hands the header generator flipping 0 -> 1. Fails loudly
     * if that doesn't happen within {@link #MAX_PACKETS} packets. Before pumping, one server->client
     * packet is round-tripped: the engine refuses to self-initiate until BOTH endpoints have used
     * the current keys (RFC 9001 §6.1, {@code usedByBothEndpoints}), and the handshake itself never
     * exercises the client's ONE_RTT read cipher. The first post-flip (phase 1) packet is delivered
     * to the server and its transparent acceptance asserted.
     */
    private RolloverState driveToRollover() throws Exception {
        RolloverState s = new RolloverState();
        s.dcid = new byte[]{ 0x4b, 0x50, 0x00, 0x01 }; // "KP"

        // Server->client packet so the client's phase-0 pair counts as used by both endpoints.
        roundTrip(server, client, s.dcid, 0, "server warm-up so client may initiate updates");
        s.nextServerPn = 1;

        // Phase-0 packet generated (hence encrypted, counting toward the limit) but NOT delivered;
        // test 3 presents it to the server only after the flip, as a "delayed" old-phase packet.
        ShortHeaderPacket stashed = new ShortHeaderPacket(Version.getDefault(), s.dcid,
                new StreamFrame(0, "delayed pre-rollover packet".getBytes(), true));
        stashed.setPacketNumber(0);
        s.stashedPhase0Wire = stashed.generatePacketBytes(client);
        s.stashedPn = 0;
        assertThat(stashed.keyPhaseBit).as("stashed packet must still be key phase 0").isEqualTo((short) 0);

        s.flipPn = -1;
        for (long pn = 1; pn <= MAX_PACKETS; pn++) {
            String payload = "rollover pump #" + pn;
            ShortHeaderPacket sent = new ShortHeaderPacket(Version.getDefault(), s.dcid,
                    new StreamFrame(0, payload.getBytes(), true));
            sent.setPacketNumber(pn);
            byte[] wire = sent.generatePacketBytes(client);

            // Deliver every packet (including the first phase-1 one) and assert payload equality --
            // for the flip packet this is already half of "the peer transparently accepts
            // post-rollover packets" (speculative next-key decrypt + its own rollover).
            ShortHeaderPacket received = parseAtServer(wire, pn - 1, s.dcid);
            assertRoundTrippedPayload(received, pn, payload);

            if (sent.keyPhaseBit == 1) {
                s.flipPn = pn;
                assertThat(received.keyPhaseBit)
                        .as("server-side parsed key phase of first post-rollover packet")
                        .isEqualTo((short) 1);
                break;
            }
        }

        if (s.flipPn < 0) {
            fail("Engine never initiated a key update within " + MAX_PACKETS + " ONE_RTT packets. "
                    + "With jdk.quic.tls.keyLimits=AES/GCM/NoPadding " + LOWERED_LIMIT + " in effect it must "
                    + "fire at ~" + (int) (0.8 * LOWERED_LIMIT) + " packets; the default limit (2^23) needs "
                    + "~6.7M. The lowered limit was NOT in effect -- most likely this class ran in a shared "
                    + "JVM where QUIC cipher classes initialized before its static block (see class javadoc; "
                    + "run via './gradlew :kwik:keyLimitsRolloverTest').");
        }
        // Sanity window around the expected trigger point (0.8 * 64 = 51.2 -> 53rd encryption; the
        // stash was the 1st, so pn ~52). Generous slack, but far below anything the default limit
        // could produce and high enough to prove the 80% heuristic (not some accident) fired.
        assertThat(s.flipPn)
                .as("client pn at key-phase flip (expected ~52 for limit " + LOWERED_LIMIT + ")")
                .isBetween(40L, 70L);

        s.nextClientPn = s.flipPn + 1;
        return s;
    }

    private ShortHeaderPacket parseAtServer(byte[] wire, long largestPn, byte[] dcid) throws Exception {
        ShortHeaderPacket received = new ShortHeaderPacket(Version.getDefault());
        received.parse(ByteBuffer.wrap(wire), server, largestPn, mock(Logger.class), dcid.length);
        return received;
    }

    /** One from->to ShortHeaderPacket round trip with payload-equality assertion. */
    private void roundTrip(QuicTlsPort from, QuicTlsPort to, byte[] dcid, long pn, String payload) throws Exception {
        ShortHeaderPacket sent = new ShortHeaderPacket(Version.getDefault(), dcid,
                new StreamFrame(0, payload.getBytes(), true));
        sent.setPacketNumber(pn);
        byte[] wire = sent.generatePacketBytes(from);

        ShortHeaderPacket received = new ShortHeaderPacket(Version.getDefault());
        received.parse(ByteBuffer.wrap(wire), to, pn - 1, mock(Logger.class), dcid.length);
        assertRoundTrippedPayload(received, pn, payload);
    }

    private static void assertRoundTrippedPayload(ShortHeaderPacket received, long pn, String payload) {
        assertThat(received.getPacketNumber()).isEqualTo(pn);
        StreamFrame frame = (StreamFrame) received.getFrames().stream()
                .filter(f -> f instanceof StreamFrame).findFirst().orElseThrow();
        assertThat(new String(frame.getStreamData())).isEqualTo(payload);
    }

    // ---- tests -------------------------------------------------------------------------------------

    @Test
    void engineInitiatedKeyUpdateFlipsPhaseAndRoundTripsTransparentlyBothDirections() throws Exception {
        RolloverState s = driveToRollover();
        // driveToRollover already proved: flip observed on the initiating side at low volume, and the
        // server transparently accepted the first phase-1 packet (payload equality + parsed phase 1).

        // Server->client response: the responder MUST have rolled its own send keys too (RFC 9001
        // §6.2 -- update send keys before sending anything after processing a phase-flipped packet).
        ShortHeaderPacket response = new ShortHeaderPacket(Version.getDefault(), s.dcid,
                new StreamFrame(0, "post-rollover response".getBytes(), true));
        response.setPacketNumber(s.nextServerPn);
        byte[] responseWire = response.generatePacketBytes(server);
        assertThat(response.keyPhaseBit)
                .as("responder's send keys must be phase 1 after processing a phase-1 packet")
                .isEqualTo((short) 1);

        ShortHeaderPacket clientReceived = new ShortHeaderPacket(Version.getDefault());
        clientReceived.parse(ByteBuffer.wrap(responseWire), client, s.nextServerPn - 1, mock(Logger.class), s.dcid.length);
        assertRoundTrippedPayload(clientReceived, s.nextServerPn, "post-rollover response");

        // And plain client->server traffic keeps flowing on the new phase.
        roundTrip(client, server, s.dcid, s.nextClientPn, "steady-state on new key phase");
    }

    @Test
    void delayedPreRolloverPacketStillDecryptsViaOldKeyRetention() throws Exception {
        RolloverState s = driveToRollover();

        // The stashed phase-0 packet (pn 0), presented only now, after the server has rolled over and
        // already decrypted phase-1 packets. Engine-side this must take the one-generation-old
        // retention path (KeySeries.old via canUseOldDecryptKey: phase bit 0 != current phase 1, and
        // pn 0 < lowest pn the current-phase read key has decrypted), per RFC 9001 §6.5 -- NOT be
        // misread as yet another key update or rejected outright.
        ShortHeaderPacket received = parseAtServer(s.stashedPhase0Wire, s.stashedPn - 1, s.dcid);
        assertRoundTrippedPayload(received, s.stashedPn, "delayed pre-rollover packet");
        assertThat(received.keyPhaseBit).as("delayed packet's parsed key phase").isEqualTo((short) 0);
    }

    @Test
    void tamperedPostRolloverPacketIsStillRejected() throws Exception {
        RolloverState s = driveToRollover();

        // Negative control: rolled-over keys must not weaken AEAD integrity handling. Same
        // ciphertext-body tamper technique as the pre-rollover tamper tests.
        ShortHeaderPacket sent = new ShortHeaderPacket(Version.getDefault(), s.dcid,
                new StreamFrame(0, "to be tampered".getBytes(), true));
        sent.setPacketNumber(s.nextClientPn);
        byte[] wire = sent.generatePacketBytes(client);
        assertThat(sent.keyPhaseBit).as("tamper victim must be a phase-1 packet").isEqualTo((short) 1);

        byte[] tampered = wire.clone();
        tampered[tampered.length - 1] ^= 0x01;

        ShortHeaderPacket received = new ShortHeaderPacket(Version.getDefault());
        assertThatThrownBy(() ->
                received.parse(ByteBuffer.wrap(tampered), server, s.nextClientPn - 1, mock(Logger.class), s.dcid.length)
        ).isInstanceOf(DecryptionException.class);

        // The rejected packet must not have wedged the connection: the untampered original still works.
        ShortHeaderPacket recovered = parseAtServer(wire, s.nextClientPn - 1, s.dcid);
        assertRoundTrippedPayload(recovered, s.nextClientPn, "to be tampered");
    }
}
