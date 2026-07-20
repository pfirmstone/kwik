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

import jdk.internal.net.quic.QuicTLSEngine.HandshakeState;
import jdk.internal.net.quic.QuicTLSEngine.KeySpace;
import jdk.internal.net.quic.QuicVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.core.frame.PingFrame;
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
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §4/§8 Step B verification: drives two real
 * {@code QuicTlsPortImpl} instances (real DirtyChai {@code QuicTLSEngine}s, not
 * {@link tech.kwik.core.tls.FakeQuicTlsPort}) through a minimal, in-memory TLS 1.3 handshake --
 * ClientHello through server Finished -- purely to get real {@code HANDSHAKE}/{@code ONE_RTT} keys
 * available on both sides for a test harness, per this task's brief. This is NOT the production
 * handshake driver (SOW §3.3's {@code CryptoStream}-replacement work, out of scope for Step B) --
 * it is a throwaway pump loop that exists only so {@link HandshakePacket}/{@link ShortHeaderPacket}'s
 * new port-based {@code generatePacketBytes}/{@code parse} can be round-tripped against a real
 * engine's real, negotiated key material, rather than only against {@code FakeQuicTlsPort}'s
 * structural-only fake or self-consistent-but-not-externally-verified round trips.
 *
 * <p>Mirrors {@code QuicTlsPortImplRealEngineTest}'s INITIAL-level precedent (same
 * {@code configureMinimal}/engine-construction shape), extended with the handshake pump this class
 * adds and {@code QuicTlsPortImplRealEngineTest} does not need (INITIAL keys are derivable with no
 * handshake state at all).
 */
class HandshakeShortHeaderPacketRealEngineRoundTripTest {

    private QuicTlsPort client;
    private QuicTlsPort server;

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
        // Required for ONE_RTT encrypt/decrypt to actually work, discovered empirically: keysAvailable
        // (KeySpace.ONE_RTT) can be true while encryptPacket/decryptPacket(ONE_RTT, ...) still throw
        // QuicKeyUnavailableException if no QuicOneRttContext has been set. "-1" (nothing acked yet)
        // is a reasonable placeholder for a fresh connection's first few packets, which is all this
        // harness needs. Real production wiring of this (the actual largest-peer-acked-PN tracker) is
        // §3.3 driver-seam territory, not built here.
        client.setOneRttContext(() -> -1L);
        server.setOneRttContext(() -> -1L);

        byte[] dcid = new byte[8];
        new SecureRandom().nextBytes(dcid);
        client.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));
        server.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));

        // Minimal handshake pump: alternately let each side produce whatever handshake bytes/tasks its
        // current HandshakeState calls for, feeding produced bytes straight to the peer. keysAvailable
        // (ONE_RTT) becomes true on BOTH sides once each has processed the key-schedule-relevant
        // transcript through the server's Finished message (RFC 8446 §7.1) -- before the client's own
        // Finished is necessarily sent. But that is not enough to actually USE ONE_RTT decrypt:
        // discovered empirically, the server engine's decryptPacket(ONE_RTT, ...) throws
        // QuicKeyUnavailableException("QUIC TLS handshake not yet complete") until
        // isTLSHandshakeComplete() is true on the server too, which requires the client's Finished to
        // have actually reached and been verified by the server. So this loop drives all the way to
        // isTLSHandshakeComplete() on both sides, not just keysAvailable(ONE_RTT) -- still well short
        // of a full production handshake driver (§3.3): no HANDSHAKE_DONE frame, no transport
        // parameter exchange beyond the empty placeholder configureMinimal sets, just enough real TLS
        // 1.3 state for both engines to treat ONE_RTT as fully usable in both directions.
        boolean bothComplete = false;
        for (int round = 0; round < 20 && !bothComplete; round++) {
            pump(client, server);
            pump(server, client);
            bothComplete = client.isTLSHandshakeComplete() && server.isTLSHandshakeComplete();
        }

        assertThat(client.isTLSHandshakeComplete()).as("client handshake complete").isTrue();
        assertThat(server.isTLSHandshakeComplete()).as("server handshake complete").isTrue();
        assertThat(client.keysAvailable(KeySpace.HANDSHAKE)).as("client HANDSHAKE keys").isTrue();
        assertThat(server.keysAvailable(KeySpace.HANDSHAKE)).as("server HANDSHAKE keys").isTrue();
        assertThat(client.keysAvailable(KeySpace.ONE_RTT)).as("client ONE_RTT keys").isTrue();
        assertThat(server.keysAvailable(KeySpace.ONE_RTT)).as("server ONE_RTT keys").isTrue();
    }

    @Test
    void handshakePacketRoundTripsThroughRealEngine() throws Exception {
        byte[] scid = { (byte) 0xba, (byte) 0xbe };
        byte[] dcid = { 0x0c, 0x0a, 0x0f, 0x0e };
        HandshakePacket sent = new HandshakePacket(Version.getDefault(), scid, dcid, new StreamFrame(0, "real HANDSHAKE-level engine round trip".getBytes(), true));
        sent.setPacketNumber(0);

        byte[] wire = sent.generatePacketBytes(client);

        HandshakePacket received = new HandshakePacket(Version.getDefault());
        received.parse(ByteBuffer.wrap(wire), server, 0, mock(Logger.class), dcid.length);

        assertThat(received.getPacketNumber()).isEqualTo(0L);
        assertThat(received.getFrames()).hasAtLeastOneElementOfType(StreamFrame.class);
        StreamFrame receivedFrame = (StreamFrame) received.getFrames().stream()
                .filter(f -> f instanceof StreamFrame).findFirst().orElseThrow();
        assertThat(new String(receivedFrame.getStreamData())).isEqualTo("real HANDSHAKE-level engine round trip");
    }

    @Test
    void shortHeaderPacketRoundTripsThroughRealEngine() throws Exception {
        byte[] dcid = { 0x0e, 0x0b, 0x02, 0x0f, 0x0a, 0x04, 0x02, 0x0d };
        ShortHeaderPacket sent = new ShortHeaderPacket(Version.getDefault(), dcid, new StreamFrame(0, "real ONE_RTT-level engine round trip".getBytes(), true));
        sent.setPacketNumber(0);

        byte[] wire = sent.generatePacketBytes(client);

        ShortHeaderPacket received = new ShortHeaderPacket(Version.getDefault());
        received.parse(ByteBuffer.wrap(wire), server, 0, mock(Logger.class), dcid.length);

        assertThat(received.getPacketNumber()).isEqualTo(0L);
        assertThat(received.getFrames()).hasAtLeastOneElementOfType(StreamFrame.class);
        StreamFrame receivedFrame = (StreamFrame) received.getFrames().stream()
                .filter(f -> f instanceof StreamFrame).findFirst().orElseThrow();
        assertThat(new String(receivedFrame.getStreamData())).isEqualTo("real ONE_RTT-level engine round trip");
    }

    @Test
    void secondShortHeaderPacketAlsoRoundTripsThroughRealEngine() throws Exception {
        // Regression check for the IntFunction header-generator inversion (§2.3/§3): a second packet
        // number, still key phase 0 (no rollover pressure at this volume), must still round-trip --
        // guards against a bug where the callback's resolved header is only captured correctly for the
        // very first invocation.
        byte[] dcid = { 0x01, 0x02, 0x03, 0x04 };
        ShortHeaderPacket first = new ShortHeaderPacket(Version.getDefault(), dcid, new PingFrame());
        first.setPacketNumber(0);
        first.generatePacketBytes(client);

        ShortHeaderPacket second = new ShortHeaderPacket(Version.getDefault(), dcid, new StreamFrame(0, "second packet".getBytes(), true));
        second.setPacketNumber(1);
        byte[] wire = second.generatePacketBytes(client);

        ShortHeaderPacket received = new ShortHeaderPacket(Version.getDefault());
        received.parse(ByteBuffer.wrap(wire), server, 0, mock(Logger.class), dcid.length);

        assertThat(received.getPacketNumber()).isEqualTo(1L);
    }

    @Test
    void tamperedHandshakePacketIsRejectedByRealEngine() throws Exception {
        byte[] scid = { (byte) 0xba, (byte) 0xbe };
        byte[] dcid = { 0x0c, 0x0a, 0x0f, 0x0e };
        HandshakePacket sent = new HandshakePacket(Version.getDefault(), scid, dcid, new PingFrame());
        sent.setPacketNumber(0);
        byte[] wire = sent.generatePacketBytes(client);

        // Flip a bit well inside the ciphertext body (past the header, which for this packet is
        // 1 (flags) + 4 (version) + 1 + dcid.length + 1 + scid.length + up-to-2 (length) + pnLength
        // bytes -- comfortably less than wire.length - 4, since padding guarantees a minimum payload).
        byte[] tampered = wire.clone();
        tampered[tampered.length - 4] ^= 0x01;

        HandshakePacket received = new HandshakePacket(Version.getDefault());
        assertThatThrownBy(() ->
                received.parse(ByteBuffer.wrap(tampered), server, 0, mock(Logger.class), dcid.length)
        ).isInstanceOf(DecryptionException.class);
    }

    // ---- handshake pump helpers -----------------------------------------------------------------
    // Package-private (not private): reused as-is by KeyUpdateRatchetRemovalRealEngineRoundTripTest
    // (Step C's own new test, ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §7.2/§8 Step C), rather
    // than duplicated, per this task's brief to "reuse [this class's] construction pattern". No
    // logic change, visibility only.

    static void pump(QuicTlsPort port, QuicTlsPort peer) throws Exception {
        for (int i = 0; i < 20; i++) {
            HandshakeState state = port.getHandshakeState();
            if (state == HandshakeState.NEED_TASK) {
                Runnable task = port.getDelegatedTask();
                if (task == null) {
                    break;
                }
                task.run();
                continue;
            }
            if (state == HandshakeState.NEED_SEND_CRYPTO) {
                KeySpace keySpace = port.getCurrentSendKeySpace();
                ByteBuffer bytes = port.getHandshakeBytes(keySpace);
                if (bytes == null || !bytes.hasRemaining()) {
                    break;
                }
                peer.consumeHandshakeBytes(keySpace, bytes);
                continue;
            }
            // NEED_SEND_HANDSHAKE_DONE/NEED_RECV_HANDSHAKE_DONE are QUIC-transport-level bookkeeping
            // (RFC 9001 §4.1.2's HANDSHAKE_DONE frame), not CRYPTO-stream data -- discovered
            // empirically, since without this the server's HandshakeState wedges at
            // NEED_SEND_HANDSHAKE_DONE forever and isTLSHandshakeComplete() never becomes true for it.
            // This harness has no real QUIC transport (no actual HANDSHAKE_DONE frame is built or
            // sent), so it drives the engine's own bookkeeping calls directly instead -- sufficient to
            // get both engines to real, usable ONE_RTT keys, which is all this harness needs; a real
            // §3.3 driver would instead do this via an actual frame round trip.
            if (state == HandshakeState.NEED_SEND_HANDSHAKE_DONE) {
                port.tryMarkHandshakeDone();
                continue;
            }
            if (state == HandshakeState.NEED_RECV_HANDSHAKE_DONE) {
                port.tryReceiveHandshakeDone();
                continue;
            }
            break;
        }
    }

    static TrustManager[] trustAllClientSide() {
        // Test-only: this harness exists to derive real key material for a crypto round-trip test,
        // not to verify certificate validation policy -- a permissive trust manager keeps the pump
        // loop free of delegated cert-path-validation tasks unrelated to what this test class checks.
        return new TrustManager[]{ new X509ExtendedTrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {}
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
    }

    /** Mirrors QuicTlsPortImplRealEngineTest's construction sequence (per SOW §3.3 note). */
    static void configureMinimal(QuicTlsPort port) throws Exception {
        SSLParameters p = port.getSSLParameters();
        p.setApplicationProtocols(new String[]{ "kwik-port-test" });
        p.setProtocols(new String[]{ "TLSv1.3" });
        port.setSSLParameters(p);
        port.setRemoteQuicTransportParametersConsumer(buf -> { /* no-op sink */ });
        port.versionNegotiated(QuicVersion.QUIC_V1);
        port.setLocalQuicTransportParameters(ByteBuffer.allocate(0));
    }
}
