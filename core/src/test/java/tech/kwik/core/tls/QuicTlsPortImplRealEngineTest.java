/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.core.tls;

import jdk.internal.net.quic.QuicTLSEngine.KeySpace;
import jdk.internal.net.quic.QuicVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression-tests, through {@link QuicTlsPortImpl}, the same INITIAL-packet round trip the
 * week-1 spike (spike/QuicTlsEngineInitialPacketSpike.java, SOW §7.1) proved out directly
 * against {@code jdk.internal.net.quic.QuicTLSEngine} -- client encrypt, server decrypt, and a
 * negative-path tamper check -- but this time entirely through the {@link QuicTlsPort}
 * abstraction, against two REAL engine instances built via
 * {@link QuicTlsPortImpl#forClient} / {@link QuicTlsPortImpl#forServer}. This demonstrates the
 * port doesn't lose anything the raw engine could do, not just that a mock compiles (see
 * {@link QuicTlsPortMockTestabilityTest} for that half).
 *
 * <p>Confirms the same SOW-vs-reality discrepancy the spike found:
 * {@link QuicTlsPort#encryptPacket} / {@link QuicTlsPort#decryptPacket} do NOT fuse
 * header-protection sampling/masking -- {@link QuicTlsPort#computeHeaderProtectionMask} is a
 * separate, mandatory call on both directions, every packet.
 *
 * <p>Must run against the DirtyChai JDK image (needs {@code jdk.internal.net.quic}).
 */
class QuicTlsPortImplRealEngineTest {

    private QuicTlsPort client;
    private QuicTlsPort server;
    private byte[] dcid;

    @BeforeEach
    void setUpEnginesAndDeriveInitialKeys() throws Exception {
        SSLContext clientCtx = SSLContext.getInstance("TLSv1.3");
        clientCtx.init(null, null, null);
        SSLContext serverCtx = SSLContext.getInstance("TLSv1.3");
        serverCtx.init(null, null, null);

        assertTrue(QuicTlsPortImpl.isQuicCompatible(clientCtx),
                "SSLContext not QUIC-compatible -- test requires the DirtyChai JDK image");
        assertTrue(QuicTlsPortImpl.isQuicCompatible(serverCtx));

        client = QuicTlsPortImpl.forClient(clientCtx, "localhost", 4433);
        server = QuicTlsPortImpl.forServer(serverCtx);

        // Mirrors JGDMS QuicEngineMtlsTest's minimal construction sequence (per SOW §3.3 note).
        configureMinimal(client);
        configureMinimal(server);

        dcid = new byte[8];
        new SecureRandom().nextBytes(dcid);
        client.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));
        server.deriveInitialKeys(QuicVersion.QUIC_V1, ByteBuffer.wrap(dcid));

        assertTrue(client.keysAvailable(KeySpace.INITIAL));
        assertTrue(server.keysAvailable(KeySpace.INITIAL));
    }

    @Test
    void initialPacketRoundTripsThroughPortAgainstRealEngines() throws Exception {
        Packet packet = buildAndProtectInitialPacket("kwik/JDK QUIC-TLS port INITIAL packet round trip "
                + "-- through QuicTlsPort, not the raw engine");

        // Server side: remove header protection (mandatory separate call, see class javadoc),
        // then the fused decryptPacket.
        ByteBuffer inSample = ByteBuffer.wrap(packet.wire, packet.pnFieldStart + 4, packet.hpSampleSize);
        byte[] inMask = drain(server.computeHeaderProtectionMask(KeySpace.INITIAL, true, inSample));
        byte[] recoveredWire = packet.wire.clone();
        xorProtectHeader(recoveredWire, packet.pnFieldStart, packet.pnLength, inMask);
        long recoveredPn = bytesToLong(recoveredWire, packet.pnFieldStart, packet.pnLength);
        assertEquals(packet.packetNumber, recoveredPn, "recovered packet number must match original");

        ByteBuffer decryptedOut = ByteBuffer.allocate(packet.plaintext.length + client.getAuthTagSize());
        server.decryptPacket(KeySpace.INITIAL, recoveredPn, -1,
                ByteBuffer.wrap(recoveredWire), packet.headerLength, decryptedOut);
        decryptedOut.flip();
        byte[] recoveredPlaintext = drain(decryptedOut);

        assertArrayEquals(packet.plaintext, recoveredPlaintext,
                "decrypted plaintext must match what the client encrypted");
    }

    @Test
    void tamperedCiphertextIsRejectedByRealEngineThroughPort() throws Exception {
        Packet packet = buildAndProtectInitialPacket("payload for the negative-path tamper check");

        ByteBuffer inSample = ByteBuffer.wrap(packet.wire, packet.pnFieldStart + 4, packet.hpSampleSize);
        byte[] inMask = drain(server.computeHeaderProtectionMask(KeySpace.INITIAL, true, inSample));
        byte[] recoveredWire = packet.wire.clone();
        xorProtectHeader(recoveredWire, packet.pnFieldStart, packet.pnLength, inMask);
        long recoveredPn = bytesToLong(recoveredWire, packet.pnFieldStart, packet.pnLength);

        byte[] tamperedWire = recoveredWire.clone();
        tamperedWire[packet.headerLength] ^= 0x01; // flip one bit in the ciphertext body

        ByteBuffer badOut = ByteBuffer.allocate(packet.plaintext.length + client.getAuthTagSize());
        assertThrows(AEADBadTagException.class, () ->
                server.decryptPacket(KeySpace.INITIAL, recoveredPn, -1,
                        ByteBuffer.wrap(tamperedWire), packet.headerLength, badOut),
                "tampered ciphertext must be rejected, not silently accepted");
    }

    @Test
    void mismatchedHeaderAadIsRejectedByRealEngineThroughPort() throws Exception {
        Packet packet = buildAndProtectInitialPacket("payload for the negative-path AAD check");

        ByteBuffer inSample = ByteBuffer.wrap(packet.wire, packet.pnFieldStart + 4, packet.hpSampleSize);
        byte[] inMask = drain(server.computeHeaderProtectionMask(KeySpace.INITIAL, true, inSample));
        byte[] recoveredWire = packet.wire.clone();
        xorProtectHeader(recoveredWire, packet.pnFieldStart, packet.pnLength, inMask);
        long recoveredPn = bytesToLong(recoveredWire, packet.pnFieldStart, packet.pnLength);

        byte[] wrongHeaderWire = recoveredWire.clone();
        wrongHeaderWire[5] ^= 0x01; // a DCID-adjacent header byte, not pn/flags -- not part of HP

        ByteBuffer badOut = ByteBuffer.allocate(packet.plaintext.length + client.getAuthTagSize());
        assertThrows(AEADBadTagException.class, () ->
                server.decryptPacket(KeySpace.INITIAL, recoveredPn, -1,
                        ByteBuffer.wrap(wrongHeaderWire), packet.headerLength, badOut),
                "mismatched header (wrong AAD) must be rejected");
    }

    // ---- helpers ------------------------------------------------------------------------

    private Packet buildAndProtectInitialPacket(String message) throws Exception {
        byte[] scid = new byte[8];
        new SecureRandom().nextBytes(scid);
        int pnLength = 4;
        long packetNumber = 2;
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

        int authTagSize = client.getAuthTagSize();
        int remainingLength = pnLength + plaintext.length + authTagSize;
        byte[] header = buildInitialHeader(dcid, scid, pnLength, packetNumber, remainingLength);
        int pnFieldStart = header.length - pnLength;

        // Client side: fused encryptPacket, then the separate, mandatory computeHeaderProtectionMask.
        ByteBuffer encryptedPayload = ByteBuffer.allocate(plaintext.length + authTagSize);
        client.encryptPacket(KeySpace.INITIAL, packetNumber,
                keyPhase -> ByteBuffer.wrap(header).asReadOnlyBuffer(),
                ByteBuffer.wrap(plaintext), encryptedPayload);
        encryptedPayload.flip();
        byte[] ciphertext = drain(encryptedPayload);
        assertNotEquals(0, ciphertext.length);

        byte[] unprotectedWire = concat(header, ciphertext);
        int hpSampleSize = client.getHeaderProtectionSampleSize(KeySpace.INITIAL);
        ByteBuffer outSample = ByteBuffer.wrap(unprotectedWire, pnFieldStart + 4, hpSampleSize);
        byte[] outMask = drain(client.computeHeaderProtectionMask(KeySpace.INITIAL, false, outSample));

        byte[] wirePacket = unprotectedWire.clone();
        xorProtectHeader(wirePacket, pnFieldStart, pnLength, outMask);

        return new Packet(wirePacket, header.length, pnFieldStart, pnLength, hpSampleSize, packetNumber, plaintext);
    }

    /** Mirrors JGDMS's QuicEngineMtlsTest construction sequence (per SOW §3.3 note). */
    private static void configureMinimal(QuicTlsPort port) throws Exception {
        SSLParameters p = port.getSSLParameters();
        p.setApplicationProtocols(new String[]{"kwik-port-test"});
        p.setProtocols(new String[]{"TLSv1.3"});
        port.setSSLParameters(p);
        port.setRemoteQuicTransportParametersConsumer(buf -> { /* no-op sink */ });
        port.versionNegotiated(QuicVersion.QUIC_V1);
        port.setLocalQuicTransportParameters(ByteBuffer.allocate(0));
    }

    /** RFC 9000 §17.2.2-shaped long header for an Initial packet. Fixed pn length (4), empty
     * token, 2-byte length varint -- same simplifications the week-1 spike used; orthogonal to
     * what this test is gating (the port's crypto call sequencing), not kwik's real variable
     * length pn encoding. */
    private static byte[] buildInitialHeader(byte[] dcid, byte[] scid, int pnLength,
                                              long packetNumber, int remainingLength) {
        ByteBuffer buf = ByteBuffer.allocate(1 + 4 + 1 + dcid.length + 1 + scid.length + 1 + 2 + pnLength);
        byte flags = (byte) (0xC0 | (pnLength - 1));
        buf.put(flags);
        buf.putInt((int) QuicVersion.QUIC_V1.versionNumber());
        buf.put((byte) dcid.length);
        buf.put(dcid);
        buf.put((byte) scid.length);
        buf.put(scid);
        buf.put((byte) 0x00);
        buf.put((byte) (0x40 | ((remainingLength >> 8) & 0x3F)));
        buf.put((byte) (remainingLength & 0xFF));
        for (int i = pnLength - 1; i >= 0; i--) {
            buf.put((byte) ((packetNumber >> (8 * i)) & 0xFF));
        }
        return buf.array();
    }

    private static void xorProtectHeader(byte[] packet, int pnFieldStart, int pnLength, byte[] mask) {
        packet[0] ^= (byte) (mask[0] & 0x0F);
        for (int i = 0; i < pnLength; i++) {
            packet[pnFieldStart + i] ^= mask[1 + i];
        }
    }

    private static long bytesToLong(byte[] buf, int offset, int length) {
        long v = 0;
        for (int i = 0; i < length; i++) {
            v = (v << 8) | (buf[offset + i] & 0xFFL);
        }
        return v;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] drain(ByteBuffer buf) {
        byte[] out = new byte[buf.remaining()];
        buf.get(out);
        return out;
    }

    private static final class Packet {
        final byte[] wire;
        final int headerLength;
        final int pnFieldStart;
        final int pnLength;
        final int hpSampleSize;
        final long packetNumber;
        final byte[] plaintext;

        Packet(byte[] wire, int headerLength, int pnFieldStart, int pnLength, int hpSampleSize,
               long packetNumber, byte[] plaintext) {
            this.wire = wire;
            this.headerLength = headerLength;
            this.pnFieldStart = pnFieldStart;
            this.pnLength = pnLength;
            this.hpSampleSize = hpSampleSize;
            this.packetNumber = packetNumber;
            this.plaintext = plaintext;
        }
    }
}
