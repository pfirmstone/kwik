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

import jdk.internal.net.quic.QuicKeyUnavailableException;
import jdk.internal.net.quic.QuicOneRttContext;
import jdk.internal.net.quic.QuicTLSEngine;
import jdk.internal.net.quic.QuicTransportException;
import jdk.internal.net.quic.QuicTransportParametersConsumer;
import jdk.internal.net.quic.QuicVersion;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.IntFunction;

/**
 * A trivial, entirely hand-written {@link QuicTlsPort} stub -- NOT a wrapper around a real
 * {@code jdk.internal.net.quic.QuicTLSEngine}. It never constructs
 * {@code jdk.internal.net.quic.QuicTLSContext}, never touches
 * {@code sun.security.ssl.QuicTLSEngineImpl}, and performs no real TLS handshake, key
 * derivation, or AEAD crypto -- everything here is an in-memory field controlled directly by
 * the test.
 *
 * <p>This class exists to demonstrate the SOW §3.1 rationale in practice: code that depends on
 * {@link QuicTlsPort} (see {@link HandshakeReadinessGate} in
 * {@code QuicTlsPortMockTestabilityTest}) can be unit-tested against this stub instead of a real
 * engine.
 *
 * <p>Also reused, from {@code tech.kwik.core.packet}/{@code tech.kwik.core.send} tests, as the
 * Handshake/App-level fixture for {@code HandshakePacket}/{@code ShortHeaderPacket}'s port-based
 * {@code generatePacketBytes}/{@code parse} methods (ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md
 * §7.2/§8 Step B) -- for tests that only need structurally-correct, self-consistent round trips
 * (byte layout, length accounting, key-phase bit plumbing), not real cryptographic correctness
 * against external test vectors. {@link QuicTlsPortImplRealEngineTest} and the new real-engine
 * Handshake/App round-trip coverage added for Step B are what verify actual crypto correctness
 * against a real DirtyChai engine; this fake exists so the many structural/negative-path tests
 * don't need one.
 *
 * <p><b>Honest caveat (see the class javadoc on {@link QuicTlsPort}, and SOW §6.2):</b> because
 * {@code QuicTlsPort}'s own method signatures name real {@code jdk.internal.net.quic} types
 * directly (by design -- a thin pass-through, not a facade with a parallel type hierarchy), this
 * stub's source still has to import {@code jdk.internal.net.quic.QuicTLSEngine.KeySpace},
 * {@code HandshakeState}, etc. purely to satisfy the interface's method signatures -- and so
 * still requires a JDK build whose {@code java.base} contains the {@code jdk.internal.net.quic}
 * package to compile at all (verified empirically: it does not exist in stock OpenJDK 25.0.3,
 * only in this DirtyChai build -- see the task report). What this stub demonstrably does NOT
 * need is any of the DirtyChai-specific *runtime* machinery: no {@code QuicTLSContext}, no
 * {@code SSLContext} QUIC-compatibility gating, no real engine instance, no actual handshake or
 * cryptography of any kind.
 */
public class FakeQuicTlsPort implements QuicTlsPort {

    // Test-controlled state -- set directly by test methods before exercising code under test.
    boolean useClientMode;
    QuicTLSEngine.HandshakeState handshakeState = QuicTLSEngine.HandshakeState.NEED_RECV_CRYPTO;
    boolean tlsHandshakeComplete;
    QuicTLSEngine.KeySpace currentSendKeySpace = QuicTLSEngine.KeySpace.INITIAL;
    final Set<QuicTLSEngine.KeySpace> keysAvailable = EnumSet.noneOf(QuicTLSEngine.KeySpace.class);
    boolean markHandshakeDoneResult;
    boolean receiveHandshakeDoneResult;

    @Override
    public Set<QuicVersion> getSupportedQuicVersions() {
        return Set.of(QuicVersion.QUIC_V1);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        this.useClientMode = mode;
    }

    @Override
    public boolean getUseClientMode() {
        return useClientMode;
    }

    @Override
    public SSLParameters getSSLParameters() {
        return new SSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        // no-op: nothing in this fake consumes SSLParameters.
    }

    @Override
    public String getApplicationProtocol() {
        return null;
    }

    @Override
    public SSLSession getSession() {
        return null;
    }

    @Override
    public SSLSession getHandshakeSession() {
        return null;
    }

    @Override
    public QuicTLSEngine.HandshakeState getHandshakeState() {
        return handshakeState;
    }

    @Override
    public boolean isTLSHandshakeComplete() {
        return tlsHandshakeComplete;
    }

    @Override
    public QuicTLSEngine.KeySpace getCurrentSendKeySpace() {
        return currentSendKeySpace;
    }

    @Override
    public void versionNegotiated(QuicVersion quicVersion) {
        // no-op
    }

    @Override
    public void restartHandshake() {
        // no-op
    }

    @Override
    public ByteBuffer getHandshakeBytes(QuicTLSEngine.KeySpace keySpace) {
        return null;
    }

    @Override
    public void consumeHandshakeBytes(QuicTLSEngine.KeySpace keySpace, ByteBuffer payload) {
        // no-op
    }

    @Override
    public Runnable getDelegatedTask() {
        return null;
    }

    @Override
    public boolean tryMarkHandshakeDone() {
        return markHandshakeDoneResult;
    }

    @Override
    public boolean tryReceiveHandshakeDone() {
        return receiveHandshakeDoneResult;
    }

    @Override
    public void setOneRttContext(QuicOneRttContext ctx) {
        // no-op
    }

    @Override
    public void setLocalQuicTransportParameters(ByteBuffer params) {
        // no-op
    }

    @Override
    public void setRemoteQuicTransportParametersConsumer(QuicTransportParametersConsumer consumer) {
        // no-op
    }

    @Override
    public void deriveInitialKeys(QuicVersion quicVersion, ByteBuffer connectionId) {
        keysAvailable.add(QuicTLSEngine.KeySpace.INITIAL);
    }

    /**
     * Test-only convenience so callers outside this package (e.g. {@code HandshakePacketTest},
     * {@code ShortHeaderPacketTest}, {@code SenderImplTest} -- all reusing this fake per the class
     * javadoc above) can seed {@link #keysAvailable} for Handshake/App-level {@code KeySpace}s
     * without a real {@code deriveInitialKeys}/handshake-drive equivalent existing for those levels.
     */
    public void makeKeysAvailable(QuicTLSEngine.KeySpace keySpace) {
        keysAvailable.add(keySpace);
    }

    @Override
    public boolean keysAvailable(QuicTLSEngine.KeySpace keySpace) {
        return keysAvailable.contains(keySpace);
    }

    @Override
    public void discardKeys(QuicTLSEngine.KeySpace keySpace) {
        keysAvailable.remove(keySpace);
    }

    @Override
    public int getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace keySpace) {
        return 16;
    }

    @Override
    public ByteBuffer computeHeaderProtectionMask(QuicTLSEngine.KeySpace keySpace, boolean incoming, ByteBuffer sample) {
        return ByteBuffer.allocate(5);
    }

    @Override
    public int getAuthTagSize() {
        return 16;
    }

    @Override
    public void encryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber,
                               IntFunction<ByteBuffer> headerGenerator,
                               ByteBuffer packetPayload,
                               ByteBuffer output)
            throws QuicKeyUnavailableException {
        if (!keysAvailable.contains(keySpace)) {
            throw new QuicKeyUnavailableException("fake: no keys", keySpace);
        }
        // headerGenerator must still be invoked, even though this fake doesn't use its result as
        // real AAD -- callers (ShortHeaderPacket in particular) rely on the invocation itself to
        // resolve the key phase and finalize the header bytes they kept a reference to (ADVICE doc
        // §2.3/§3's IntFunction inversion). A phase of 0 mirrors what a real engine would pass for a
        // KeySpace where key phase isn't applicable (HANDSHAKE); tests that care about a specific
        // phase value for ONE_RTT should not rely on this fake's arbitrary choice here.
        headerGenerator.apply(0);
        // Trivial "encryption": copy the plaintext through, then append a fixed-size, all-zero fake
        // tag of getAuthTagSize() bytes -- not real authentication, but keeps output length accurate
        // (payload + auth tag size) for tests that check estimateLength()-vs-actual-length
        // accounting. No real AEAD; good enough for testing driver/structural logic, not crypto
        // correctness -- that is exactly what QuicTlsPortImplRealEngineTest is for.
        output.put(packetPayload);
        output.put(new byte[getAuthTagSize()]);
    }

    @Override
    public void decryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber, int keyPhase,
                               ByteBuffer packet, int headerLength, ByteBuffer output)
            throws QuicKeyUnavailableException {
        if (!keysAvailable.contains(keySpace)) {
            throw new QuicKeyUnavailableException("fake: no keys", keySpace);
        }
        // Inverse of encryptPacket above: strip the trailing fake tag, copy the rest through.
        packet.position(packet.position() + headerLength);
        int plaintextLength = packet.remaining() - getAuthTagSize();
        if (plaintextLength < 0) {
            throw new IllegalArgumentException("fake: packet shorter than the fake auth tag size");
        }
        int savedLimit = packet.limit();
        packet.limit(packet.position() + plaintextLength);
        output.put(packet);
        packet.limit(savedLimit);
    }

    @Override
    public void signRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet, ByteBuffer output) {
        // no-op
    }

    @Override
    public void verifyRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet) {
        // no-op: never throws, i.e. this fake always "verifies" successfully.
    }
}
