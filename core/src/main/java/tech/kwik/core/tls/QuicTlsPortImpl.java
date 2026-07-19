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
import jdk.internal.net.quic.QuicTLSContext;
import jdk.internal.net.quic.QuicTLSEngine;
import jdk.internal.net.quic.QuicTransportException;
import jdk.internal.net.quic.QuicTransportParametersConsumer;
import jdk.internal.net.quic.QuicVersion;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Set;
import java.util.function.IntFunction;

/**
 * Production implementation of {@link QuicTlsPort}: wraps one real
 * {@code jdk.internal.net.quic.QuicTLSEngine} instance and delegates every port method to it.
 *
 * <p>This is the <em>only</em> class in the fork that is expected to construct a
 * {@code QuicTLSEngine} (via {@link QuicTLSContext}) or hold a direct reference to one -- per
 * SOW §3.1, re-pointed kwik code is meant to obtain a {@link QuicTlsPort} through the static
 * factories here ({@link #forClient} / {@link #forServer}) and never touch
 * {@code jdk.internal.net.quic} itself.
 */
public final class QuicTlsPortImpl implements QuicTlsPort {

    private final QuicTLSEngine engine;

    /**
     * Package-visible (not private) so tests in this package can construct a port directly
     * around an engine they built themselves, without going through the SSLContext-based
     * factories below.
     */
    QuicTlsPortImpl(QuicTLSEngine engine) {
        this.engine = Objects.requireNonNull(engine, "engine");
    }

    /**
     * @see QuicTLSContext#isQuicCompatible(SSLContext)
     */
    public static boolean isQuicCompatible(SSLContext sslContext) {
        return QuicTLSContext.isQuicCompatible(sslContext);
    }

    /**
     * Builds a client-mode port over a freshly constructed engine.
     *
     * @param sslContext a QUIC-compatible {@code SSLContext} (see {@link #isQuicCompatible})
     * @param peerHost   advisory peer hostname for session-cache hints / server_name extension;
     *                   may be null
     * @param peerPort   advisory peer port; -1 if unknown
     */
    public static QuicTlsPort forClient(SSLContext sslContext, String peerHost, int peerPort) {
        QuicTLSEngine engine = new QuicTLSContext(sslContext).createEngine(peerHost, peerPort);
        engine.setUseClientMode(true);
        return new QuicTlsPortImpl(engine);
    }

    /**
     * Builds a server-mode port over a freshly constructed engine.
     *
     * @param sslContext a QUIC-compatible {@code SSLContext} (see {@link #isQuicCompatible})
     */
    public static QuicTlsPort forServer(SSLContext sslContext) {
        QuicTLSEngine engine = new QuicTLSContext(sslContext).createEngine();
        engine.setUseClientMode(false);
        return new QuicTlsPortImpl(engine);
    }

    // ---- Configuration -------------------------------------------------------------------

    @Override
    public Set<QuicVersion> getSupportedQuicVersions() {
        return engine.getSupportedQuicVersions();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        engine.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    @Override
    public SSLParameters getSSLParameters() {
        return engine.getSSLParameters();
    }

    @Override
    public void setSSLParameters(SSLParameters sslParameters) {
        engine.setSSLParameters(sslParameters);
    }

    @Override
    public String getApplicationProtocol() {
        return engine.getApplicationProtocol();
    }

    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    @Override
    public SSLSession getHandshakeSession() {
        return engine.getHandshakeSession();
    }

    // ---- Handshake state / drive -----------------------------------------------------------

    @Override
    public QuicTLSEngine.HandshakeState getHandshakeState() {
        return engine.getHandshakeState();
    }

    @Override
    public boolean isTLSHandshakeComplete() {
        return engine.isTLSHandshakeComplete();
    }

    @Override
    public QuicTLSEngine.KeySpace getCurrentSendKeySpace() {
        return engine.getCurrentSendKeySpace();
    }

    @Override
    public void versionNegotiated(QuicVersion quicVersion) {
        engine.versionNegotiated(quicVersion);
    }

    @Override
    public void restartHandshake() throws IOException {
        engine.restartHandshake();
    }

    @Override
    public ByteBuffer getHandshakeBytes(QuicTLSEngine.KeySpace keySpace) throws IOException {
        return engine.getHandshakeBytes(keySpace);
    }

    @Override
    public void consumeHandshakeBytes(QuicTLSEngine.KeySpace keySpace, ByteBuffer payload) throws QuicTransportException {
        engine.consumeHandshakeBytes(keySpace, payload);
    }

    @Override
    public Runnable getDelegatedTask() {
        return engine.getDelegatedTask();
    }

    @Override
    public boolean tryMarkHandshakeDone() {
        return engine.tryMarkHandshakeDone();
    }

    @Override
    public boolean tryReceiveHandshakeDone() {
        return engine.tryReceiveHandshakeDone();
    }

    @Override
    public void setOneRttContext(QuicOneRttContext ctx) {
        engine.setOneRttContext(ctx);
    }

    // ---- Transport parameters --------------------------------------------------------------

    @Override
    public void setLocalQuicTransportParameters(ByteBuffer params) {
        engine.setLocalQuicTransportParameters(params);
    }

    @Override
    public void setRemoteQuicTransportParametersConsumer(QuicTransportParametersConsumer consumer) {
        engine.setRemoteQuicTransportParametersConsumer(consumer);
    }

    // ---- Keys ------------------------------------------------------------------------------

    @Override
    public void deriveInitialKeys(QuicVersion quicVersion, ByteBuffer connectionId) throws IOException {
        engine.deriveInitialKeys(quicVersion, connectionId);
    }

    @Override
    public boolean keysAvailable(QuicTLSEngine.KeySpace keySpace) {
        return engine.keysAvailable(keySpace);
    }

    @Override
    public void discardKeys(QuicTLSEngine.KeySpace keySpace) {
        engine.discardKeys(keySpace);
    }

    // ---- Packet protection ------------------------------------------------------------------

    @Override
    public int getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace keySpace) {
        return engine.getHeaderProtectionSampleSize(keySpace);
    }

    @Override
    public ByteBuffer computeHeaderProtectionMask(QuicTLSEngine.KeySpace keySpace, boolean incoming, ByteBuffer sample)
            throws QuicKeyUnavailableException, QuicTransportException {
        return engine.computeHeaderProtectionMask(keySpace, incoming, sample);
    }

    @Override
    public int getAuthTagSize() {
        return engine.getAuthTagSize();
    }

    @Override
    public void encryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber,
                               IntFunction<ByteBuffer> headerGenerator,
                               ByteBuffer packetPayload,
                               ByteBuffer output)
            throws QuicKeyUnavailableException, QuicTransportException, ShortBufferException {
        engine.encryptPacket(keySpace, packetNumber, headerGenerator, packetPayload, output);
    }

    @Override
    public void decryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber, int keyPhase,
                               ByteBuffer packet, int headerLength, ByteBuffer output)
            throws QuicKeyUnavailableException, AEADBadTagException, QuicTransportException, ShortBufferException {
        engine.decryptPacket(keySpace, packetNumber, keyPhase, packet, headerLength, output);
    }

    // ---- Retry -----------------------------------------------------------------------------

    @Override
    public void signRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet, ByteBuffer output)
            throws ShortBufferException, QuicTransportException {
        engine.signRetryPacket(version, originalConnectionId, packet, output);
    }

    @Override
    public void verifyRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet)
            throws AEADBadTagException, QuicTransportException {
        engine.verifyRetryPacket(version, originalConnectionId, packet);
    }
}
