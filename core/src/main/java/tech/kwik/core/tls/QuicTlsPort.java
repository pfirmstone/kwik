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
import tech.kwik.core.common.EncryptionLevel;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.function.IntFunction;

/**
 * SOW-Kwik-JSSE-QUIC-TLS-Transport.md §3.1 isolation port.
 *
 * <p>This is the single point of contact between this fork's re-pointed code and
 * {@code jdk.internal.net.quic.QuicTLSEngine}: per §3.1, <em>all</em> re-pointed kwik code is
 * meant to talk to this port, never to {@code jdk.internal.net.quic} types directly. The
 * benefit is a single choke-point (one file changes if/when OpenJDK publishes a public
 * QUIC-TLS API per JEP 517) and mock-testability (code that depends on this interface can be
 * unit-tested against a hand-written stub, without the DirtyChai JDK).
 *
 * <p><b>This is a thin pass-through, not a facade.</b> Per SOW §6.2(d), the architecture
 * decision here is a direct dependency on {@code jdk.internal.net.quic} plus this port, not a
 * facade with a parallel type hierarchy. Accordingly this interface's own method signatures
 * name real {@code jdk.internal.net.quic} types directly ({@link QuicVersion},
 * {@link QuicTransportException}, {@link QuicTLSEngine.KeySpace}, etc.) — the isolation this
 * port gives is a single call-site choke-point, not type erasure. The honest consequence
 * (also per §6.2): the port <em>confines</em> the {@code jdk.internal.net.quic} dependency to
 * one file's contract, it does not <em>sever</em> it — a future conversion to a public QUIC-TLS
 * API will still need to touch this interface's signatures, not just {@link QuicTlsPortImpl}.
 *
 * <p>The method set below is a 1:1 mirror of every method on
 * {@code jdk.internal.net.quic.QuicTLSEngine} (verified against the DirtyChai source, not just
 * the SOW's prose description of it — see the corrected header-protection note on
 * {@link #computeHeaderProtectionMask}). Every engine method is covered, not just the ones the
 * SOW's work items happen to enumerate by name, so that re-pointed code never has a reason to
 * reach past the port for configuration ({@link #setSSLParameters}, mode selection,
 * {@link #getSession()}, etc.) the way it would for the crypto/handshake-drive calls.
 */
public interface QuicTlsPort {

    // ---- Configuration -------------------------------------------------------------------

    /**
     * @see QuicTLSEngine#getSupportedQuicVersions()
     */
    Set<QuicVersion> getSupportedQuicVersions();

    /**
     * @see QuicTLSEngine#setUseClientMode(boolean)
     */
    void setUseClientMode(boolean mode);

    /**
     * @see QuicTLSEngine#getUseClientMode()
     */
    boolean getUseClientMode();

    /**
     * @see QuicTLSEngine#getSSLParameters()
     */
    SSLParameters getSSLParameters();

    /**
     * @see QuicTLSEngine#setSSLParameters(SSLParameters)
     */
    void setSSLParameters(SSLParameters sslParameters);

    /**
     * @see QuicTLSEngine#getApplicationProtocol()
     */
    String getApplicationProtocol();

    /**
     * @see QuicTLSEngine#getSession()
     */
    SSLSession getSession();

    /**
     * @see QuicTLSEngine#getHandshakeSession()
     */
    SSLSession getHandshakeSession();

    // ---- Handshake state / drive (§3.3) ---------------------------------------------------

    /**
     * @see QuicTLSEngine#getHandshakeState()
     */
    QuicTLSEngine.HandshakeState getHandshakeState();

    /**
     * @see QuicTLSEngine#isTLSHandshakeComplete()
     */
    boolean isTLSHandshakeComplete();

    /**
     * @see QuicTLSEngine#getCurrentSendKeySpace()
     */
    QuicTLSEngine.KeySpace getCurrentSendKeySpace();

    /**
     * @see QuicTLSEngine#versionNegotiated(QuicVersion)
     */
    void versionNegotiated(QuicVersion quicVersion);

    /**
     * @see QuicTLSEngine#restartHandshake()
     */
    void restartHandshake() throws IOException;

    /**
     * @see QuicTLSEngine#getHandshakeBytes(QuicTLSEngine.KeySpace)
     */
    ByteBuffer getHandshakeBytes(QuicTLSEngine.KeySpace keySpace) throws IOException;

    /**
     * @see QuicTLSEngine#consumeHandshakeBytes(QuicTLSEngine.KeySpace, ByteBuffer)
     */
    void consumeHandshakeBytes(QuicTLSEngine.KeySpace keySpace, ByteBuffer payload) throws QuicTransportException;

    /**
     * @see QuicTLSEngine#getDelegatedTask()
     */
    Runnable getDelegatedTask();

    /**
     * @see QuicTLSEngine#tryMarkHandshakeDone()
     */
    boolean tryMarkHandshakeDone();

    /**
     * @see QuicTLSEngine#tryReceiveHandshakeDone()
     */
    boolean tryReceiveHandshakeDone();

    /**
     * @see QuicTLSEngine#setOneRttContext(QuicOneRttContext)
     */
    void setOneRttContext(QuicOneRttContext ctx);

    // ---- Transport parameters (§3.4) ------------------------------------------------------

    /**
     * @see QuicTLSEngine#setLocalQuicTransportParameters(ByteBuffer)
     */
    void setLocalQuicTransportParameters(ByteBuffer params);

    /**
     * @see QuicTLSEngine#setRemoteQuicTransportParametersConsumer(QuicTransportParametersConsumer)
     */
    void setRemoteQuicTransportParametersConsumer(QuicTransportParametersConsumer consumer);

    // ---- Keys (§3.2, §3.5) -----------------------------------------------------------------

    /**
     * @see QuicTLSEngine#deriveInitialKeys(QuicVersion, ByteBuffer)
     */
    void deriveInitialKeys(QuicVersion quicVersion, ByteBuffer connectionId) throws IOException;

    /**
     * @see QuicTLSEngine#keysAvailable(QuicTLSEngine.KeySpace)
     */
    boolean keysAvailable(QuicTLSEngine.KeySpace keySpace);

    /**
     * @see QuicTLSEngine#discardKeys(QuicTLSEngine.KeySpace)
     */
    void discardKeys(QuicTLSEngine.KeySpace keySpace);

    // ---- Packet protection (§3.2) -----------------------------------------------------------
    //
    // NOTE, correcting an inaccuracy in an earlier SOW draft: encryptPacket/decryptPacket do
    // NOT fuse header-protection sampling/masking. computeHeaderProtectionMask is a mandatory
    // separate call, required alongside encryptPacket (outgoing) and before decryptPacket
    // (incoming), on every packet, both directions -- not an optional fallback for cases the
    // fused call doesn't fit. This was verified two ways: reading decryptPacket's own javadoc
    // ("Header protection must be removed before calling this method") and the week-1 spike
    // (spike/QuicTlsEngineInitialPacketSpike.java) driving a real INITIAL packet round trip.
    // Callers of this port MUST call computeHeaderProtectionMask themselves; it is not done for
    // them inside encryptPacket/decryptPacket.

    /**
     * @see QuicTLSEngine#getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace)
     */
    int getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace keySpace);

    /**
     * Compute the header-protection mask for the given sample. This is a mandatory, separate
     * step from {@link #encryptPacket} / {@link #decryptPacket} -- see the class-level note
     * above.
     *
     * @see QuicTLSEngine#computeHeaderProtectionMask(QuicTLSEngine.KeySpace, boolean, ByteBuffer)
     */
    ByteBuffer computeHeaderProtectionMask(QuicTLSEngine.KeySpace keySpace, boolean incoming, ByteBuffer sample)
            throws QuicKeyUnavailableException, QuicTransportException;

    /**
     * @see QuicTLSEngine#getAuthTagSize()
     */
    int getAuthTagSize();

    /**
     * @see QuicTLSEngine#encryptPacket(QuicTLSEngine.KeySpace, long, IntFunction, ByteBuffer, ByteBuffer)
     */
    void encryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber,
                        IntFunction<ByteBuffer> headerGenerator,
                        ByteBuffer packetPayload,
                        ByteBuffer output)
            throws QuicKeyUnavailableException, QuicTransportException, ShortBufferException;

    /**
     * @see QuicTLSEngine#decryptPacket(QuicTLSEngine.KeySpace, long, int, ByteBuffer, int, ByteBuffer)
     */
    void decryptPacket(QuicTLSEngine.KeySpace keySpace, long packetNumber, int keyPhase,
                        ByteBuffer packet, int headerLength, ByteBuffer output)
            throws QuicKeyUnavailableException, AEADBadTagException, QuicTransportException, ShortBufferException;

    // ---- Retry (§3.3) ------------------------------------------------------------------------

    /**
     * @see QuicTLSEngine#signRetryPacket(QuicVersion, ByteBuffer, ByteBuffer, ByteBuffer)
     */
    void signRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet, ByteBuffer output)
            throws ShortBufferException, QuicTransportException;

    /**
     * @see QuicTLSEngine#verifyRetryPacket(QuicVersion, ByteBuffer, ByteBuffer)
     */
    void verifyRetryPacket(QuicVersion version, ByteBuffer originalConnectionId, ByteBuffer packet)
            throws AEADBadTagException, QuicTransportException;

    // ---- EncryptionLevel <-> KeySpace mapping (§4.1, Step B) ----------------------------------

    /**
     * Translates a kwik {@link EncryptionLevel} to the port's {@link QuicTLSEngine.KeySpace}, for use
     * at the {@code PacketParser}/{@code SenderImpl} call sites that select which key space to pass
     * into the packet-protection methods above (ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§4).
     *
     * <p>{@link EncryptionLevel#ZeroRTT} has no mapping: per SOW §3.5 (STD-010 §6.2), 0-RTT re-pointing
     * to this port is a separate, not-yet-scoped work item, and per §6.1.1 of the ADVICE doc above,
     * {@code ZeroRttPacket} continues to use the legacy {@code ConnectionSecrets}/{@code Aead}
     * path for the duration of this rewrite, never this port. Callers MUST branch on
     * {@code EncryptionLevel == ZeroRTT} themselves and never reach this method for it; calling it
     * with {@code ZeroRTT} is a caller bug, hence an unchecked exception, not a checked one.
     *
     * <p>{@link EncryptionLevel#Initial} likewise stays permanently on the legacy path per §6.1.2/§10
     * (OQ-4) of the ADVICE doc -- this method still translates it correctly (the mapping itself is
     * 1:1), but no re-pointed call site is expected to actually invoke this method with {@code Initial}.
     *
     * <p>{@link QuicTLSEngine.KeySpace#RETRY} has no corresponding {@code EncryptionLevel} at all
     * (RFC 9001 §5.8's Retry integrity tag is not TLS-secret-derived) and is therefore not a case this
     * method can be asked to produce -- there is no {@code EncryptionLevel} value that maps to it.
     * {@code RetryPacket} uses {@link #signRetryPacket}/{@link #verifyRetryPacket} directly instead.
     *
     * @throws IllegalArgumentException if {@code level} is {@link EncryptionLevel#ZeroRTT}
     */
    static QuicTLSEngine.KeySpace toKeySpace(EncryptionLevel level) {
        switch (level) {
            case Initial:   return QuicTLSEngine.KeySpace.INITIAL;
            case Handshake: return QuicTLSEngine.KeySpace.HANDSHAKE;
            case App:       return QuicTLSEngine.KeySpace.ONE_RTT;
            case ZeroRTT:
                throw new IllegalArgumentException(
                        "ZeroRTT has no KeySpace mapping: 0-RTT is not re-pointed to the port by this " +
                        "rewrite (SOW §3.5); ZeroRttPacket must use the legacy Aead path, not this method.");
            default:
                throw new IllegalStateException("unreachable: " + level); // exhaustive switch guard
        }
    }
}
