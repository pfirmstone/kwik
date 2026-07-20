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
package tech.kwik.core.packet;

import jdk.internal.net.quic.QuicKeyUnavailableException;
import jdk.internal.net.quic.QuicTLSEngine;
import jdk.internal.net.quic.QuicTransportException;
import tech.kwik.core.QuicConstants;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.generic.IntegerTooLargeException;
import tech.kwik.core.generic.InvalidIntegerEncodingException;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.DecryptionException;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.PacketProcessor;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.tls.QuicTlsPort;

import java.nio.ByteBuffer;
import java.util.function.IntFunction;

import static tech.kwik.core.common.KwikConstants.MAX_SUPPORTED_PACKET_SIZE;

public class HandshakePacket extends LongHeaderPacket {

    // Mirrors LongHeaderPacket.MIN_PACKET_LENGTH (private there, so re-derived here): type version
    // dcid len dcid scid len scid length packet number payload.
    private static final int MIN_HANDSHAKE_PACKET_LENGTH = 1 + 4 + 1 + 0 + 1 + 0 + 1 + 1;

    // https://www.rfc-editor.org/rfc/rfc9000.html#name-handshake-packet
    // "A Handshake packet uses long headers with a type value of 0x02, ..."
    private static int V1_type = 2;
    // https://www.rfc-editor.org/rfc/rfc9369.html#name-long-header-packet-types
    // "Handshake: 0b11"
    private static int V2_type = 3;

    public static boolean isHandshake(int type, Version quicVersion) {
        if (quicVersion.isV2()) {
            return type == V2_type;
        }
        else {
            return type == V1_type;
        }
    }

    public HandshakePacket(Version quicVersion) {
        super(quicVersion);
    }

    public HandshakePacket(Version quicVersion, byte[] sourceConnectionId, byte[] destConnectionId, QuicFrame payload) {
        super(quicVersion, sourceConnectionId, destConnectionId, payload);
    }

    public HandshakePacket copy() {
        return new HandshakePacket(quicVersion, sourceConnectionId, destinationConnectionId, frames.size() > 0? frames.get(0): null);
    }

    @Override
    protected byte getPacketType() {
        if (quicVersion.isV2()) {
            return (byte) V2_type;
        }
        else {
            return (byte) V1_type;
        }
    }

    @Override
    protected void generateAdditionalFields(ByteBuffer packetBuffer) {
    }

    @Override
    protected int estimateAdditionalFieldsLength() {
        return 0;
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.Handshake;
    }

    @Override
    public PnSpace getPnSpace() {
        return PnSpace.Handshake;
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, PacketMetaData metaData) {
        return processor.process(this, metaData);
    }

    @Override
    protected void parseAdditionalFields(ByteBuffer buffer) {
    }

    // ---- Port-based protection (ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §2.3/§3/§8 Step B) --
    //
    // HandshakePacket moves to QuicTlsPort/KeySpace.HANDSHAKE; the Aead-taking overrides below are
    // therefore made explicitly unreachable (fail loud, not silently stale) rather than left as a
    // second, parallel, no-longer-used implementation -- see the class-hierarchy decision recorded in
    // the ADVICE doc's §8 Step B entry.

    @Override
    public byte[] generatePacketBytes(Aead aead) {
        throw new UnsupportedOperationException(
                "HandshakePacket uses the port-based protection path (QuicTLSEngine.KeySpace.HANDSHAKE); " +
                "see generatePacketBytes(QuicTlsPort). " +
                "ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§8 Step B.");
    }

    @Override
    public void parse(ByteBuffer data, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) {
        throw new UnsupportedOperationException(
                "HandshakePacket uses the port-based protection path (QuicTLSEngine.KeySpace.HANDSHAKE); " +
                "see parse(ByteBuffer, QuicTlsPort, long, Logger, int). " +
                "ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§8 Step B.");
    }

    @Override
    public byte[] generatePacketBytes(QuicTlsPort tlsPort) throws QuicKeyUnavailableException, QuicTransportException {
        assert (packetNumber >= 0);

        ByteBuffer packetBuffer = ByteBuffer.allocate(MAX_SUPPORTED_PACKET_SIZE);
        generateFrameHeaderInvariant(packetBuffer);
        generateAdditionalFields(packetBuffer);
        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        ByteBuffer frameBytesBuf = generatePayloadBytes(encodedPacketNumber.length);
        byte[] payload = new byte[frameBytesBuf.remaining()];
        frameBytesBuf.get(payload);

        int authTagSize = tlsPort.getAuthTagSize();
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2 -- Length field covers packet
        // number + payload + auth tag; getAuthTagSize() replaces the hardcoded "+ 16" the Aead-based
        // LongHeaderPacket.addLength used (ADVICE doc §3 table).
        VariableLengthInteger.encode(encodedPacketNumber.length + payload.length + authTagSize, packetBuffer);
        int pnFieldStart = packetBuffer.position();
        packetBuffer.put(encodedPacketNumber);

        byte[] header = new byte[packetBuffer.position()];
        packetBuffer.rewind();
        packetBuffer.get(header);
        // Handshake packets have no key-phase bit -- the header is fully known up front, so this
        // callback ignores the phase the engine passes it. Per QuicTLSEngine.encryptPacket's own
        // javadoc: "For KeySpaces where key phase isn't applicable, the headerGenerator will be
        // invoked with a value of 0 for the key phase."
        IntFunction<ByteBuffer> headerGenerator = keyPhase -> ByteBuffer.wrap(header).asReadOnlyBuffer();

        byte[] ciphertext = portEncryptPacket(tlsPort, QuicTLSEngine.KeySpace.HANDSHAKE, packetNumber, headerGenerator, payload);

        byte[] wire = new byte[header.length + ciphertext.length];
        System.arraycopy(header, 0, wire, 0, header.length);
        System.arraycopy(ciphertext, 0, wire, header.length, ciphertext.length);

        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.1 -- header protection is applied
        // after packet protection; sample offset is always 4 bytes after the start of the packet
        // number field, regardless of its actual (1-4 byte) encoded length.
        int sampleSize = tlsPort.getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace.HANDSHAKE);
        byte[] sample = new byte[sampleSize];
        System.arraycopy(wire, pnFieldStart + 4, sample, 0, sampleSize);
        byte[] mask = portComputeHeaderProtectionMask(tlsPort, QuicTLSEngine.KeySpace.HANDSHAKE, false, sample);

        // Long header: 4 bits masked.
        wire[0] ^= (byte) (mask[0] & 0x0f);
        for (int i = 0; i < encodedPacketNumber.length; i++) {
            wire[pnFieldStart + i] ^= mask[1 + i];
        }

        packetSize = wire.length;
        return wire;
    }

    @Override
    public void parse(ByteBuffer buffer, QuicTlsPort tlsPort, long largestPacketNumber, Logger log, int sourceConnectionIdLength)
            throws DecryptionException, InvalidPacketException, TransportError, QuicKeyUnavailableException {
        int packetStartPosition = buffer.position();
        if (buffer.remaining() < MIN_HANDSHAKE_PACKET_LENGTH) {
            throw new InvalidPacketException();
        }
        byte flags = buffer.get();
        checkPacketType((flags & 0x30) >> 4);

        boolean matchingVersion = Version.parse(buffer.getInt()).equals(this.quicVersion);
        if (!matchingVersion) {
            throw new InvalidPacketException("Version does not match version of the connection");
        }

        int dstConnIdLength = buffer.get();
        if (dstConnIdLength < 0 || dstConnIdLength > 20) {
            throw new InvalidPacketException();
        }
        if (buffer.remaining() < dstConnIdLength) {
            throw new InvalidPacketException();
        }
        destinationConnectionId = new byte[dstConnIdLength];
        buffer.get(destinationConnectionId);

        int srcConnIdLength = buffer.get();
        if (srcConnIdLength < 0 || srcConnIdLength > 20) {
            throw new InvalidPacketException();
        }
        if (buffer.remaining() < srcConnIdLength) {
            throw new InvalidPacketException();
        }
        sourceConnectionId = new byte[srcConnIdLength];
        buffer.get(sourceConnectionId);

        parseAdditionalFields(buffer);

        int length;
        try {
            length = VariableLengthInteger.parseInt(buffer);
        }
        catch (IllegalArgumentException | InvalidIntegerEncodingException | IntegerTooLargeException invalidInt) {
            throw new TransportError(QuicConstants.TransportErrorCode.FRAME_ENCODING_ERROR);
        }

        try {
            parsePacketNumberAndPayload(buffer, packetStartPosition, flags, length, tlsPort, QuicTLSEngine.KeySpace.HANDSHAKE, largestPacketNumber, log);
        }
        finally {
            packetSize = buffer.position() - packetStartPosition;
        }
    }
}
