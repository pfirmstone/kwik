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
import tech.kwik.core.impl.DecryptionException;
import tech.kwik.core.impl.InvalidPacketException;
import tech.kwik.core.impl.PacketProcessor;
import tech.kwik.core.impl.TransportError;
import tech.kwik.core.impl.Version;
import tech.kwik.core.log.Logger;
import tech.kwik.core.tls.QuicTlsPort;
import tech.kwik.core.util.Bytes;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.function.IntFunction;
import java.util.stream.Collectors;

import static tech.kwik.core.common.KwikConstants.MAX_SUPPORTED_PACKET_SIZE;

public class ShortHeaderPacket extends QuicPacket {

    protected short keyPhaseBit;

    /**
     * Constructs an empty short header packet for use with the parse() method.
     * @param quicVersion
     */
    public ShortHeaderPacket(Version quicVersion) {
        this.quicVersion = quicVersion;
    }

    /**
     * Constructs a short header packet for sending (client role).
     * @param quicVersion
     * @param destinationConnectionId
     * @param frame
     */
    public ShortHeaderPacket(Version quicVersion, byte[] destinationConnectionId, QuicFrame frame) {
        this.quicVersion = quicVersion;
        this.destinationConnectionId = destinationConnectionId;
        frames = new ArrayList<>();
        if (frame != null) {
            frames.add(frame);
        }
    }

    @Override
    public void parse(ByteBuffer buffer, Aead aead, long largestPacketNumber, Logger log, int sourceConnectionIdLength) {
        // ShortHeaderPacket (App/ONE_RTT) uses the port-based protection path -- see
        // parse(ByteBuffer, QuicTlsPort, long, Logger, int) and the class-hierarchy decision recorded
        // in ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md's §8 Step B entry. This also removes this
        // method's former key-update ratchet call sites (aead.confirmKeyUpdateIfInProgress() /
        // aead.cancelKeyUpdateIfInProgress()) as a side effect: the engine owns key-phase state
        // internally now (§2.2/§2.3) and there is no port-equivalent call to translate them to.
        // KeyUpdateSupport.java itself is left in place, as now-dead code, for Step C to delete
        // deliberately and in isolation (§8 Step C) -- not deleted here.
        throw new UnsupportedOperationException(
                "ShortHeaderPacket uses the port-based protection path (QuicTLSEngine.KeySpace.ONE_RTT); " +
                "see parse(ByteBuffer, QuicTlsPort, long, Logger, int). " +
                "ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§8 Step B.");
    }

    protected void checkReservedBits(byte decryptedFlags) throws TransportError {
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1
        // "An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both
        //  packet and header protection, as a connection error of type PROTOCOL_VIOLATION. "
        if ((decryptedFlags & 0x18) != 0) {
            throw new TransportError(QuicConstants.TransportErrorCode.PROTOCOL_VIOLATION, "Reserved bits in short header packet are not zero");
        }
    }

    @Override
    protected void setUnprotectedHeader(byte decryptedFlags) {
        keyPhaseBit = (short) ((decryptedFlags & 0x04) >> 2);
    }

    @Override
    public int estimateLength(int additionalPayload) {
        int packetNumberSize = computePacketNumberSize(packetNumber);
        int payloadSize = getFrames().stream().mapToInt(f -> f.getFrameLength()).sum() + additionalPayload;
        int padding = Integer.max(0,4 - packetNumberSize - payloadSize);
        return 1
                + destinationConnectionId.length
                + (packetNumber < 0? 4: packetNumberSize)
                + payloadSize
                + padding
                // https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-sample
                // "The ciphersuites defined in [TLS13] - (...) - have 16-byte expansions..."
                + 16;
    }

    @Override
    public EncryptionLevel getEncryptionLevel() {
        return EncryptionLevel.App;
    }

    @Override
    public PnSpace getPnSpace() {
        return PnSpace.App;
    }

    @Override
    public byte[] generatePacketBytes(Aead aead) {
        // ShortHeaderPacket (App/ONE_RTT) uses the port-based protection path -- see
        // generatePacketBytes(QuicTlsPort) and the class-hierarchy decision recorded in
        // ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md's §8 Step B entry. This also removes this
        // method's former "keyPhaseBit = aead.getKeyPhase()" read as a side effect: the engine decides
        // the key phase now, only inside encryptPacket (§2.2/§2.3), which is exactly why the
        // port-based replacement below needs the IntFunction header-generator inversion §2.3/§3
        // describe rather than a straight call substitution.
        throw new UnsupportedOperationException(
                "ShortHeaderPacket uses the port-based protection path (QuicTLSEngine.KeySpace.ONE_RTT); " +
                "see generatePacketBytes(QuicTlsPort). " +
                "ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§8 Step B.");
    }

    @Override
    public byte[] generatePacketBytes(QuicTlsPort tlsPort) throws QuicKeyUnavailableException, QuicTransportException {
        assert (packetNumber >= 0);

        byte[] encodedPacketNumber = encodePacketNumber(packetNumber);
        ByteBuffer frameBytesBuf = generatePayloadBytes(encodedPacketNumber.length);
        byte[] payload = new byte[frameBytesBuf.remaining()];
        frameBytesBuf.get(payload);

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3 -- "|0|1|S|R|R|K|P P|". The key
        // phase (K) bit is only known *inside* encryptPacket -- the engine may roll keys over as a
        // side effect of the very call that's asking for it (ADVICE doc §2.2-2.4/§3). So, unlike the
        // old Aead-based code (which read aead.getKeyPhase() up front and built the whole header
        // before encrypting), the header can only be finalized from *inside* the headerGenerator
        // callback the engine invokes with the phase it decided on -- a structural inversion, not a
        // call substitution.
        byte[][] resolvedHeader = new byte[1][];
        IntFunction<ByteBuffer> headerGenerator = phase -> {
            keyPhaseBit = (short) phase;
            byte flags = 0x40;  // 0100 0000
            flags = (byte) (flags | (keyPhaseBit << 2));
            flags = encodePacketNumberLength(flags, packetNumber);

            ByteBuffer header = ByteBuffer.allocate(1 + destinationConnectionId.length + encodedPacketNumber.length);
            header.put(flags);
            header.put(destinationConnectionId);
            header.put(encodedPacketNumber);
            header.flip();
            byte[] headerBytes = new byte[header.remaining()];
            header.get(headerBytes);
            resolvedHeader[0] = headerBytes;
            return ByteBuffer.wrap(headerBytes).asReadOnlyBuffer();
        };

        byte[] ciphertext = portEncryptPacket(tlsPort, QuicTLSEngine.KeySpace.ONE_RTT, packetNumber, headerGenerator, payload);
        byte[] header = resolvedHeader[0];

        byte[] wire = new byte[header.length + ciphertext.length];
        System.arraycopy(header, 0, wire, 0, header.length);
        System.arraycopy(ciphertext, 0, wire, header.length, ciphertext.length);

        // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.1 -- header protection is applied
        // after packet protection; sample offset is always 4 bytes after the start of the packet
        // number field, regardless of its actual (1-4 byte) encoded length.
        int pnFieldStart = 1 + destinationConnectionId.length;
        int sampleSize = tlsPort.getHeaderProtectionSampleSize(QuicTLSEngine.KeySpace.ONE_RTT);
        byte[] sample = new byte[sampleSize];
        System.arraycopy(wire, pnFieldStart + 4, sample, 0, sampleSize);
        byte[] mask = portComputeHeaderProtectionMask(tlsPort, QuicTLSEngine.KeySpace.ONE_RTT, false, sample);

        // Short header: 5 bits masked.
        wire[0] ^= (byte) (mask[0] & 0x1f);
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
        if (buffer.remaining() < 1 + sourceConnectionIdLength) {
            throw new InvalidPacketException();
        }
        byte flags = buffer.get();
        checkPacketType(flags);

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
        // "Packets with short headers (Section 17.3) only include the Destination Connection ID and omit the explicit
        //  length. The length of the Destination Connection ID field is expected to be known to endpoints. "
        byte[] packetConnectionId = new byte[sourceConnectionIdLength];
        destinationConnectionId = packetConnectionId;
        buffer.get(packetConnectionId);

        try {
            parsePacketNumberAndPayload(buffer, packetStartPosition, flags, buffer.limit() - buffer.position(),
                    tlsPort, QuicTLSEngine.KeySpace.ONE_RTT, largestPacketNumber, log);
            // No confirmKeyUpdateIfInProgress()/cancelKeyUpdateIfInProgress() call here (unlike the old
            // Aead-based parse above): the engine handles peer-initiated key-phase rollover
            // (speculate against "next" keys, then confirm-on-success/cancel-on-AEADBadTagException)
            // entirely internally now -- see ADVICE doc §2.2/§2.3. There is no kwik-side ratchet state
            // left to confirm or cancel.
        }
        finally {
            packetSize = buffer.position() - packetStartPosition;
        }
    }

    @Override
    public PacketProcessor.ProcessResult accept(PacketProcessor processor, PacketMetaData metaData) {
        return processor.process(this, metaData);
    }

    protected void checkPacketType(byte flags) {
        if ((flags & 0xc0) != 0x40) {
            // Programming error: this method shouldn't have been called if packet is not a Short Frame
            throw new RuntimeException();
        }
    }

    public byte[] getDestinationConnectionId() {
        return destinationConnectionId;
    }

    @Override
    public String toString() {
        return "Packet "
                + (isProbe? "P": "")
                + getEncryptionLevel().name().charAt(0) + "|"
                + (packetNumber >= 0? packetNumber: ".") + "|"
                + "S" + keyPhaseBit + "|"
                + Bytes.bytesToHex(destinationConnectionId) + "|"
                + packetSize + "|"
                + frames.size() + "  "
                + frames.stream().map(f -> f.toString()).collect(Collectors.joining(" "));
    }

}
