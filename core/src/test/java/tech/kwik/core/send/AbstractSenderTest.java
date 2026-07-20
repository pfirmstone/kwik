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
package tech.kwik.core.send;

import jdk.internal.net.quic.QuicTLSEngine;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.impl.TestUtils;
import tech.kwik.core.crypto.Aead;
import tech.kwik.core.packet.QuicPacket;
import tech.kwik.core.tls.FakeQuicTlsPort;
import org.junit.jupiter.api.BeforeEach;

public class AbstractSenderTest {

    public static final int MAX_PACKET_SIZE = 1232;

    protected Aead aead;
    protected Aead[] levelKeys = new Aead[4];
    /**
     * Handshake/App-level fixture (ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §3/§6.1.2):
     * {@code aead}/{@code levelKeys} above still cover Initial/ZeroRTT, which stay on the legacy
     * Aead path; Handshake and App packets now need a {@link tech.kwik.core.tls.QuicTlsPort} instead.
     * See {@link #generatePacketBytesForTest(QuicPacket)}.
     */
    protected FakeQuicTlsPort tlsPort;

    @BeforeEach
    void initKeys() throws Exception {
        aead = TestUtils.createKeys();
        for (int i = 0; i < EncryptionLevel.values().length; i++) {
            levelKeys[i] = TestUtils.createKeys();
        }
        tlsPort = new FakeQuicTlsPort();
        tlsPort.makeKeysAvailable(QuicTLSEngine.KeySpace.HANDSHAKE);
        tlsPort.makeKeysAvailable(QuicTLSEngine.KeySpace.ONE_RTT);
    }

    /**
     * Dispatches to the Aead-taking or port-taking {@code generatePacketBytes} overload depending on
     * the packet's encryption level (ADVICE doc §3/§6.1.2): Handshake/App use {@link #tlsPort} above;
     * Initial/ZeroRTT keep using the per-level {@link #levelKeys} Aead fixture. Centralizes the branch
     * so call sites that used to call {@code generatePacketBytes(aead)}/{@code generatePacketBytes(levelKeys[...])}
     * uniformly across all packet types (before Handshake/App moved to the port) don't each need to
     * know which path a given packet's level is on.
     */
    protected byte[] generatePacketBytesForTest(QuicPacket packet) throws Exception {
        EncryptionLevel level = packet.getEncryptionLevel();
        if (level == EncryptionLevel.Handshake || level == EncryptionLevel.App) {
            return packet.generatePacketBytes(tlsPort);
        }
        return packet.generatePacketBytes(levelKeys[level.ordinal()]);
    }

    /**
     * Same as {@link #generatePacketBytesForTest(QuicPacket)}, wrapping the checked exceptions in an
     * unchecked one -- for call sites inside a lambda passed to {@code Stream.mapToInt(...)} etc.,
     * where a checked exception can't be thrown directly.
     */
    protected byte[] generatePacketBytesForTestUnchecked(QuicPacket packet) {
        try {
            return generatePacketBytesForTest(packet);
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
