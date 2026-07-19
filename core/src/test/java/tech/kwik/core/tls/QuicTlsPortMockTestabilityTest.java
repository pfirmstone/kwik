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

import jdk.internal.net.quic.QuicTLSEngine;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Demonstrates the whole stated rationale of SOW §3.1: code written against the
 * {@link QuicTlsPort} abstraction can be unit-tested with a hand-written stub
 * ({@link FakeQuicTlsPort}), never constructing a real
 * {@code jdk.internal.net.quic.QuicTLSEngine}, never calling
 * {@code jdk.internal.net.quic.QuicTLSContext.createEngine(...)}, and never exercising any
 * DirtyChai-specific runtime behaviour (custom-trust-manager admission, real TLS handshake,
 * real AEAD/HKDF). {@link HandshakeReadinessGate} below stands in for a small slice of the kind
 * of driver logic §3.3 describes moving onto the port (a real port consumer would live in
 * {@code impl/QuicConnectionImpl.java} etc. -- out of scope for this task, see §3.1 scope note).
 *
 * <p>See {@link FakeQuicTlsPort}'s class javadoc for the one honest caveat this test does NOT
 * paper over: because {@link QuicTlsPort}'s own method signatures name real
 * {@code jdk.internal.net.quic} types directly (by design, SOW §6.2), this test file's source
 * still needs a JDK build that has that package present in {@code java.base} to compile -- in
 * this repo's environment that is still the DirtyChai image. What it does NOT need is any of
 * that package's actual engine behaviour.
 */
class QuicTlsPortMockTestabilityTest {

    @Test
    void notReadyForOneRttWhenHandshakeIncomplete() {
        FakeQuicTlsPort fake = new FakeQuicTlsPort();
        fake.tlsHandshakeComplete = false;
        fake.keysAvailable.add(QuicTLSEngine.KeySpace.ONE_RTT);

        assertFalse(HandshakeReadinessGate.readyForOneRtt(fake));
    }

    @Test
    void notReadyForOneRttWhenKeysNotYetAvailable() {
        FakeQuicTlsPort fake = new FakeQuicTlsPort();
        fake.tlsHandshakeComplete = true;
        // ONE_RTT deliberately not added to fake.keysAvailable.

        assertFalse(HandshakeReadinessGate.readyForOneRtt(fake));
    }

    @Test
    void readyForOneRttWhenHandshakeCompleteAndKeysAvailable() {
        FakeQuicTlsPort fake = new FakeQuicTlsPort();
        fake.tlsHandshakeComplete = true;
        fake.keysAvailable.add(QuicTLSEngine.KeySpace.ONE_RTT);

        assertTrue(HandshakeReadinessGate.readyForOneRtt(fake));
    }

    @Test
    void serverShouldSendHandshakeDoneReflectsFakeHandshakeState() {
        FakeQuicTlsPort fake = new FakeQuicTlsPort();
        fake.handshakeState = QuicTLSEngine.HandshakeState.NEED_SEND_HANDSHAKE_DONE;

        assertTrue(HandshakeReadinessGate.serverShouldSendHandshakeDone(fake));
    }

    @Test
    void serverShouldNotSendHandshakeDoneBeforeThatState() {
        FakeQuicTlsPort fake = new FakeQuicTlsPort();
        fake.handshakeState = QuicTLSEngine.HandshakeState.NEED_RECV_CRYPTO;

        assertFalse(HandshakeReadinessGate.serverShouldSendHandshakeDone(fake));
    }

    /**
     * A minimal stand-in for the kind of small, focused decision kwik's re-pointed driver code
     * (§3.3) will make by querying the port instead of a raw {@code QuicTLSEngine}. Deliberately
     * NOT the real thing -- §3.1 scope is just the port definition, not re-pointing
     * {@code QuicConnectionImpl} et al.
     */
    static final class HandshakeReadinessGate {
        private HandshakeReadinessGate() {
        }

        static boolean readyForOneRtt(QuicTlsPort port) {
            return port.isTLSHandshakeComplete() && port.keysAvailable(QuicTLSEngine.KeySpace.ONE_RTT);
        }

        static boolean serverShouldSendHandshakeDone(QuicTlsPort port) {
            return port.getHandshakeState() == QuicTLSEngine.HandshakeState.NEED_SEND_HANDSHAKE_DONE;
        }
    }
}
