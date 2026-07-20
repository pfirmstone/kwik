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
package tech.kwik.core.crypto;

import tech.kwik.core.impl.DecryptionException;

/**
 * https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
 * "As with TLS over TCP, QUIC protects packets with keys derived from the TLS handshake, using the AEAD algorithm [AEAD]
 *  negotiated by TLS."
 */
public interface Aead {

    byte[] createHeaderProtectionMask(byte[] sample);

    byte[] getIv();

    byte[] aeadEncrypt(byte[] associatedData, byte[] message, byte[] nonce);

    byte[] aeadDecrypt(byte[] associatedData, byte[] message, byte[] nonce) throws DecryptionException;

    // Key-update ratchet methods (checkKeyPhase/computeKeyUpdate/computeNextApplicationTrafficSecret/
    // confirmKeyUpdateIfInProgress/cancelKeyUpdateIfInProgress/getKeyPhase/getKeyUpdateCounter/
    // setPeerAead) were deleted here: kwik no longer tracks or drives key-phase state itself for
    // Handshake/App-level traffic (both moved to QuicTlsPort/QuicTLSEngine in Step B). The engine
    // owns key-phase rollover -- both peer-initiated (speculative "next key" decrypt, confirm/cancel
    // on success/failure) and self-initiated (autonomous, at ~80% of the AEAD confidentiality limit,
    // not caller-triggerable) -- entirely internally; there is no kwik-side state left to check,
    // compute, confirm, or cancel. See ADVICE-Crypto-Seam-Rewrite-Scope-2026-07-20.md §2.2/§2.3/§8
    // Step C. This interface (and Aes128Gcm/Aes256Gcm/ChaCha20/BaseAeadImpl below it) survives for
    // Initial/0-RTT use only, per §6.1.1/§6.1.2 -- neither of which ever used the ratchet.

    byte[] getTrafficSecret();

    byte[] getHp();
}
