"""
SHA-256 (Secure Hash Algorithm 256-bit) implementation from scratch.

This is a complete implementation following FIPS 180-4 specification.
Implements the core algorithm without using library hash functions.
"""

from typing import List, Tuple


class SHA256:
    """SHA-256 hash function implementation from scratch."""

    # SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]

    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    INITIAL_HASH = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    def __init__(self, data: bytes = b""):
        """
        Initialize SHA256 with optional data.

        Args:
            data: Bytes to hash
        """
        self.hash_values = self.INITIAL_HASH.copy()
        self.message_length = 0
        self._buffer = b""

        if data:
            self.update(data)

    @staticmethod
    def _right_rotate(value: int, amount: int) -> int:
        """Right rotate a 32-bit integer."""
        value &= 0xFFFFFFFF
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

    @staticmethod
    def _right_shift(value: int, amount: int) -> int:
        """Right shift a 32-bit integer."""
        return (value >> amount) & 0xFFFFFFFF

    @staticmethod
    def _sigma0(x: int) -> int:
        """Sigma 0 function: ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)"""
        return (
            SHA256._right_rotate(x, 2)
            ^ SHA256._right_rotate(x, 13)
            ^ SHA256._right_rotate(x, 22)
        )

    @staticmethod
    def _sigma1(x: int) -> int:
        """Sigma 1 function: ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)"""
        return (
            SHA256._right_rotate(x, 6)
            ^ SHA256._right_rotate(x, 11)
            ^ SHA256._right_rotate(x, 25)
        )

    @staticmethod
    def _gamma0(x: int) -> int:
        """Gamma 0 function: ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)"""
        return (
            SHA256._right_rotate(x, 7)
            ^ SHA256._right_rotate(x, 18)
            ^ SHA256._right_shift(x, 3)
        )

    @staticmethod
    def _gamma1(x: int) -> int:
        """Gamma 1 function: ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)"""
        return (
            SHA256._right_rotate(x, 17)
            ^ SHA256._right_rotate(x, 19)
            ^ SHA256._right_shift(x, 10)
        )

    @staticmethod
    def _ch(x: int, y: int, z: int) -> int:
        """CH function: (x AND y) XOR ((NOT x) AND z)"""
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x: int, y: int, z: int) -> int:
        """MAJ function: (x AND y) XOR (x AND z) XOR (y AND z)"""
        return (x & y) ^ (x & z) ^ (y & z)

    def _process_block(self, block: bytes) -> None:
        """
        Process a 512-bit (64-byte) block.

        Args:
            block: 64-byte block to process
        """
        self._process_block_with_state(block, self.hash_values)

    def _process_block_with_state(self, block: bytes, hash_values: List[int]) -> None:
        """
        Process a 512-bit (64-byte) block with custom hash state.

        Args:
            block: 64-byte block to process
            hash_values: List of 8 hash values to update
        """
        # Parse block into 16 32-bit words (big-endian)
        w: List[int] = []
        for i in range(16):
            word = (
                (block[i * 4] << 24)
                | (block[i * 4 + 1] << 16)
                | (block[i * 4 + 2] << 8)
                | (block[i * 4 + 3])
            )
            w.append(word & 0xFFFFFFFF)

        # Extend the 16 32-bit words to 64 words
        for i in range(16, 64):
            s0 = self._gamma0(w[i - 15])
            s1 = self._gamma1(w[i - 2])
            word = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF
            w.append(word)

        # Initialize working variables with current hash values
        a, b, c, d, e, f, g, h = hash_values

        # Main loop (64 iterations)
        for i in range(64):
            S1 = self._sigma1(e)
            ch = self._ch(e, f, g)
            temp1 = (h + S1 + ch + self.K[i] + w[i]) & 0xFFFFFFFF
            S0 = self._sigma0(a)
            maj = self._maj(a, b, c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add compressed chunk to current hash value
        hash_values[0] = (hash_values[0] + a) & 0xFFFFFFFF
        hash_values[1] = (hash_values[1] + b) & 0xFFFFFFFF
        hash_values[2] = (hash_values[2] + c) & 0xFFFFFFFF
        hash_values[3] = (hash_values[3] + d) & 0xFFFFFFFF
        hash_values[4] = (hash_values[4] + e) & 0xFFFFFFFF
        hash_values[5] = (hash_values[5] + f) & 0xFFFFFFFF
        hash_values[6] = (hash_values[6] + g) & 0xFFFFFFFF
        hash_values[7] = (hash_values[7] + h) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:
        """
        Update hash with new data.

        Args:
            data: Bytes to add to hash
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        self.message_length += len(data)

        # Combine buffer with new data
        buffer = self._buffer + data

        # Process complete 64-byte blocks
        while len(buffer) >= 64:
            self._process_block(buffer[:64])
            buffer = buffer[64:]

        # Store remaining bytes for final processing
        self._buffer = buffer

    def digest(self) -> bytes:
        """
        Return the digest as bytes.

        Returns:
            32-byte hash digest
        """
        # Create temporary copies to avoid modifying state
        hash_values = self.hash_values.copy()
        message_length = self.message_length
        buffer = self._buffer

        # Pre-processing (padding)
        msg_len_bits = message_length * 8
        msg = bytearray(buffer)
        msg.append(0x80)  # Append '1' bit (plus 7 '0' bits)

        # Append '0' bits until message length ≡ 448 (mod 512)
        while (len(msg) % 64) != 56:
            msg.append(0x00)

        # Append message length as 64-bit big-endian
        msg.extend(msg_len_bits.to_bytes(8, byteorder="big"))

        # Process final blocks using temporary hash values
        for i in range(0, len(msg), 64):
            self._process_block_with_state(bytes(msg[i : i + 64]), hash_values)

        # Produce the final hash value
        hash_digest = b""
        for h in hash_values:
            hash_digest += h.to_bytes(4, byteorder="big")

        return hash_digest

    def hexdigest(self) -> str:
        """
        Return the digest as a hex string.

        Returns:
            64-character hex string
        """
        return self.digest().hex()

    def copy(self) -> "SHA256":
        """Create a copy of the hash object."""
        new_hash = SHA256.__new__(SHA256)
        new_hash.hash_values = self.hash_values.copy()
        new_hash.message_length = self.message_length
        new_hash._buffer = getattr(self, "_buffer", b"")
        return new_hash


def sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Bytes to hash

    Returns:
        32-byte hash digest
    """
    return SHA256(data).digest()


def sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash of data as hex string.

    Args:
        data: Bytes to hash

    Returns:
        64-character hex string
    """
    return SHA256(data).hexdigest()
