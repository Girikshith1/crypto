import hashlib
import math


class BloomFilter:
    """Standard Bloom filter using a compact bytearray bit array."""

    def __init__(self, expected_items=1000, bits_per_item=10, k=None):
        self.n_expected = max(1, int(expected_items))
        self.m = max(8, int(self.n_expected * bits_per_item))
        self.k = int(k or max(1, round((self.m / self.n_expected) * math.log(2))))
        self.bits = bytearray((self.m + 7) // 8)
        self.inserted_count = 0

    def _positions(self, value):
        value = str(value).encode("utf-8")
        # Double hashing: h_i(x) = h1(x) + i*h2(x)
        h1 = int.from_bytes(hashlib.sha256(b"A" + value).digest()[:8], "big")
        h2 = int.from_bytes(hashlib.sha256(b"B" + value).digest()[:8], "big")
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def _set_bit(self, pos):
        self.bits[pos // 8] |= (1 << (pos % 8))

    def _get_bit(self, pos):
        return bool(self.bits[pos // 8] & (1 << (pos % 8)))

    def add(self, value):
        for pos in self._positions(value):
            self._set_bit(pos)
        self.inserted_count += 1

    def might_contain(self, value):
        return all(self._get_bit(pos) for pos in self._positions(value))

    def load_factor(self):
        set_bits = sum(byte.bit_count() for byte in self.bits)
        return set_bits / self.m

    def estimated_false_positive_rate(self, n=None):
        n = self.inserted_count if n is None else n
        return (1 - math.exp(-self.k * n / self.m)) ** self.k
