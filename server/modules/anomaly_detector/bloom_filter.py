import mmh3
from bitarray import bitarray
import math
import logging

logger = logging.getLogger(__name__)

class BloomFilter:
    """
    A Probabilistic data structure for set membership.
    Used for near-instant request fingerprint checks to detect 'seen before' traffic.
    """
    def __init__(self, size: int = 1_000_000, fp_rate: float = 0.01):
        self.size = size
        self.fp_rate = fp_rate
        self.bit_size = self._get_size(size, fp_rate)
        self.hash_count = self._get_hash_count(self.bit_size, size)
        self.bit_array = bitarray(self.bit_size)
        self.bit_array.setall(0)

    def add(self, string: str):
        for i in range(self.hash_count):
            digest = mmh3.hash(string, i) % self.bit_size
            self.bit_array[digest] = True

    def __contains__(self, string: str):
        for i in range(self.hash_count):
            digest = mmh3.hash(string, i) % self.bit_size
            if self.bit_array[digest] == False:
                return False
        return True

    def _get_size(self, n, p):
        m = -(n * math.log(p)) / (math.log(2)**2)
        return int(m)

    def _get_hash_count(self, m, n):
        k = (m/n) * math.log(2)
        return int(k)
        
    def reset(self):
        self.bit_array.setall(0)
