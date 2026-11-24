# BitcoinOil merge-mining (AuxPoW) and ASERT difficulty rules.
# Mirrors src/auxpow.cpp and src/pow.cpp of BitcoinOil Core.
from typing import NamedTuple, Sequence, Tuple

from .crypto import sha256d

VERSION_AUXPOW = 0x100
MM_HEADER = b'\xfa\xbemm'
HEADER_SIZE = 80


class AuxPowError(Exception):
    pass


class AuxPow(NamedTuple):
    coinbase_txid: bytes  # internal byte order
    coinbase_num_inputs: int
    coinbase_script: bytes  # scriptSig of the first input
    merkle_branch: Sequence[bytes]
    chain_merkle_branch: Sequence[bytes]
    chain_index: int
    parent_header: bytes


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise AuxPowError('truncated auxpow')
        res = self.data[self.pos:self.pos + n]
        self.pos += n
        return res

    def uint(self, n: int) -> int:
        return int.from_bytes(self.read(n), 'little')

    def compact_size(self) -> int:
        n = self.uint(1)
        if n < 0xfd:
            return n
        size, minimum = {0xfd: (2, 0xfd), 0xfe: (4, 0x10000), 0xff: (8, 0x100000000)}[n]
        n = self.uint(size)
        if n < minimum:
            raise AuxPowError('non-canonical compact size')
        return n

    def branch(self) -> Sequence[bytes]:
        return [self.read(32) for _ in range(self.compact_size())]

    def coinbase(self) -> Tuple[bytes, int, bytes]:
        version = self.read(4)
        witness = self.data[self.pos:self.pos + 2] == b'\x00\x01'
        if witness:
            self.read(2)
        start = self.pos
        n_in = self.compact_size()
        script = b''
        for i in range(n_in):
            self.read(36)
            s = self.read(self.compact_size())
            if i == 0:
                script = s
            self.read(4)
        for _ in range(self.compact_size()):
            self.read(8)
            self.read(self.compact_size())
        body = self.data[start:self.pos]
        if witness:
            for _ in range(n_in):
                for _ in range(self.compact_size()):
                    self.read(self.compact_size())
        locktime = self.read(4)
        return sha256d(version + body + locktime), n_in, script


def has_auxpow(version: int) -> bool:
    return bool(version & VERSION_AUXPOW)


def get_chain_id(version: int) -> int:
    """As GetChainId(): the version is a signed int32 and C++ division truncates."""
    if version >= 1 << 31:
        version -= 1 << 32
    return abs(version) // 0x10000 * (1 if version >= 0 else -1)


def parse_auxpow(data: bytes) -> AuxPow:
    r = _Reader(data)
    txid, n_in, script = r.coinbase()
    r.read(32)  # parent block hash, not used by consensus
    merkle_branch = r.branch()
    r.read(4)  # index, always taken as 0
    chain_branch = r.branch()
    chain_index = r.uint(4)
    parent = r.read(HEADER_SIZE)
    if r.pos != len(data):
        raise AuxPowError('extra data after auxpow')
    return AuxPow(txid, n_in, script, merkle_branch, chain_branch, chain_index, parent)


def _merkle_root(leaf: bytes, branch: Sequence[bytes], index: int) -> bytes:
    for h in branch:
        leaf = sha256d(h + leaf) if index & 1 else sha256d(leaf + h)
        index >>= 1
    return leaf


def expected_index(nonce: int, chain_id: int, height: int) -> int:
    mod = 1 << height
    rand = (nonce * 1103515245 + 12345) % mod
    rand = ((rand + chain_id) * 1103515245 + 12345) % mod
    return rand


def verify_auxpow(pow_: AuxPow, *, aux_hash: bytes, chain_id: int) -> bytes:
    """Check the link from a block hash (internal byte order) to the parent header.
    Returns the parent block hash (internal byte order), which must meet the target.
    """
    if get_chain_id(int.from_bytes(pow_.parent_header[:4], 'little')) == chain_id:
        raise AuxPowError('parent has our chain ID')
    if len(pow_.chain_merkle_branch) > 30:
        raise AuxPowError('chain merkle branch too long')
    if pow_.chain_index >= 1 << 31:
        raise AuxPowError('negative chain index')
    root = _merkle_root(aux_hash, pow_.chain_merkle_branch, pow_.chain_index)[::-1]
    if _merkle_root(pow_.coinbase_txid, pow_.merkle_branch, 0) != pow_.parent_header[36:68]:
        raise AuxPowError('merkle root incorrect')
    if pow_.coinbase_num_inputs == 0:
        raise AuxPowError('coinbase has no inputs')
    script = pow_.coinbase_script
    pos = script.find(root)
    if pos == -1:
        raise AuxPowError('missing chain merkle root in parent coinbase')
    head = script.find(MM_HEADER)
    if head != -1:
        if script.find(MM_HEADER, head + 1) != -1:
            raise AuxPowError('multiple merged mining headers')
        if head + len(MM_HEADER) != pos:
            raise AuxPowError('merged mining header is not just before the root')
    elif pos > 20:
        raise AuxPowError('root must start in the first 20 bytes')
    pos += 32
    if len(script) - pos < 8:
        raise AuxPowError('missing chain merkle size and nonce')
    size = int.from_bytes(script[pos:pos + 4], 'little')
    nonce = int.from_bytes(script[pos + 4:pos + 8], 'little')
    height = len(pow_.chain_merkle_branch)
    if size != 1 << height:
        raise AuxPowError('merkle branch size does not match')
    if pow_.chain_index != expected_index(nonce, chain_id, height):
        raise AuxPowError('wrong index')
    return sha256d(pow_.parent_header)


def asert_target(*, ref_target: int, spacing: int, time_diff: int, height_diff: int, limit: int, half_life: int) -> int:
    """aserti3 target (CalculateASERT). limit must have 32 leading zero bits."""
    assert 0 < ref_target <= limit < 1 << 224
    assert height_diff >= 0
    num = (time_diff - spacing * (height_diff + 1)) * 65536
    exponent = abs(num) // half_life * (1 if num >= 0 else -1)  # truncating division
    shifts = exponent >> 16
    frac = exponent & 0xffff
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac ** 2 + 5127 * frac ** 3 + (1 << 47)) >> 48)
    target = ref_target * factor
    shifts -= 16
    if shifts >= 256:
        return limit
    target = target >> -shifts if shifts <= 0 else target << shifts
    return max(1, min(target, limit))
