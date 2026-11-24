# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading
import time
from typing import Optional, Dict, List, Mapping, Sequence, TYPE_CHECKING
from pathlib import Path

from . import util
from .bitcoin import hash_encode
from .crypto import sha256d
from . import auxpow
from . import constants
from .util import bfh, with_lock
from .logging import Logger

if TYPE_CHECKING:
    from .simple_config import SimpleConfig


HEADER_SIZE = 80  # bytes
CHUNK_SIZE = constants.HEADERS_CHUNK_SIZE  # num headers requested together
MAX_FUTURE_BLOCK_TIME = 20 * 60  # consensus allows 15 minutes under ASERT; tolerate a small local clock error
MEDIAN_TIME_SPAN = 11

# see https://github.com/bitcoin/bitcoin/blob/feedb9c84e72e4fff489810a2bbeec09bcda5763/src/chainparams.cpp#L76
MAX_TARGET = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff  # compact: 0x1d00ffff


class MissingHeader(Exception):
    pass


class InvalidHeader(Exception):
    pass


def serialize_header(header_dict: dict) -> bytes:
    s = (
        int.to_bytes(header_dict['version'], length=4, byteorder="little", signed=False)
        + bfh(header_dict['prev_block_hash'])[::-1]
        + bfh(header_dict['merkle_root'])[::-1]
        + int.to_bytes(int(header_dict['timestamp']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['bits']), length=4, byteorder="little", signed=False)
        + int.to_bytes(int(header_dict['nonce']), length=4, byteorder="little", signed=False))
    return s


def deserialize_header(s: bytes, height: int) -> dict:
    if not s:
        raise InvalidHeader('Invalid header: {}'.format(s))
    if len(s) < HEADER_SIZE:
        raise InvalidHeader('Invalid header length: {}'.format(len(s)))
    h = {}
    h['version'] = int.from_bytes(s[0:4], byteorder='little')
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = int.from_bytes(s[68:72], byteorder='little')
    h['bits'] = int.from_bytes(s[72:76], byteorder='little')
    h['nonce'] = int.from_bytes(s[76:80], byteorder='little')
    h['block_height'] = height
    if len(s) > HEADER_SIZE:
        # merge-mined: the proof of work follows the 80 bytes. It is checked once and not stored.
        if not auxpow.has_auxpow(h['version']):
            raise InvalidHeader('extra data after header')
        try:
            h['auxpow'] = auxpow.parse_auxpow(s[HEADER_SIZE:])
        except auxpow.AuxPowError as e:
            raise InvalidHeader(f'bad auxpow: {e}') from e
    return h


def hash_header(header: Optional[dict]) -> str:
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_raw_header(serialize_header(header))


def hash_raw_header(header: bytes) -> str:
    assert isinstance(header, bytes)
    return hash_encode(sha256d(header))


# block hash -> chain work above the max checkpoint, up to and including that block
_CHAINWORK_CACHE = {}  # type: Dict[str, int]


class BlockchainManager(Logger):

    def __init__(self, *, headers_dir: Path):
        Logger.__init__(self)
        self.headers_dir = headers_dir
        self.forks_dir = headers_dir / 'forks'
        util.make_dir(self.forks_dir)

        # key: blockhash hex at forkpoint
        # the chain at some key is the best chain that includes the given hash
        self.blockchains = {}  # type: Dict[str, Blockchain]
        self.blockchains_lock = threading.RLock()  # lock order: take this last; so after Blockchain.lock

        self._read_blockchains()
        self._init_headers_file_for_best_chain()
        self.logger.info(f"blockchains {list(map(lambda b: b.forkpoint, self.blockchains.values()))}")

    @classmethod
    def from_config(cls, config: 'SimpleConfig') -> 'BlockchainManager':
        headers_dir = util.get_headers_dir(config)
        return cls(headers_dir=Path(headers_dir))

    def _read_blockchains(self):
        best_chain = Blockchain(
            bc_mgr=self,
            forkpoint=0,
            parent=None,
            forkpoint_hash=constants.net.GENESIS,
            prev_hash=None,
        )
        self.blockchains[constants.net.GENESIS] = best_chain

        # consistency checks
        if best_chain.height() > constants.net.max_checkpoint():
            header_after_cp = best_chain.read_header(constants.net.max_checkpoint()+1)
            if not header_after_cp or not best_chain.can_connect(header_after_cp, check_height=False, check_pow=False):
                self.logger.warning("[blockchain] deleting best chain. cannot connect header after last cp to last cp.")
                best_chain.path().unlink()
                best_chain.update_size()

        # forks
        # files are named as: fork2_{forkpoint}_{prev_hash}_{first_hash}
        l = filter(lambda x: x.startswith('fork2_') and '.' not in x, os.listdir(self.forks_dir))
        l = sorted(l, key=lambda x: int(x.split('_')[1]))  # sort by forkpoint

        for filename in l:
            self._instantiate_chain(filename)

    def _instantiate_chain(self, filename: str):
        __, forkpoint, prev_hash, first_hash = filename.split('_')
        forkpoint = int(forkpoint)
        prev_hash = (64-len(prev_hash)) * "0" + prev_hash  # left-pad with zeroes
        first_hash = (64-len(first_hash)) * "0" + first_hash
        # forks below the max checkpoint are not allowed
        if forkpoint <= constants.net.max_checkpoint():
            self._delete_chain(filename, "deleting fork below max checkpoint")
            return
        # find parent (sorting by forkpoint guarantees it's already instantiated)
        for parent in self.blockchains.values():
            if parent.check_hash(forkpoint - 1, prev_hash):
                break
        else:
            self._delete_chain(filename, "cannot find parent for chain")
            return
        b = Blockchain(
            bc_mgr=self,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=first_hash,
            prev_hash=prev_hash,
        )
        # consistency checks
        h = b.read_header(b.forkpoint)
        if first_hash != hash_header(h):
            self._delete_chain(filename, "incorrect first hash for chain")
            return
        if not b.parent.can_connect(h, check_height=False, check_pow=False):
            self._delete_chain(filename, "cannot connect chain to parent")
            return
        chain_id = b.get_id()
        assert first_hash == chain_id, (first_hash, chain_id)
        self.blockchains[chain_id] = b

    def _delete_chain(self, filename: str, reason: str):
        self.logger.info(f"[blockchain] deleting chain {filename}: {reason}")
        file = self.forks_dir / filename
        file.unlink()

    def _init_headers_file_for_best_chain(self):
        b = self.get_best_chain()
        filename = b.path()
        length = HEADER_SIZE * len(constants.net.CHECKPOINTS) * CHUNK_SIZE
        if not filename.exists() or filename.stat().st_size < length:
            with open(filename, 'wb') as f:
                if length > 0:
                    f.seek(length - 1)
                    f.write(b'\x00')
            util.ensure_sparse_file(filename)
        with b.lock:
            b.update_size()

    def get_best_chain(self) -> 'Blockchain':
        return self.blockchains[constants.net.GENESIS]

    def check_header(self, header: dict) -> Optional['Blockchain']:
        """Returns any Blockchain that contains header, or None."""
        if type(header) is not dict:
            return None
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.check_header(header):
                return b
        return None

    def can_connect(self, header: dict) -> Optional['Blockchain']:
        """Returns the Blockchain that has a tip that directly links up
        with header, or None.
        """
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        for b in chains:
            if b.can_connect(header):
                return b
        return None

    def get_chains_that_contain_header(self, height: int, header_hash: str) -> Sequence['Blockchain']:
        """Returns a list of Blockchains that contain header, best chain first."""
        with self.blockchains_lock:
            chains = list(self.blockchains.values())
        chains = [chain for chain in chains
                  if chain.check_hash(height=height, header_hash=header_hash)]
        chains = sorted(chains, key=lambda x: x.get_chainwork(), reverse=True)
        return chains


class Blockchain(Logger):
    """
    Manages blockchain headers and their verification
    """

    def __init__(
        self,
        *,
        bc_mgr: 'BlockchainManager',
        forkpoint: int,
        parent: Optional['Blockchain'],
        forkpoint_hash: str,
        prev_hash: Optional[str],
    ):
        assert isinstance(forkpoint_hash, str) and len(forkpoint_hash) == 64, forkpoint_hash
        assert (prev_hash is None) or (isinstance(prev_hash, str) and len(prev_hash) == 64), prev_hash
        # assert (parent is None) == (forkpoint == 0)
        if 0 < forkpoint <= constants.net.max_checkpoint():
            raise Exception(f"cannot fork below max checkpoint. forkpoint: {forkpoint}")
        Logger.__init__(self)
        self.bc_mgr = bc_mgr
        if parent is not None:
            assert bc_mgr is parent.bc_mgr
        self.forkpoint = forkpoint  # height of first header
        self.parent = parent
        self._forkpoint_hash = forkpoint_hash  # blockhash at forkpoint. "first hash"
        self._prev_hash = prev_hash  # blockhash immediately before forkpoint
        self.lock = threading.RLock()
        self.update_size()

    @property
    def checkpoints(self):
        return constants.net.CHECKPOINTS

    def get_max_child(self) -> Optional[int]:
        children = self.get_direct_children()
        return max([x.forkpoint for x in children]) if children else None

    def get_max_forkpoint(self) -> int:
        """Returns the max height where there is a fork
        related to this chain.
        """
        mc = self.get_max_child()
        return mc if mc is not None else self.forkpoint

    def get_direct_children(self) -> Sequence['Blockchain']:
        with self.bc_mgr.blockchains_lock:
            return list(filter(lambda y: y.parent==self, self.bc_mgr.blockchains.values()))

    def get_parent_heights(self) -> Mapping['Blockchain', int]:
        """Returns map: (parent chain -> height of last common block)"""
        with self.lock, self.bc_mgr.blockchains_lock:
            result = {self: self.height()}
            chain = self
            while True:
                parent = chain.parent
                if parent is None: break
                result[parent] = chain.forkpoint - 1
                chain = parent
            return result

    def get_height_of_last_common_block_with_chain(self, other_chain: 'Blockchain') -> int:
        last_common_block_height = 0
        our_parents = self.get_parent_heights()
        their_parents = other_chain.get_parent_heights()
        for chain in our_parents:
            if chain in their_parents:
                h = min(our_parents[chain], their_parents[chain])
                last_common_block_height = max(last_common_block_height, h)
        return last_common_block_height

    @with_lock
    def get_branch_size(self) -> int:
        return self.height() - self.get_max_forkpoint() + 1

    def get_name(self) -> str:
        return self.get_hash(self.get_max_forkpoint()).lstrip('0')[0:10]

    def check_header(self, header: dict) -> bool:
        header_hash = hash_header(header)
        height = header.get('block_height')
        return self.check_hash(height, header_hash)

    def check_hash(self, height: int, header_hash: str) -> bool:
        """Returns whether the hash of the block at given height
        is the given hash.
        """
        assert isinstance(header_hash, str) and len(header_hash) == 64, header_hash  # hex
        try:
            return header_hash == self.get_hash(height)
        except Exception:
            return False

    def fork(parent, header: dict) -> 'Blockchain':
        if not parent.can_connect(header, check_height=False):
            raise Exception("forking header does not connect to parent chain")
        forkpoint = header.get('block_height')
        self = Blockchain(
            bc_mgr=parent.bc_mgr,
            forkpoint=forkpoint,
            parent=parent,
            forkpoint_hash=hash_header(header),
            prev_hash=parent.get_hash(forkpoint-1),
        )
        self.assert_headers_file_available(parent.path())
        open(self.path(), 'w+').close()
        self.save_header(header)
        # put into global dict. note that in some cases
        # save_header might have already put it there but that's OK
        chain_id = self.get_id()
        with parent.bc_mgr.blockchains_lock:
            parent.bc_mgr.blockchains[chain_id] = self
        return self

    @with_lock
    def height(self) -> int:
        return self.forkpoint + self.size() - 1

    @with_lock
    def size(self) -> int:
        return self._size

    @with_lock
    def update_size(self) -> None:
        p = self.path()
        self._size = os.path.getsize(p)//HEADER_SIZE if p.exists() else 0

    @classmethod
    def verify_header(cls, header: dict, prev_hash: str, target: int, expected_header_hash: str=None, *, check_pow: bool = True, prev_times: Sequence[int] = ()) -> None:
        _hash = hash_header(header)
        if expected_header_hash and expected_header_hash != _hash:
            raise InvalidHeader("hash mismatches with expected: {} vs {}".format(expected_header_hash, _hash))
        if prev_hash != header.get('prev_block_hash'):
            raise InvalidHeader("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.SKIP_POW_CHECK:
            return
        bits = cls.target_to_bits(target)
        if bits != header.get('bits'):
            raise InvalidHeader("bits mismatch: %s vs %s" % (bits, header.get('bits')))
        if header['timestamp'] > time.time() + MAX_FUTURE_BLOCK_TIME:
            # ASERT makes a block after a far-future one easier
            raise InvalidHeader("timestamp too far in the future. is the local clock correct?")
        if prev_times and header['timestamp'] <= sorted(prev_times)[len(prev_times) // 2]:
            raise InvalidHeader("timestamp not after the median of the previous blocks")
        version = header['version']
        if auxpow.has_auxpow(version):
            base_version = version & 0xff
        else:
            base_version = version if version < 1 << 31 else version - (1 << 32)
        if base_version < 4 and header['block_height'] > 0 and header['block_height'] > constants.net.max_checkpoint():
            raise InvalidHeader("outdated version")
        if not check_pow:  # loaded from disk: was checked before it was stored, without the auxpow
            return
        if auxpow.has_auxpow(header['version']):
            chain_id = constants.net.AUXPOW_CHAIN_ID
            if header['block_height'] < constants.net.AUXPOW_START_HEIGHT:
                raise InvalidHeader("auxpow before its start height")
            if auxpow.get_chain_id(header['version']) != chain_id:
                raise InvalidHeader("wrong chain ID")
            if 'auxpow' not in header:
                raise InvalidHeader("missing auxpow")
            try:
                parent_hash = auxpow.verify_auxpow(header['auxpow'], aux_hash=bfh(_hash)[::-1], chain_id=chain_id)
            except auxpow.AuxPowError as e:
                raise InvalidHeader(f"bad auxpow: {e}") from e
            pow_hash_as_num = int.from_bytes(parent_hash, byteorder='little')
        else:
            pow_hash_as_num = int.from_bytes(bfh(_hash), byteorder='big')
        if pow_hash_as_num > target:
            raise InvalidHeader(f"insufficient proof of work: {pow_hash_as_num} vs target {target}")

    def verify_chunk(self, index: int, headers: Sequence[bytes]) -> None:
        start_height = index * CHUNK_SIZE
        prev_hash = self.get_hash(start_height - 1)
        below_checkpoint = index < len(self.checkpoints)
        if below_checkpoint and len(headers) != CHUNK_SIZE:
            raise InvalidHeader("incomplete chunk below checkpoint")
        times = [] if below_checkpoint else self._get_prev_times(start_height)
        for i, raw_header in enumerate(headers):
            height = start_height + i
            try:
                expected_header_hash = self.get_hash(height)
            except MissingHeader:
                expected_header_hash = None
            header = deserialize_header(raw_header, height)
            if below_checkpoint:
                # The chunk must hash-link to the checkpoint at its end, which fixes every header.
                _hash = hash_header(header)
                if expected_header_hash and expected_header_hash != _hash:
                    raise InvalidHeader("hash mismatches with expected")
                if prev_hash != header['prev_block_hash']:
                    raise InvalidHeader("prev hash mismatch")
            else:
                target = self.get_target(height, prev_timestamp=times[-1] if times else None)
                self.verify_header(header, prev_hash, target, expected_header_hash, prev_times=times)
            prev_hash = hash_header(header)
            times = (times + [header['timestamp']])[-MEDIAN_TIME_SPAN:]

    @with_lock
    def path(self) -> Path:
        if self.parent is None:
            return self.bc_mgr.headers_dir / 'blockchain_headers'
        else:
            assert self.forkpoint > 0, self.forkpoint
            prev_hash = self._prev_hash.lstrip('0')
            first_hash = self._forkpoint_hash.lstrip('0')
            basename = f'fork2_{self.forkpoint}_{prev_hash}_{first_hash}'
            return self.bc_mgr.forks_dir / basename

    @with_lock
    def save_chunk(self, index: int, chunk: bytes):
        assert index >= 0, index
        chunk_within_checkpoint_region = index < len(self.checkpoints)
        # chunks in checkpoint region are the responsibility of the 'main chain'
        if chunk_within_checkpoint_region and self.parent is not None:
            main_chain = self.bc_mgr.get_best_chain()
            main_chain.save_chunk(index, chunk)
            return

        delta_height = (index * CHUNK_SIZE - self.forkpoint)
        delta_bytes = delta_height * HEADER_SIZE
        # if this chunk contains our forkpoint, only save the part after forkpoint
        # (the part before is the responsibility of the parent)
        if delta_bytes < 0:
            chunk = chunk[-delta_bytes:]
            delta_bytes = 0
        truncate = not chunk_within_checkpoint_region
        self.write(chunk, delta_bytes, truncate)
        self.swap_with_parent()

    def swap_with_parent(self) -> None:
        with self.lock, self.bc_mgr.blockchains_lock:
            # do the swap; possibly multiple ones
            cnt = 0
            while True:
                old_parent = self.parent
                if not self._swap_with_parent():
                    break
                # make sure we are making progress
                cnt += 1
                if cnt > len(self.bc_mgr.blockchains):
                    raise Exception(f'swapping fork with parent too many times: {cnt}')
                # we might have become the parent of some of our former siblings
                for old_sibling in old_parent.get_direct_children():
                    if self.check_hash(old_sibling.forkpoint - 1, old_sibling._prev_hash):
                        old_sibling.parent = self

    def _swap_with_parent(self) -> bool:
        """Check if this chain became stronger than its parent, and swap
        the underlying files if so. The Blockchain instances will keep
        'containing' the same headers, but their ids change and so
        they will be stored in different files."""
        if self.parent is None:
            return False
        if self.parent.get_chainwork() >= self.get_chainwork():
            return False
        self.logger.info(f"swapping {self.forkpoint} {self.parent.forkpoint}")
        parent_branch_size = self.parent.height() - self.forkpoint + 1
        forkpoint = self.forkpoint  # type: Optional[int]
        parent = self.parent  # type: Optional[Blockchain]
        child_old_id = self.get_id()
        parent_old_id = parent.get_id()
        # swap files
        # child takes parent's name
        # parent's new name will be something new (not child's old name)
        self.assert_headers_file_available(self.path())
        child_old_name = self.path()
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        assert forkpoint > parent.forkpoint, (f"forkpoint of parent chain ({parent.forkpoint}) "
                                              f"should be at lower height than children's ({forkpoint})")
        with open(parent.path(), 'rb') as f:
            f.seek((forkpoint - parent.forkpoint)*HEADER_SIZE)
            parent_data = f.read(parent_branch_size*HEADER_SIZE)
        self.write(parent_data, 0)
        parent.write(my_data, (forkpoint - parent.forkpoint)*HEADER_SIZE)
        # swap parameters
        self.parent, parent.parent = parent.parent, self  # type: Optional[Blockchain], Optional[Blockchain]
        self.forkpoint, parent.forkpoint = parent.forkpoint, self.forkpoint
        self._forkpoint_hash, parent._forkpoint_hash = parent._forkpoint_hash, hash_raw_header(parent_data[:HEADER_SIZE])
        self._prev_hash, parent._prev_hash = parent._prev_hash, self._prev_hash
        # parent's new name
        os.replace(child_old_name, parent.path())
        self.update_size()
        parent.update_size()
        # update pointers
        blockchains = self.bc_mgr.blockchains
        blockchains.pop(child_old_id, None)
        blockchains.pop(parent_old_id, None)
        blockchains[self.get_id()] = self
        blockchains[parent.get_id()] = parent
        return True

    def get_id(self) -> str:
        return self._forkpoint_hash

    def assert_headers_file_available(self, path: Path):
        if path.exists():
            return
        elif not self.bc_mgr.headers_dir.exists():
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    @with_lock
    def write(self, data: bytes, offset: int, truncate: bool = True, *, fsync: bool = True) -> None:
        filename = self.path()
        self.assert_headers_file_available(filename)
        with open(filename, 'rb+') as f:
            if truncate and offset != self._size * HEADER_SIZE:
                f.seek(offset)
                f.truncate()
            f.seek(offset)
            f.write(data)
            if fsync:
                f.flush()
                os.fsync(f.fileno())
        self.update_size()

    @with_lock
    def save_header(self, header: dict) -> None:
        delta = header.get('block_height') - self.forkpoint
        data = serialize_header(header)
        # headers are only _appended_ to the end:
        assert delta == self.size(), (delta, self.size())
        assert len(data) == HEADER_SIZE
        # note: we don't fsync, to improve perf. losing headers at end of file is ok.
        self.write(data, delta*HEADER_SIZE, fsync=False)
        self.swap_with_parent()

    @with_lock
    def read_header(self, height: int) -> Optional[dict]:
        if height < 0:
            return
        if height < self.forkpoint:
            return self.parent.read_header(height)
        if height > self.height():
            return
        delta = height - self.forkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(delta * HEADER_SIZE)
            h = f.read(HEADER_SIZE)
            if len(h) < HEADER_SIZE:
                raise Exception('Expected to read a full header. This was only {} bytes'.format(len(h)))
        if h == bytes([0])*HEADER_SIZE:
            return None
        return deserialize_header(h, height)

    def header_at_tip(self) -> Optional[dict]:
        """Return latest header."""
        height = self.height()
        return self.read_header(height)

    def is_tip_stale(self) -> bool:
        STALE_DELAY = 8 * 60 * 60  # in seconds
        header = self.header_at_tip()
        if not header:
            return True
        # note: We check the timestamp only in the latest header.
        #       The Bitcoin consensus has a lot of leeway here:
        #       - needs to be greater than the median of the timestamps of the past 11 blocks, and
        #       - up to at most 2 hours into the future compared to local clock
        #       so there is ~2 hours of leeway in either direction
        if header['timestamp'] + STALE_DELAY < time.time():
            return True
        return False

    def get_hash(self, height: int) -> str:
        def is_height_checkpoint():
            within_cp_range = height <= constants.net.max_checkpoint()
            at_chunk_boundary = (height+1) % CHUNK_SIZE == 0
            return within_cp_range and at_chunk_boundary

        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif is_height_checkpoint():
            index = height // CHUNK_SIZE
            h, _timestamp = self.checkpoints[index]
            return h
        else:
            header = self.read_header(height)
            if header is None:
                raise MissingHeader(height)
            return hash_header(header)

    def get_target(self, height: int, *, prev_timestamp: int = None) -> int:
        """Target for the block at height, above the max checkpoint. Uses the header before it."""
        net = constants.net
        if net.SKIP_POW_CHECK:
            return 0
        if height <= net.ASERT_ANCHOR_HEIGHT:
            if net.ASERT_ANCHOR_HEIGHT < 116 and net.TESTNET:
                return MAX_TARGET
            raise Exception("targets before ASERT are fixed by the checkpoints")
        if prev_timestamp is None:
            prev_timestamp = self._get_timestamp(height - 1)
        target = auxpow.asert_target(
            ref_target=self.bits_to_target(net.ASERT_ANCHOR_BITS),
            spacing=net.BLOCK_SPACING,
            time_diff=prev_timestamp - net.ASERT_ANCHOR_PARENT_TIME,
            height_diff=height - 1 - net.ASERT_ANCHOR_HEIGHT,
            limit=MAX_TARGET,
            half_life=net.ASERT_HALF_LIFE,
        )
        return self.bits_to_target(self.target_to_bits(target))

    def _get_prev_times(self, height: int) -> List[int]:
        """Timestamps of up to 11 blocks before height, oldest first."""
        if constants.net.SKIP_POW_CHECK:
            return []
        return [self._get_timestamp(h) for h in range(max(0, height - MEDIAN_TIME_SPAN), height)]

    def _get_timestamp(self, height: int) -> int:
        back = constants.net.max_checkpoint() - height
        if 0 <= back < len(constants.net.CHECKPOINT_TIMES):
            return constants.net.CHECKPOINT_TIMES[-1 - back]
        if height <= constants.net.max_checkpoint() and (height + 1) % CHUNK_SIZE == 0:
            _hash, timestamp = self.checkpoints[height // CHUNK_SIZE]
            return timestamp
        header = self.read_header(height)
        if header is None:
            raise MissingHeader(height)
        return header['timestamp']

    @classmethod
    def bits_to_target(cls, bits: int) -> int:
        # arith_uint256::SetCompact in Bitcoin Core
        if not (0 <= bits < (1 << 32)):
            raise InvalidHeader(f"bits should be uint32. got {bits!r}")
        bitsN = (bits >> 24) & 0xff
        bitsBase = bits & 0x7fffff
        if bitsN <= 3:
            target = bitsBase >> (8 * (3-bitsN))
        else:
            target = bitsBase << (8 * (bitsN-3))
        if target != 0 and bits & 0x800000 != 0:
            # Bit number 24 (0x800000) represents the sign of N
            raise InvalidHeader("target cannot be negative")
        if (target != 0 and
                (bitsN > 34 or
                 (bitsN > 33 and bitsBase > 0xff) or
                 (bitsN > 32 and bitsBase > 0xffff))):
            raise InvalidHeader("target has overflown")
        return target

    @classmethod
    def target_to_bits(cls, target: int) -> int:
        # arith_uint256::GetCompact in Bitcoin Core
        # see https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
        c = target.to_bytes(length=32, byteorder='big')
        bitsN = len(c)
        while bitsN > 0 and c[0] == 0:
            c = c[1:]
            bitsN -= 1
            if len(c) < 3:
                c += b'\x00'
        bitsBase = int.from_bytes(c[:3], byteorder='big')
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        return bitsN << 24 | bitsBase

    @with_lock
    def get_chainwork(self, height=None) -> int:
        """Work of the chain above the max checkpoint. All chains share everything up to it."""
        if height is None:
            height = max(0, self.height())
        if constants.net.SKIP_POW_CHECK:
            # On testnet/regtest, difficulty works somewhat different.
            # It's out of scope to properly implement that.
            return height
        base = constants.net.max_checkpoint()
        if height <= base:
            return 0
        # find the closest cached chunk boundary below
        cached = height // CHUNK_SIZE * CHUNK_SIZE - 1
        while cached > base and self.get_hash(cached) not in _CHAINWORK_CACHE:
            cached -= CHUNK_SIZE
        total = 0 if cached <= base else _CHAINWORK_CACHE[self.get_hash(cached)]
        for h in range(max(cached, base) + 1, height + 1):
            header = self.read_header(h)
            if header is None:
                raise MissingHeader(h)
            target = self.bits_to_target(header['bits'])
            total += ((2 ** 256 - target - 1) // (target + 1)) + 1
            if (h + 1) % CHUNK_SIZE == 0:
                _CHAINWORK_CACHE[hash_header(header)] = total
        return total

    def can_connect(self, header: Optional[dict], *, check_height: bool = True, check_pow: bool = True) -> bool:
        if header is None:
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except Exception:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        try:
            target = self.get_target(height)
            prev_times = self._get_prev_times(height)
        except MissingHeader:
            return False
        try:
            self.verify_header(header, prev_hash, target, check_pow=check_pow, prev_times=prev_times)
        except BaseException as e:
            self.logger.info(f'header {height} rejected: {e!r}')
            return False
        return True

    def connect_chunk(self, idx: int, headers: Sequence[bytes]) -> bool:
        assert idx >= 0, idx
        try:
            self.verify_chunk(idx, headers)
            self.save_chunk(idx, b"".join(h[:HEADER_SIZE] for h in headers))
            return True
        except BaseException as e:
            self.logger.info(f'verify_chunk idx {idx} failed: {repr(e)}')
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash and the timestamp of its last block
        cp = []
        n = (self.height() + 1) // CHUNK_SIZE
        for index in range(n):
            height = (index + 1) * CHUNK_SIZE - 1
            cp.append((self.get_hash(height), self._get_timestamp(height)))
        return cp
