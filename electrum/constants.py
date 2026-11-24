# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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

import copy
import os
import json
from typing import Sequence, Tuple, Mapping, Type, List, Optional

from .lntransport import LNPeerAddr
from .util import inv_dict, all_subclasses, classproperty
from . import bitcoin


def read_json(filename, default=None):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except Exception:
        if default is None:
            # Sometimes it's better to hard-fail: the file might be missing
            # due to a packaging issue, which might otherwise go unnoticed.
            raise
        r = default
    return r


def create_fallback_node_list(fallback_nodes_dict: dict[str, dict]) -> List[LNPeerAddr]:
    """Take a json dict of fallback nodes like: k:node_id, v:{k:'host', k:'port'} and return LNPeerAddr list"""
    fallback_nodes = []
    for node_id, address in fallback_nodes_dict.items():
        fallback_nodes.append(
            LNPeerAddr(host=address['host'], port=int(address['port']), pubkey=bytes.fromhex(node_id)))
    return fallback_nodes


GIT_REPO_URL = "https://github.com/Pan0ramix/electrum-btco"
GIT_REPO_ISSUES_URL = "https://github.com/Pan0ramix/electrum-btco/issues"
RELEASE_NOTES_URL = "https://raw.githubusercontent.com/Pan0ramix/electrum-btco/refs/heads/btco/RELEASE-NOTES"
BIP39_WALLET_FORMATS = read_json('bip39_wallet_formats.json')


# num headers per checkpoint. 157500 (ASERT activation) is a multiple.
HEADERS_CHUNK_SIZE = 500


class AbstractNet:

    NET_NAME: str
    SKIP_POW_CHECK: bool = False
    TESTNET: bool
    WIF_PREFIX: int
    ADDRTYPE_P2PKH: int
    ADDRTYPE_P2SH: int
    SEGWIT_HRP: str
    BOLT11_HRP: str
    GENESIS: str
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS: int = 0
    BIP44_COIN_TYPE: int
    LN_REALM_BYTE: int
    LIGHTNING_SUPPORTED: bool = False  # BitcoinOil has no Lightning network
    DEFAULT_PORTS: Mapping[str, str]
    LN_DNS_SEEDS: Sequence[str]
    XPRV_HEADERS: Mapping[str, int]
    XPRV_HEADERS_INV: Mapping[int, str]
    XPUB_HEADERS: Mapping[str, int]
    XPUB_HEADERS_INV: Mapping[int, str]

    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.CHECKPOINTS) * HEADERS_CHUNK_SIZE - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(cls.GENESIS)[::-1]

    @classmethod
    def set_as_network(cls) -> None:
        global net
        net = cls

    _cached_default_servers = None
    @classproperty
    def DEFAULT_SERVERS(cls) -> Mapping[str, Mapping[str, str]]:
        if cls._cached_default_servers is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            d = read_json(os.path.join('chains', cls.NET_NAME, 'servers.json'), default_file)
            # sanity check
            for k, v in d.items():
                assert isinstance(v, dict), f'value for {k} not a dict in servers.json'
                assert all(isinstance(v2, str) for v2 in v.values()), f'non-str values for key {k} in servers.json'
            cls._cached_default_servers = d
        return copy.deepcopy(cls._cached_default_servers)

    _cached_fallback_lnnodes = None
    @classproperty
    def FALLBACK_LN_NODES(cls) -> Sequence[LNPeerAddr]:
        if cls._cached_fallback_lnnodes is None:
            default_file = {} if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            d = read_json(os.path.join('chains', cls.NET_NAME, 'fallback_lnnodes.json'), default_file)
            cls._cached_fallback_lnnodes = create_fallback_node_list(d)
        return cls._cached_fallback_lnnodes

    _cached_checkpoints = None
    @classproperty
    def CHECKPOINTS(cls) -> Sequence[Tuple[str, int]]:
        if cls._cached_checkpoints is None:
            default_file = [] if cls.TESTNET else None  # for mainnet we hard-fail if the file is missing.
            cls._cached_checkpoints = read_json(os.path.join('chains', cls.NET_NAME, 'checkpoints.json'), default_file)
        return cls._cached_checkpoints

    @classmethod
    def datadir_subdir(cls) -> Optional[str]:
        """The name of the folder in the filesystem.
        None means top-level, used by mainnet.
        """
        return cls.NET_NAME

    @classmethod
    def cli_flag(cls) -> str:
        """as used in e.g. `$ run_electrum --testnet4`"""
        return cls.NET_NAME

    @classmethod
    def config_key(cls) -> str:
        """as used for SimpleConfig.get()"""
        return cls.NET_NAME


class BitcoinMainnet(AbstractNet):

    NET_NAME = "mainnet"
    TESTNET = False
    WIF_PREFIX = 153
    ADDRTYPE_P2PKH = 26
    ADDRTYPE_P2SH = 25
    SEGWIT_HRP = "btco"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "00000000baccc78f2852f3943bb19ff89df6d374252e72f6b487e68c0d839d54"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS = 497000

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 0
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = []

    AUXPOW_CHAIN_ID = 0x0B0C
    AUXPOW_START_HEIGHT = 155000
    BLOCK_SPACING = 6 * 60
    ASERT_ANCHOR_HEIGHT = 157499  # last block before ASERT
    ASERT_ANCHOR_BITS = 0x1904e74a
    ASERT_ANCHOR_PARENT_TIME = 1795447755  # timestamp of block 157498
    ASERT_HALF_LIFE = 2 * 60 * 60
    # timestamps of the 11 blocks up to the max checkpoint, for the median time rule
    CHECKPOINT_TIMES = (
        1795445038, 1795445224, 1795445761, 1795446601, 1795446603, 1795446717,
        1795446917, 1795446989, 1795447732, 1795447755, 1795448307,
    )

    @classmethod
    def datadir_subdir(cls):
        return None


class BitcoinTestnet(AbstractNet):

    NET_NAME = "testnet"
    TESTNET = True
    WIF_PREFIX = 178
    ADDRTYPE_P2PKH = 51
    ADDRTYPE_P2SH = 50
    SEGWIT_HRP = "tbtco"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "00000000f130184486dad044d14fff1d39665f09551dfafccd5a8f938c05df57"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh':  0x024285b5,  # Uprv
        'p2wpkh':      0x045f18bc,  # vprv
        'p2wsh':       0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh':  0x024289ef,  # Upub
        'p2wpkh':      0x045f1cf6,  # vpub
        'p2wsh':       0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 1

    AUXPOW_CHAIN_ID = 0x0B0C
    AUXPOW_START_HEIGHT = 0
    BLOCK_SPACING = 6 * 60
    ASERT_ANCHOR_HEIGHT = 109  # LWMA gives the easiest target below its window of 116 blocks
    ASERT_ANCHOR_BITS = 0x1d00ffff
    ASERT_ANCHOR_PARENT_TIME = 1795058918  # timestamp of block 108
    ASERT_HALF_LIFE = 2 * 60 * 60
    CHECKPOINT_TIMES = ()
    LN_REALM_BYTE = 1
    LN_DNS_SEEDS = [  # TODO investigate this again
        #'test.nodes.lightning.directory.',  # times out.
        #'lseed.bitcoinstats.com.',  # ignores REALM byte and returns mainnet peers...
    ]


class BitcoinRegtest(BitcoinTestnet):

    NET_NAME = "regtest"
    SKIP_POW_CHECK = True
    SEGWIT_HRP = "rbtco"
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "1d58cac6acc090fa7089c03657b2368f6eb16dfc588f577de01394ae9ce75ab3"
    LN_DNS_SEEDS = []


NETS_LIST = tuple(all_subclasses(AbstractNet))  # type: Sequence[Type[AbstractNet]]
NETS_LIST = tuple(sorted(NETS_LIST, key=lambda x: x.NET_NAME))

assert len(NETS_LIST) == len(set([chain.NET_NAME for chain in NETS_LIST])), "NET_NAME must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.datadir_subdir() for chain in NETS_LIST])), "datadir must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.cli_flag() for chain in NETS_LIST])), "cli_flag must be unique for each concrete AbstractNet"
assert len(NETS_LIST) == len(set([chain.config_key() for chain in NETS_LIST])), "config_key must be unique for each concrete AbstractNet"

# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinMainnet  # type: Type[AbstractNet]
