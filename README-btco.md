# Electrum for BitcoinOil (BTCO), test version

Based on Electrum 4.8.4. Not released: do not use it with real funds yet.

- Checkpoints every 500 blocks up to 157499. From block 157500 the wallet checks the
  ASERT difficulty and the proof of work of every header, including merge-mined (AuxPoW) ones.
- Needs a server with Electrum protocol 1.6, from https://github.com/Pan0ramix/btco-explorer
  There is no default server yet: use `--oneserver --server HOST:50002:s`.
- Transparent addresses only. Peg-outs from MWEB can be received and spent after 6 blocks.
  MWEB addresses are not supported.
- Off: Lightning, swaps, fiat prices, hardware wallets and 2FA.
- BIP44 coin type 0, the same derivation as Bitcoin. Do not reuse a Bitcoin seed.

Test: `pytest tests/test_btco.py tests/test_blockchain.py tests/test_interface.py`.
Many other upstream tests fail because they contain Bitcoin addresses, keys and amounts.
