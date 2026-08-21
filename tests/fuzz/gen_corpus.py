#!/usr/bin/env python3
#
# Seed tests/fuzz/corpus/* from known-good vectors so coverage ramps quickly.
#
#   python tests/fuzz/gen_corpus.py
import hashlib
import os

import _harness as h
from electrum.lnmsg import LNSerializer
from electrum.bip32 import BIP32Node
from electrum.bitcoin import DecodeBase58Check


def write(subdir, data):
    d = h.corpus_dir(subdir)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, hashlib.sha1(data).hexdigest()[:16]), "wb") as f:
        f.write(data)


# tx: legacy p2pkh spend (from tests/test_transaction.py)
write("tx", bytes.fromhex(
    "01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb40"
    "31000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76e"
    "c764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bf"
    "b1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227ba"
    "e35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef84"
    "14ae929feaafc388ac00000000"))

# lnmsg: a handful of common message types
ser = LNSerializer()
for msg_type, kwargs in [
    ("init", dict(gflen=0, globalfeatures=b"", flen=1, features=b"\x82")),
    ("error", dict(channel_id=b"\x00" * 32, len=5, data=b"hello")),
    ("ping", dict(num_pong_bytes=4, byteslen=2, _ignored_bytes=b"\x00\x00")),
    ("pong", dict(byteslen=2, ignored=b"\x00\x00")),
]:
    write("lnmsg", ser.encode_msg(msg_type, **kwargs))

# bolt11: mainnet invoice from the BOLT-11 spec
write("bolt11", (
    "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq"
    "dq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2aw"
    "hz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp"
).encode("ascii"))

# address_diff: one canonical mainnet address of each type Electrum understands
for addr in [
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",                                # P2PKH
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",                                # P2SH
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                        # v0 P2WPKH
    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",    # v0 P2WSH
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",    # v1 P2TR
]:
    write("address_diff", addr.encode("ascii"))

# tx_diff: a legacy and a segwit tx (raw bytes fed straight to both parsers)
write("tx_diff", bytes.fromhex(
    "01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb40"
    "31000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76e"
    "c764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bf"
    "b1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227ba"
    "e35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef84"
    "14ae929feaafc388ac00000000"))
write("tx_diff", bytes.fromhex(
    "02000000000101a97a9ae7fb1a9220fdd170a974987ac24631dcff89b60fa4907c78c363"
    "9994db0000000000fdffffff0210270000000000001976a914ea7804a2c266063572cc00"
    "9a63dc25dcc0e9d9b588ac20491e0000000000160014b8e4fdc91593b67de2bf214694ef"
    "47e38dc2ee8e02473044022005326882904906cfa9c1de75333ace1019596f2ab25d2111"
    "8220d037dfc0e48b02207d0b3f075cfe5e1e0247ff3cdd7155dc05e7459daf1bfa0ea02e"
    "9112b9151ec90121026cc6a74c2b0e38661d341ffae48fe7dde5196ca4afe95d28b49667"
    "3fa4cf646700000000"))

# bip32_diff: harness input is (version-selector byte || chaincode(32) + key(33));
# the harness pins version + metadata, so seed with the chaincode+key of a valid
# mainnet master xpub/xprv (payload bytes 13:78) so coverage ramps past length checks.
_seed = BIP32Node.from_rootseed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), xtype="standard")
write("bip32_diff", b"\x00" + DecodeBase58Check(_seed.to_xpub())[13:])   # even selector -> xpub
write("bip32_diff", b"\x01" + DecodeBase58Check(_seed.to_xprv())[13:])   # odd selector  -> xprv
