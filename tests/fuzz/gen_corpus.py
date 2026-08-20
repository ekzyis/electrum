#!/usr/bin/env python3
#
# Seed tests/fuzz/corpus/* from known-good vectors so coverage ramps quickly.
#
#   python tests/fuzz/gen_corpus.py
import hashlib
import os

import _harness as h
from electrum.lnmsg import LNSerializer


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
