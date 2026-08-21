#!/usr/bin/env python3
# Differential fuzzer: Electrum vs. embit for BIP32 extended-key parsing.
#
# Electrum (electrum_ecc / libsecp256k1) and embit (its own ec.py) are fully
# independent implementations down to the elliptic-curve math, so a disagreement
# on an xpub/xprv -- e.g. one accepting a key off the curve or a scalar >= n, or
# deriving a different pubkey -- would be a real crypto divergence.
#
# base58check has a 32-bit checksum a mutator can't satisfy by chance, so the
# fuzzer bytes are treated as the *payload* and a valid checksum is appended, so
# exploration lands in key validation rather than bouncing off the checksum.
#
# We pin the version to a standard mainnet header AND the metadata (depth /
# parent-fingerprint / child-number) to the valid master-key values, then fuzz
# only the chaincode + key material. That focuses divergences on the part where
# the implementations are genuinely independent -- the elliptic-curve validation
# of the key -- instead of BIP32 metadata-strictness policy (e.g. whether a
# depth-0 key is allowed a non-zero child index), which is low-value noise.
#
#   python tests/fuzz/fuzz_bip32_diff.py tests/fuzz/corpus/bip32_diff
#   python tests/fuzz/fuzz_bip32_diff.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum.bip32 import BIP32Node
    from electrum.bitcoin import EncodeBase58Check

# Reference implementation (independent of Electrum; not instrumented).
from embit.bip32 import HDKey

XPUB_VERSION = bytes.fromhex("0488b21e")  # mainnet standard, public
XPRV_VERSION = bytes.fromhex("0488ade4")  # mainnet standard, private
MASTER_META = b"\x00" + b"\x00" * 4 + b"\x00" * 4  # depth=0, parent_fp=0, child=0


class Divergence(Exception):
    """Electrum and the reference disagree on an extended key."""


def _electrum(xkey: str):
    try:
        node = BIP32Node.from_xkey(xkey)
        return True, node.to_xprv() if node.is_private() else node.to_xpub()
    except Exception:
        return False, None


def _embit(xkey: str):
    try:
        return True, HDKey.from_string(xkey).to_string()
    except Exception:
        return False, None


def TestOneInput(data: bytes):
    if not data:
        return
    version = XPRV_VERSION if data[0] & 1 else XPUB_VERSION
    payload = version + MASTER_META + data[1:]  # body: chaincode(32) + key(33)
    xkey = EncodeBase58Check(payload)

    el_ok, el = _electrum(xkey)
    em_ok, em = _embit(xkey)

    if el_ok and em_ok:
        if el != em:
            # both parse, but to different extended keys: the crypto-divergence bug.
            raise Divergence(f"different reencoding for {xkey}: "
                             f"electrum={el} embit={em}")
        return
    if not el_ok and not em_ok:
        return  # both reject: agreement
    raise Divergence(
        f"acceptance mismatch for {xkey}: "
        f"electrum={'accept ' + el if el_ok else 'reject'}, "
        f"embit={'accept ' + em if em_ok else 'reject'}")


if __name__ == "__main__":
    h.run(TestOneInput, allowed=(), corpus_dir=h.corpus_dir("bip32_diff"))
