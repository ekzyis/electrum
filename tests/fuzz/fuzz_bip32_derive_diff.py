#!/usr/bin/env python3
# Differential fuzzer: Electrum vs. embit for BIP32 *child key derivation*.
#
# fuzz_bip32_diff.py only exercises xkey *parsing*; this harness fuzzes the
# derivation math itself -- CKD_priv / CKD_pub (bip32.py) -- which is where the
# real theft ceiling lives: Electrum (electrum_ecc / libsecp256k1) and embit
# (its own pure-python secp256k1) are independent down to the field arithmetic,
# so if they derive a *different* child from the same parent + path, a wallet
# would compute a different address than its counterparty -- silent loss of
# funds, not just a DoS.
#
# A random 32-byte string is almost never a valid xprv (checksum + privkey
# range), so instead of fuzzing an xkey we synthesise a *definitely valid*
# master directly: the scalar is folded into [1, n) and the 0x00 privkey prefix
# is set, so both libraries agree on the master by construction and every
# divergence is attributable to derivation, not parse strictness (the parse
# differences are already covered as F1/F2 in DIFFERENTIAL_FINDINGS.md).
#
# Oracles, per input:
#   1. private derivation   electrum.subkey_at_private_derivation(path).xprv
#                        == embit.derive(path).xprv                (hardened ok)
#   2. public derivation    for a non-hardened path, all three must be equal:
#        a) electrum private-derive then .to_xpub()
#        b) electrum public-derive (CKD_pub) .to_xpub()
#        c) embit  .to_public().derive(path).xprv-string
#      (a)==(b) is a self-referential check of Electrum's own CKD_pub vs CKD_priv
#      that holds even where embit would share a bug; (c) adds the cross-impl leg.
#
#   python tests/fuzz/fuzz_bip32_derive_diff.py tests/fuzz/corpus/bip32_derive_diff
#   python tests/fuzz/fuzz_bip32_derive_diff.py <crash-file>
import _harness as h

# instrument electrum_ecc too: its Python EC branches (point-at-infinity /
# curve-membership) gate CKD_pub, so coverage guidance benefits from them. The
# libsecp256k1 core underneath is C and stays opaque to Atheris regardless.
with h.instrument_imports(["electrum_ecc"]):
    import electrum_ecc as ecc
    from electrum.bip32 import BIP32Node
    from electrum.bitcoin import EncodeBase58Check

# Reference implementation (independent of Electrum; not instrumented).
from embit.bip32 import HDKey

XPRV_VERSION = bytes.fromhex("0488ade4")  # mainnet standard, private
MASTER_META = b"\x00" + b"\x00" * 4 + b"\x00" * 4  # depth=0, parent_fp=0, child=0
HARDENED = 0x80000000
CURVE_ORDER = ecc.CURVE_ORDER


class Divergence(Exception):
    """Electrum and the reference disagree on a derived child key."""


def _master_xprv(privkey: bytes, chaincode: bytes) -> str:
    # scalar folded into [1, n) so ECPrivkey always accepts -> identical master.
    scalar = int.from_bytes(privkey, "big") % (CURVE_ORDER - 1) + 1
    body = chaincode + b"\x00" + scalar.to_bytes(32, "big")
    return EncodeBase58Check(XPRV_VERSION + MASTER_META + body)


def _consume_path(fdp, *, allow_hardened: bool):
    n = fdp.ConsumeIntInRange(1, 6)
    path = []
    for _ in range(n):
        idx = int.from_bytes(fdp.ConsumeBytes(4), "little")
        if not allow_hardened:
            idx &= ~HARDENED  # clear the hardened bit -> pubkey-derivable
        path.append(idx)
    return path


def _el_priv(node, path):
    try:
        return True, node.subkey_at_private_derivation(path).to_xprv()
    except Exception:
        return False, None


def _em_priv(master, path):
    try:
        return True, master.derive(path).to_string()
    except Exception:
        return False, None


def TestOneInput(data: bytes):
    fdp = h.FuzzedDataProvider(data)
    privkey = fdp.ConsumeBytes(32)
    chaincode = fdp.ConsumeBytes(32)
    if len(privkey) < 32 or len(chaincode) < 32:
        return
    xprv = _master_xprv(privkey, chaincode)

    # both must accept the (valid-by-construction) master, else it's a parse
    # divergence -> out of scope here (see F1/F2), just skip.
    try:
        node = BIP32Node.from_xkey(xprv)
        master = HDKey.from_string(xprv)
    except Exception:
        return

    path = _consume_path(fdp, allow_hardened=True)

    # --- oracle 1: private derivation (hardened allowed) -------------------
    el_ok, el = _el_priv(node, path)
    em_ok, em = _em_priv(master, path)
    if el_ok != em_ok:
        raise Divergence(
            f"private-derive acceptance mismatch on {xprv} path={path}: "
            f"electrum={'ok' if el_ok else 'reject'} embit={'ok' if em_ok else 'reject'}")
    if el_ok and em_ok and el != em:
        raise Divergence(
            f"private-derive mismatch on {xprv} path={path}:\n"
            f"  electrum={el}\n  embit   ={em}")
    if not el_ok:
        return  # derivation failed in both (astronomically rare); nothing to compare

    # --- oracle 2: public derivation of the non-hardened prefix ------------
    # take the leading run of non-hardened indices (public derivation cannot
    # cross a hardened step).
    pub_path = []
    for idx in path:
        if idx & HARDENED:
            break
        pub_path.append(idx)
    if not pub_path:
        return

    try:
        a = node.subkey_at_private_derivation(pub_path).to_xpub()  # priv-derive -> xpub
        b = node.subkey_at_public_derivation(pub_path).to_xpub()   # CKD_pub path
    except Exception as e:
        raise Divergence(f"electrum xpub derivation raised on {xprv} pub_path={pub_path}: {e!r}")
    if a != b:
        raise Divergence(
            f"electrum CKD_pub != CKD_priv->xpub on {xprv} pub_path={pub_path}:\n"
            f"  priv->xpub={a}\n  pub -derive={b}")

    try:
        c = master.to_public().derive(pub_path).to_string()
    except Exception:
        c = None
    if c is not None and a != c:
        raise Divergence(
            f"public-derive mismatch on {xprv} pub_path={pub_path}:\n"
            f"  electrum={a}\n  embit   ={c}")


if __name__ == "__main__":
    h.run(TestOneInput, allowed=(), corpus_dir=h.corpus_dir("bip32_derive_diff"))
