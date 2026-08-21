#!/usr/bin/env python3
# Differential / correctness fuzzer for Electrum's SPV merkle-proof verifier.
#
# A merkle branch is *automatic, remote, untrusted* input: an Electrum server
# streams `(pos, merkle_branch)` for each of the wallet's txs and Electrum
# decides "this tx is in the block with root R" (verifier.py:_request_and_
# verify_single_proof -> verify_tx_is_in_block -> SPV.hash_merkle_root). A bug
# here is not a DoS: it lets a malicious server *forge inclusion* of a tx that
# isn't in the block (or hide one that is) -> the wallet shows fake confirmations
# / wrong history. That is the money bug, and a crash oracle can't see it.
#
# There is no independent merkle implementation in embit to diff against, so the
# "reference" here is a from-scratch, full-tree Bitcoin-consensus merkle builder
# (below). Because we build the whole tree we know the *true* root and the *one*
# genuine authentication branch for a leaf, which lets us assert two properties
# a self-contained oracle can check without a second library:
#
#   completeness — the genuine branch MUST verify against the true root, and
#                  SPV.hash_merkle_root MUST return exactly the reference root
#                  (catches byte-order / odd-node-duplication / index-shift bugs);
#   soundness    — any *forged* branch/pos/txid (!= the genuine one) MUST be
#                  rejected against the true root (catches structural bypasses of
#                  the hash chain: bad final-index check, length handling, etc).
#
#   python tests/fuzz/fuzz_merkle_diff.py tests/fuzz/corpus/merkle_diff
#   python tests/fuzz/fuzz_merkle_diff.py <crash-file>
import hashlib

import _harness as h

with h.instrument_imports():
    from electrum.bitcoin import hash_encode
    from electrum.verifier import (
        SPV, verify_tx_is_in_block,
        MerkleVerificationFailure, InnerNodeOfSpvProofIsValidTx,
    )


class Divergence(Exception):
    """Electrum's SPV verifier violated completeness or soundness."""


# --- independent Bitcoin-consensus merkle reference ------------------------
# All hashes here are in *internal* (little-endian) byte order, like Bitcoin
# consensus code. Electrum's API speaks display-order hex, so we hash_encode()
# at the boundary.

def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _root_and_branch(leaves, pos):
    """Return (root, branch) for leaf `pos`, all in internal byte order.

    Mirrors Bitcoin's merkle tree: odd layers duplicate the last node; the
    branch is the sequence of siblings from the leaf up to the root.
    """
    branch = []
    layer = list(leaves)
    index = pos
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # duplicate last node (consensus rule)
        sib = layer[index + 1] if index % 2 == 0 else layer[index - 1]
        branch.append(sib)
        layer = [_sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
        index //= 2
    return layer[0], branch


def _gen_leaves(seed: bytes, n: int):
    # n distinct 32-byte leaf txids (internal order). Distinct so that a genuine
    # proof never legitimately trips the CVE-2012-2459 left-sibling-duplicate
    # guard (adjacent equal leaves), keeping the completeness oracle clean.
    return [hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(n)]


def _verifies(txid_disp, branch_disp, pos, root_disp):
    """True iff Electrum accepts (txid, branch, pos) as proving membership in a
    block whose merkle_root is root_disp. Any MerkleVerificationFailure -> reject.
    """
    try:
        verify_tx_is_in_block(txid_disp, branch_disp, pos,
                              {"merkle_root": root_disp}, 0)
        return True
    except MerkleVerificationFailure:
        return False


def TestOneInput(data: bytes):
    fdp = h.FuzzedDataProvider(data)
    n = fdp.ConsumeIntInRange(1, 300)
    pos = fdp.ConsumeIntInRange(0, n - 1)
    seed = fdp.ConsumeBytes(8)

    leaves = _gen_leaves(seed, n)
    root, branch = _root_and_branch(leaves, pos)
    root_disp = hash_encode(root)
    txid_disp = hash_encode(leaves[pos])
    branch_disp = [hash_encode(s) for s in branch]

    # --- oracle 1: completeness + differential root ------------------------
    # The genuine branch must reproduce exactly the reference root, and must
    # verify. (The rare CVE-2017-12842 guard firing on a random 64-byte inner
    # node that happens to parse as a tx is a legitimate rejection, not a bug,
    # so we let it pass.)
    try:
        got = SPV.hash_merkle_root(branch_disp, txid_disp, pos)
    except InnerNodeOfSpvProofIsValidTx:
        return  # benign: protection fired on a coincidental valid-tx inner node
    except MerkleVerificationFailure as e:
        raise Divergence(f"genuine proof rejected (n={n} pos={pos}): {e!r}")
    if got != root_disp:
        raise Divergence(
            f"root mismatch (n={n} pos={pos}): electrum={got} reference={root_disp}")

    # --- oracle 2: soundness ----------------------------------------------
    # Forge the proof and demand rejection against the *true* root. Any accept
    # of a non-genuine (txid, branch, pos) is a forged-inclusion bug.
    for f_txid, f_branch, f_pos in _forgeries(fdp, leaves, pos, branch, n):
        if (f_txid, f_branch, f_pos) == (txid_disp, branch_disp, pos):
            continue  # mutation was a no-op
        try:
            if _verifies(f_txid, f_branch, f_pos, root_disp):
                raise Divergence(
                    f"forged proof accepted against true root {root_disp}: "
                    f"txid={f_txid} pos={f_pos} branch={f_branch}")
        except InnerNodeOfSpvProofIsValidTx:
            pass  # protection fired -> rejected, which is the safe outcome


def _forgeries(fdp, leaves, pos, branch, n):
    """Yield a handful of forged (txid_disp, branch_disp, pos) variants derived
    from the remaining fuzz bytes."""
    branch_disp = [hash_encode(s) for s in branch]
    txid_disp = hash_encode(leaves[pos])

    # (a) wrong position (same branch/txid)
    if n > 1:
        alt = fdp.ConsumeIntInRange(0, n - 1)
        yield txid_disp, list(branch_disp), alt

    # (b) wrong leaf txid (claim a different tx is at this position)
    if n > 1:
        j = fdp.ConsumeIntInRange(0, n - 1)
        yield hash_encode(leaves[j]), list(branch_disp), pos

    # (c) drop a branch element
    if branch_disp:
        k = fdp.ConsumeIntInRange(0, len(branch_disp) - 1)
        yield txid_disp, branch_disp[:k] + branch_disp[k + 1:], pos

    # (d) flip a byte in a branch element
    if branch_disp:
        k = fdp.ConsumeIntInRange(0, len(branch_disp) - 1)
        b = bytearray(bytes.fromhex(branch_disp[k]))
        b[fdp.ConsumeIntInRange(0, 31)] ^= 0xff
        mutated = list(branch_disp)
        mutated[k] = b.hex()
        yield txid_disp, mutated, pos

    # (e) empty branch (only valid when the tx is the single leaf of its block)
    yield txid_disp, [], pos


if __name__ == "__main__":
    h.run(TestOneInput, allowed=(), corpus_dir=h.corpus_dir("merkle_diff"))
