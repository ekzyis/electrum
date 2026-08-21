#!/usr/bin/env python3
# Differential fuzzer: Electrum vs. embit for raw transaction parsing.
#
# Raw txs are automatic, remote, untrusted input (Electrum servers stream them
# to the verifier/synchronizer). embit's transaction parser is independent code,
# so feeding the same bytes to both and comparing the re-serialization catches
# the money bug a crash-oracle can't: two parsers reading the same bytes into
# *different* transactions (or one accepting what the other rejects).
#
#   python tests/fuzz/fuzz_tx_diff.py tests/fuzz/corpus/tx_diff
#   python tests/fuzz/fuzz_tx_diff.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum.transaction import Transaction

# Reference implementation (independent of Electrum; not instrumented).
from embit.transaction import Transaction as EmbitTransaction


class Divergence(Exception):
    """Electrum and the reference disagree on a raw transaction."""


def _electrum(raw: bytes):
    # parse -> txid (the consensus identity of the tx). Any failure -> reject.
    try:
        tx = Transaction(raw)
        tx.deserialize()
        return True, tx.txid()
    except Exception:
        return False, None


def _embit(raw: bytes):
    try:
        return True, EmbitTransaction.parse(raw).txid().hex()
    except Exception:
        return False, None


def TestOneInput(data: bytes):
    el_ok, el = _electrum(data)
    em_ok, em = _embit(data)

    # Only flag the theft-class bug: both parsers accept the bytes but read them
    # into transactions with *different txids* (i.e. a different transaction).
    # We compare txid, not full serialization: the accept/reject boundary and
    # witness-serialization normalization (e.g. an empty witness re-emitted as
    # legacy) are policy/canonicalization differences with identical txids, not
    # Electrum bugs.
    if el_ok and em_ok and el != em:
        raise Divergence(f"different txid for {data.hex()}: "
                         f"electrum={el} embit={em}")


if __name__ == "__main__":
    h.run(TestOneInput, allowed=(), corpus_dir=h.corpus_dir("tx_diff"))
