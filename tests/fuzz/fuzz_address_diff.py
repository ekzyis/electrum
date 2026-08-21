#!/usr/bin/env python3
# Differential fuzzer: Electrum vs. embit
#
#   python tests/fuzz/fuzz_address_diff.py tests/fuzz/corpus/address_diff
#   python tests/fuzz/fuzz_address_diff.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum import constants
    from electrum.bitcoin import address_to_script

# Reference implementation.
import embit.script as embit_script


class Divergence(Exception):
    """Electrum and the reference disagree on a mainnet address."""


def _electrum(addr: str):
    try:
        return True, bytes(address_to_script(addr))
    except Exception:
        return False, None


def _embit(addr: str):
    try:
        return True, bytes(embit_script.address_to_scriptpubkey(addr).data)
    except Exception:
        return False, None


def _mainnet_plausible(addr: str) -> bool:
    # electrum only accepts mainnet so skip any testnet address
    low = addr.lower()
    return low.startswith("bc1") or addr[:1] in ("1", "3")


def _embit_rejects_uppercase_bech32(addr, el_ok, em_ok, el, em) -> bool:
    # ignore embit rejecting all-uppercase bech32 address
    return (el_ok and not em_ok
            and addr == addr.upper()
            and addr.lower().startswith("bc1"))


# Known-benign acceptance divergences, filled in as they are triaged. Each entry
# is a predicate (addr, el_ok, em_ok, el, em) -> bool; returning True suppresses.
_SUPPRESS = [
    _embit_rejects_uppercase_bech32,
]


def _suppressed(addr, el_ok, em_ok, el, em) -> bool:
    return any(pred(addr, el_ok, em_ok, el, em) for pred in _SUPPRESS)


def TestOneInput(data: bytes):
    try:
        addr = data.decode("ascii")
    except UnicodeDecodeError:
        return  # addresses are ASCII
    addr = addr.strip()
    if not addr or not _mainnet_plausible(addr):
        return

    el_ok, el = _electrum(addr)
    em_ok, em = _embit(addr)

    if el_ok and em_ok:
        if el != em:
            # both accept, different script: this is the theft-class bug.
            raise Divergence(
                f"different script for {addr!r}: electrum={el.hex()} embit={em.hex()}")
        return
    if not el_ok and not em_ok:
        return  # both reject: agreement
    # exactly one accepts: strictness divergence
    if _suppressed(addr, el_ok, em_ok, el, em):
        return
    raise Divergence(
        f"acceptance mismatch for {addr!r}: "
        f"electrum={'accept ' + el.hex() if el_ok else 'reject'}, "
        f"embit={'accept ' + em.hex() if em_ok else 'reject'}")


if __name__ == "__main__":
    # allowed=(): any exception (i.e. any Divergence) is a finding.
    h.run(TestOneInput, allowed=(), corpus_dir=h.corpus_dir("address_diff"))
