#!/usr/bin/env python3
# Fuzz Electrum transaction / PSBT deserialization via tx_from_any().
#
#   python tests/fuzz/fuzz_tx.py tests/fuzz/corpus/tx
#   python tests/fuzz/fuzz_tx.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum.transaction import (
        tx_from_any, PartialTransaction, SerializationError)

# tx_from_any funnels malformed input into SerializationError.
ALLOWED = (SerializationError,)


def _serialize(tx):
    if isinstance(tx, PartialTransaction):
        return tx.serialize_as_bytes()
    return bytes.fromhex(tx.serialize())


def TestOneInput(data: bytes):
    tx = tx_from_any(data, deserialize=True)
    # Whatever parsed must survive a serialize -> parse roundtrip unchanged.
    try:
        raw = _serialize(tx)
    except SerializationError:
        return  # incomplete PSBT that can't be serialized yet
    assert _serialize(tx_from_any(raw, deserialize=True)) == raw


if __name__ == "__main__":
    h.run(TestOneInput, allowed=ALLOWED, corpus_dir=h.corpus_dir("tx"))
