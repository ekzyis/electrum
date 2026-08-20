#!/usr/bin/env python3
# Fuzz Electrum BOLT-11 invoice decoding via decode_bolt11_invoice().
#
#   python tests/fuzz/fuzz_bolt11.py tests/fuzz/corpus/bolt11
#   python tests/fuzz/fuzz_bolt11.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum import constants
    from electrum.segwit_addr import Encoding, bech32_encode, convertbits
    from electrum.bolt11 import decode_bolt11_invoice, BOLT11InvoiceException
    from electrum.lnutil import IncompatibleOrInsaneFeatures

# decode_bolt11_invoice documents these as its only failure modes.
ALLOWED = (BOLT11InvoiceException, IncompatibleOrInsaneFeatures)

# amount suffix of the HRP: digits and multiplier letters
_AMOUNT_CHARS = "0123456789munp"


def TestOneInput(data: bytes):
    fdp = h.FuzzedDataProvider(data)
    amount = "".join(_AMOUNT_CHARS[b % len(_AMOUNT_CHARS)]
                     for b in fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 8)))
    data5 = convertbits(fdp.ConsumeBytes(fdp.remaining_bytes()), 8, 5)
    invoice = bech32_encode(Encoding.BECH32, "lnbc" + amount, data5)
    decode_bolt11_invoice(invoice, net=constants.net)


if __name__ == "__main__":
    h.run(TestOneInput, allowed=ALLOWED, corpus_dir=h.corpus_dir("bolt11"))
