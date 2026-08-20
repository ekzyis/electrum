#!/usr/bin/env python3
# Fuzz Electrum Lightning wire-message decoding via LNSerializer.decode_msg().
#
#   python tests/fuzz/fuzz_lnmsg.py tests/fuzz/corpus/lnmsg
#   python tests/fuzz/fuzz_lnmsg.py <crash-file>
import _harness as h

with h.instrument_imports():
    from electrum.lnmsg import LNSerializer, FailedToParseMsg

_ser = LNSerializer()
ALLOWED = (FailedToParseMsg,)


def TestOneInput(data: bytes):
    # Wire messages are length-prefixed and always carry a 2-byte type;
    # decode_msg assumes as much, so shorter inputs aren't meaningful here.
    if len(data) < 2:
        return
    name, parsed = _ser.decode_msg(data)
    # Re-encoding and decoding again must reproduce the same message.
    assert _ser.decode_msg(_ser.encode_msg(name, **parsed)) == (name, parsed)


if __name__ == "__main__":
    h.run(TestOneInput, allowed=ALLOWED, corpus_dir=h.corpus_dir("lnmsg"))
