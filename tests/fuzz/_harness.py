# Shared plumbing for the Electrum fuzz harnesses. Each harness defines
# TestOneInput(data) and calls run().
#
# The wrapper swallows the parser's expected rejection exceptions (the `allowed`
# tuple) and treats anything else as a finding, so keep the allow-lists tight.
#
# With Atheris installed this is a normal coverage-guided libFuzzer target.
# Without it, run() replays the seed corpus and does dumb mutation instead:
# enough to smoke-test the harness and to reproduce a saved crash file.

import glob
import hashlib
import os
import random
import sys
import traceback
from contextlib import nullcontext

try:
    import atheris
except ImportError:
    atheris = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def instrument_imports(extra=()):
    """Instrument electrum for coverage (no-op without Atheris)."""
    include = ["electrum", *extra]
    return atheris.instrument_imports(include=include) if atheris else nullcontext()


def corpus_dir(name):
    return os.path.join(SCRIPT_DIR, "corpus", name)


def crashes_dir(name):
    d = os.path.join(SCRIPT_DIR, "crashes", name)
    os.makedirs(d, exist_ok=True)
    return d


def _harness_name():
    # fuzz_bolt11.py -> bolt11, so crashes land in crashes/bolt11/
    stem = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    return stem[len("fuzz_"):] if stem.startswith("fuzz_") else stem


class _FDP:
    """Enough of atheris.FuzzedDataProvider for the harnesses to run without it."""

    def __init__(self, data):
        self._data = data

    def remaining_bytes(self):
        return len(self._data)

    def ConsumeBytes(self, n):
        n = max(0, min(n, len(self._data)))
        out, self._data = self._data[:n], self._data[n:]
        return out

    def ConsumeIntInRange(self, lo, hi):
        if hi <= lo:
            return lo
        return lo + int.from_bytes(self.ConsumeBytes(4), "little") % (hi - lo + 1)

    def ConsumeUnicodeNoSurrogates(self, n):
        return self.ConsumeBytes(n).decode("latin-1")


def FuzzedDataProvider(data):
    return atheris.FuzzedDataProvider(data) if atheris else _FDP(data)


def run(TestOneInput, *, allowed, corpus_dir=None, fallback_rounds=200_000):
    """Run TestOneInput as a fuzz target."""
    cdir = crashes_dir(_harness_name())
    if atheris:
        argv = list(sys.argv)
        if not any(a.startswith("-artifact_prefix=") for a in argv):
            argv.insert(1, f"-artifact_prefix={cdir}{os.sep}")
        atheris.Setup(argv, _guard(TestOneInput, allowed))
        atheris.Fuzz()
    else:
        rounds = int(os.environ.get("ELECTRUM_FUZZ_ROUNDS", fallback_rounds))
        _fallback_run(TestOneInput, allowed, corpus_dir, cdir, rounds)


def _guard(TestOneInput, allowed):
    def wrapped(data):
        try:
            TestOneInput(data)
        except allowed:
            pass
    return wrapped


# --- fallback runner (no Atheris) ------------------------------------------

def _load_seeds(corpus_dir):
    if not (corpus_dir and os.path.isdir(corpus_dir)):
        return [b""]
    seeds = []
    for path in sorted(glob.glob(os.path.join(corpus_dir, "*"))):
        if os.path.isfile(path):
            with open(path, "rb") as f:
                seeds.append(f.read())
    return seeds or [b""]


def _mutate(rng, seed):
    if not seed:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 32)))
    b = bytearray(seed)
    for _ in range(rng.randint(1, 8)):
        r = rng.random()
        if r < 0.4 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)   # flip
        elif r < 0.7:
            b.insert(rng.randrange(len(b) + 1), rng.randrange(256))  # insert
        elif b:
            del b[rng.randrange(len(b))]                     # delete
    return bytes(b)


def _fallback_run(TestOneInput, allowed, corpus_dir, cdir, rounds):
    # If files are passed on the command line, just reproduce them (mirrors how
    # you'd replay a crash under libFuzzer).
    files = [a for a in sys.argv[1:] if os.path.isfile(a)]
    if files:
        rc = 0
        for path in files:
            with open(path, "rb") as f:
                data = f.read()
            try:
                TestOneInput(data)
                print(f"[ok] {path}")
            except allowed as e:
                print(f"[ok] {path}: {type(e).__name__}")
            except Exception:
                rc = 1
                print(f"[CRASH] {path}")
                traceback.print_exc()
        sys.exit(rc)

    # Keep going after a crash (like a real fuzzing run), but dedup by crash
    # site so one bug hit thousands of times doesn't flood crashes/.
    seeds = _load_seeds(corpus_dir)
    rng = random.Random()
    seen = set()
    for i in range(len(seeds) + rounds):
        data = seeds[i] if i < len(seeds) else _mutate(rng, rng.choice(seeds))
        try:
            TestOneInput(data)
        except allowed:
            pass
        except Exception as e:
            frame = traceback.extract_tb(e.__traceback__)[-1]
            if (frame.filename, frame.lineno) in seen:
                continue
            seen.add((frame.filename, frame.lineno))
            path = os.path.join(cdir, "crash-" + hashlib.sha1(data).hexdigest())
            with open(path, "wb") as f:
                f.write(data)
            print(f"[CRASH] {type(e).__name__}: {e}  ->  {path}")
    if seen:
        sys.exit(1)
    print("no findings")
