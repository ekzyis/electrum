# Electrum fuzzing harnesses (Atheris)

Electrum is fuzzed with [Atheris](https://github.com/google/atheris), a
coverage-guided, native python fuzzer by Google.

## Layout

```
tests/fuzz/
  _harness.py          plumbing shared by all harnesses
  fuzz_tx.py           harness for transactions
  fuzz_lnmsg.py        harness for lightning wire messages
  fuzz_bolt11.py       harness for lightning payment requests
  fuzz_tx_diff.py      differential: tx parsing vs. embit (txid oracle)
  fuzz_bip32_diff.py   differential: BIP32 xkey parsing vs. embit
  fuzz_bip32_derive_diff.py differential: BIP32 child derivation (CKD) vs. embit
  fuzz_address_diff.py differential: address_to_script vs. embit
  fuzz_merkle_diff.py  SPV merkle-proof verifier (completeness + soundness)
  gen_corpus.py        writes initial corpus to ramp up coverage
  corpus/              minimized corpus for maximum coverage and regression testing
  crashes/             crash inputs are saved here
```

## Setup

Install into the environment you already run the test suite in:

```bash
pip install -r contrib/requirements/requirements-fuzz.txt   # atheris
python tests/fuzz/gen_corpus.py                             # populate corpus/
```

## Running

```bash
python tests/fuzz/fuzz_<harness>.py tests/fuzz/corpus/<harness>
```

Findings are written to `tests/fuzz/crashes/<harness>/crash-<hash>`. By default
the run stops at the first crash; to keep fuzzing and collect more, use
libFuzzer's fork mode: `-fork=1 -ignore_crashes=1`.

Atheris is based on libFuzzer, so you can also use flags to control runs like
`-runs=N` and `-max_total_time=SECONDS`, or `-merge=1 <dst> <src>` to minimize a
corpus.

## Reproduce

```bash
python tests/fuzz/fuzz_<target>.py <crash-file>
```

### Without Atheris

If `atheris` can't be imported, the harnesses fall back to replaying the corpus
and dumb-mutating it, reporting any un-allow-listed exception. It reuses the
same allow-lists, so it still reproduces a crash file and works as a smoke test,
but dumb mutation rarely reaches the valid-checksum inputs where the interesting
parsing lives — it is no substitute for a real run.

```bash
ELECTRUM_FUZZ_ROUNDS=20000 python tests/fuzz/fuzz_bolt11.py
```

