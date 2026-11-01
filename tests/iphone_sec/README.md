# Tests for iphone_sec.sh

A test harness for `iphone_sec.sh`. It never touches a phone: every test runs the script against stand-in tools in a throwaway home folder.

Needs macOS (the script only runs there, and the tests run it under the system `/bin/bash`, 3.2) and Python 3.9 or newer (the suite has been run on 3.9.6, the `python3` Apple's developer tools provide, and on 3.14.6). Nothing needs installing to start; see [Real tools](#real-tools-optional) for the two optional ones.

## Run

From the top of the repo:

```bash
python3 tests/iphone_sec/run_tests.py                         # everything
python3 tests/iphone_sec/run_tests.py -k quick                # one group: pre, find, quick, report, fix, deep
python3 tests/iphone_sec/run_tests.py -k deep/D07,report/R10  # a comma means "or"
python3 tests/iphone_sec/run_tests.py --list                  # show what would run
python3 tests/iphone_sec/pty_smoke.py                         # what only a real terminal shows
```

`run_tests.py` prints one `PASS`, `FAIL` or `SKIP` line per test and ends with `N passed, M failed` (plus `, K skipped` when something was skipped). It exits 1 if anything failed. A skip is not a failure.

`pty_smoke.py` runs the script on a pseudo-terminal and checks what the pipe-driven tests cannot see: the screen is cleared, colours show, a typed password is not echoed, the terminal is left as it was after Ctrl-C, and a closed window stops the script and the backup tool.

Run one thing at a time. A few deep-scan tests (`D07c`, `D18*`, `D19c`) depend on timing and can fail on a busy machine; run the failing one alone (`-k D18`) before suspecting the script.

## What is faked and what is real

Every test gets a fresh fake `HOME` (its path has a space in it), a `PATH` of the stand-in tools plus `/usr/bin:/bin`, and a dead USB address (`127.0.0.1:9`), so no phone and no network can be reached.

| Part | In the tests |
|------|--------------|
| `iphone_sec.sh`, its embedded Python helper, `bash` 3.2, `zip` | real |
| `pymobiledevice3` | `stubs/pymobiledevice3`, a strict stand-in. What the "phone" answers comes from a per-test scenario. An unknown command or option exits 2 like the real CLI, so a typo in the script cannot pass |
| `mvt-ios download-iocs`, `decrypt-backup` | faked by `stubs/mvt-ios` (they need the network or a real encrypted backup) |
| `mvt-ios check-backup` | the real MVT, run on a small synthetic backup that `fixtures/make_synth_backup.py` builds. Some tests fake its output instead, to produce results a clean backup never would |

Every `pymobiledevice3` command line the script builds is recorded. After a test passes, each distinct one is replayed against the real `pymobiledevice3` (with the dead USB address and a made-up device ID) and must not be rejected as a usage error. Before anything is replayed, a self-check confirms that the dead address really cuts the real tool off from USB, and the run stops if it does not.

## Real tools (optional)

Two parts of the suite use the real tools when they are installed (`pipx install pymobiledevice3` and `pipx install mvt`):

- `pymobiledevice3`, for the command-line replay above. Without it the replay is switched off, with a note.
- `mvt-ios`, for the deep-scan tests that run MVT on a synthetic backup. Without it those tests are skipped, and so cannot catch a mutant (below).

Both are looked for on `PATH`, then in `~/.local/bin` (where `pipx` puts them).

## Environment variables

All optional.

| Variable | Meaning |
|----------|---------|
| `IPHONE_SCRIPT` | The script to test. Default: `iphone_sec.sh` at the top of the repo |
| `IPHONE_RUN` | Where the per-test folders go. Default: `run/` next to the harness (`run_pty/` for `pty_smoke.py`) |
| `IPHONE_TEST_REAL_PMD3` | The real `pymobiledevice3`. When set, nothing else is tried |
| `IPHONE_TEST_REAL_MVT` | The real `mvt-ios`. When set, nothing else is tried |
| `IPHONE_TEST_SHEBANG` | First line of the stand-in tool launchers. Default: `#!` plus the Python running the tests. The script reads that line to pick its helper Python |

## Mutation runs

A mutant is a copy of the script with one deliberate change (a flipped test, a dropped flag, a skipped check). The tests of its group should fail for it; a mutant that none of them catches is reported as `SURVIVED`, which means a behaviour the tests do not pin down. The `mut_*.py` files list the mutants.

```bash
python3 tests/iphone_sec/mutate.py mut_quick -k quick --check  # only check that every mutant can be built
python3 tests/iphone_sec/mutate.py mut_quick -k quick -j 4     # run them, 4 at a time
python3 tests/iphone_sec/mutate.py mut_fix -k fix --only applyNever  # one mutant (the ids are in the mut_*.py file)
```

`-k` names the group whose tests are run (`quick`, `report`, `fix`, `deep`). Each mutant and its run folder are written to `mutants/`.

## Layout

| Path | What it is |
|------|------------|
| `harness.py` | `Run` (one script run in a fake home), `Session` (answer prompts one at a time), the assertion helpers, the command-line replay |
| `run_tests.py` | The runner |
| `tests_pre.py` `tests_find.py` `tests_quick.py` `tests_report.py` `tests_fix.py` `tests_deep.py` | The tests, by stage of the script: start-up checks, finding the phone, quick checks, report and ZIP, `APPLY=1` fixes, deep scan |
| `mutate.py`, `mut_quick.py` `mut_report.py` `mut_fix.py` `mut_deep.py` | The mutation runner and its mutants |
| `pty_smoke.py` | The pseudo-terminal checks |
| `stubs/` | The stand-in `pymobiledevice3` and the `mvt-ios` shim |
| `fixtures/` | The synthetic backup builder and two small indicator files |

Test ids start with the group's letter: `P` pre, `F` find, `Q` quick, `R` report, `X` fix, `D` deep.
