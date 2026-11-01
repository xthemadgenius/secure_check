#!/usr/bin/env python3
"""Mutation runner: python3 mutate.py MUTATIONS_MODULE [-k GROUP] [-j JOBS] [--only ID,ID]

MUTATIONS_MODULE defines MUTANTS = [(id, description, old, new, expected_tests)], where `old` is text that must occur
exactly once in the script (or a list of such texts, with `new` a list of the same length, for a change at several sites). Each mutant is a copy of the script with that one replacement; the group's tests must
fail for it, and at least one of the failures must be among expected_tests.
"""
import argparse
import importlib
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from harness import REAL_MVT, SCRIPT, force_rmtree

HERE = Path(__file__).resolve().parent
OUT = HERE / "mutants"


def helper_source(text):
    m = re.search(r"<<'PYEOF'[^\n]*\n(.*?)\nPYEOF\n", text, re.S)
    return m.group(1) if m else None


def build(mut):
    """(mutated text, None), or (None, why) when a pattern is not found exactly once or the result cannot run at all."""
    mid, desc, old, new, expected = mut
    olds = list(old) if isinstance(old, (list, tuple)) else [old]
    news = list(new) if isinstance(new, (list, tuple)) else [new]
    if len(olds) != len(news):
        return None, "old and new lists differ in length"
    src = SCRIPT.read_text()
    for o, n in zip(olds, news):
        if src.count(o) != 1:
            return None, "pattern occurs %d times: %r" % (src.count(o), o[:60])
        src = src.replace(o, n, 1)
    py = helper_source(src)
    if py is not None:
        try:
            compile(py, "helper", "exec")
        except SyntaxError as exc:
            return None, "the embedded Python has a syntax error: %s" % exc
    return src, None


def run_tests(mutant, runroot, select):
    """(ids of the failed tests, how many tests ran) for the tests whose label contains one of the comma-separated SELECT texts."""
    force_rmtree(runroot)
    env = dict(os.environ, IPHONE_SCRIPT=str(mutant), IPHONE_RUN=str(runroot))
    p = subprocess.run([sys.executable, str(HERE / "run_tests.py"), "-k", select, "--no-replay"], capture_output=True,
                       text=True, env=env, cwd=str(HERE))
    failed = [f.split("/")[-1] for f in re.findall(r"^FAIL\s+(\S+)", p.stdout, re.M)]
    m = re.search(r"^(\d+) passed, (\d+) failed", p.stdout, re.M)
    force_rmtree(runroot)
    return failed, (int(m.group(1)) + int(m.group(2)) if m else 0)


def run_one(mut, group, full=False):
    """The expected tests run first (quick); only a mutant they do not kill gets the whole group, which then says OFF-TARGET or SURVIVED."""
    mid, desc, old, new, expected = mut
    src, why = build(mut)
    if why:
        return mid, desc, "BAD", why, []
    mutant = OUT / ("%s.sh" % mid)
    mutant.write_text(src)
    if subprocess.run(["/bin/bash", "-n", str(mutant)], capture_output=True).returncode != 0:
        return mid, desc, "BAD", "mutant has a syntax error", []
    runroot = OUT / ("run_%s" % mid)
    if expected and not full:
        short, ran = run_tests(mutant, runroot, ",".join(expected))
        if ran == 0:
            return mid, desc, "BAD", "none of the expected tests %s exist" % expected, []
        if set(expected) & set(short):
            return mid, desc, "KILLED", "by %s" % ", ".join(short), short
    short, _ = run_tests(mutant, runroot, group)
    if not short:
        return mid, desc, "SURVIVED", "no test failed", short
    if expected and not set(expected) & set(short):
        return mid, desc, "OFF-TARGET", "failed %s but expected one of %s" % (short, expected), short
    return mid, desc, "KILLED", "by %s" % ", ".join(short), short


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module")
    ap.add_argument("-k", default="quick")
    ap.add_argument("-j", type=int, default=4)
    ap.add_argument("--only", default="")
    ap.add_argument("--check", action="store_true", help="only check that every mutant can be built, run no tests")
    ap.add_argument("--full", action="store_true", help="always run the whole group, not just the expected tests first")
    a = ap.parse_args()
    sys.path.insert(0, str(HERE))
    mutants = importlib.import_module(a.module).MUTANTS
    if a.only:
        wanted = set(a.only.split(","))
        mutants = [m for m in mutants if m[0] in wanted]
    OUT.mkdir(exist_ok=True)
    if a.check:
        bad = 0
        for m in mutants:
            src, why = build(m)
            if why is None:
                (OUT / ("%s.sh" % m[0])).write_text(src)
                if subprocess.run(["/bin/bash", "-n", str(OUT / ("%s.sh" % m[0]))], capture_output=True).returncode != 0:
                    why = "mutant has a shell syntax error"
            if why:
                bad += 1
                print("BAD  %-24s %s" % (m[0], why))
        print("%d mutants, %d cannot be built" % (len(mutants), bad))
        return 1 if bad else 0
    if not REAL_MVT:
        print("NOTE: the real mvt-ios was not found, so the tests that need it are skipped and cannot kill a mutant "
              "(set IPHONE_TEST_REAL_MVT, or: pipx install mvt)")
    with ThreadPoolExecutor(max_workers=a.j) as ex:
        results = list(ex.map(lambda m: run_one(m, a.k, a.full), mutants))
    bad = 0
    for mid, desc, verdict, detail, _ in results:
        print("%-10s %-10s %s -- %s" % (verdict, mid, desc, detail))
        bad += verdict != "KILLED"
    print("\n%d mutants, %d killed, %d not killed" % (len(results), len(results) - bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
