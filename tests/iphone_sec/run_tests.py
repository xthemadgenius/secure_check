#!/usr/bin/env python3
"""Runner: python3 run_tests.py [-k substring] [--list] [--no-replay]

Tests that need a real tool this machine lacks are skipped, not failed (see harness.py for how the tools are found)."""
import argparse
import importlib
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness  # noqa: E402

GROUPS = ["pre", "find", "quick", "report", "fix", "deep"]


def load_groups():
    for g in GROUPS:
        if (HERE / ("tests_%s.py" % g)).exists():
            importlib.import_module("tests_%s" % g)


def safety_selfcheck():
    """The dead usbmuxd redirect must really cut the real phone off before anything is replayed.
    With no real pymobiledevice3 installed there is nothing to cut off, so it passes."""
    import subprocess
    if not harness.REAL_PMD3:
        return True
    env = {"HOME": str(harness.RUN / "_replay" / "home"), "PATH": "/usr/bin:/bin",
           "USBMUXD_SOCKET_ADDRESS": "127.0.0.1:9", "PYMOBILEDEVICE3_USBMUX": "127.0.0.1:9"}
    (harness.RUN / "_replay" / "home").mkdir(parents=True, exist_ok=True)
    p = subprocess.run([harness.REAL_PMD3, "usbmux", "list", "--usb"], capture_output=True, text=True, env=env)
    return p.returncode != 0 and "UniqueDeviceID" not in p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--no-replay", action="store_true")
    args = ap.parse_args()
    load_groups()
    chosen = [t for t in harness.TESTS if any(k in "%s/%s" % (t[0], t[1]) for k in args.k.split(","))]   # comma = or
    if args.list:
        for g, tid, doc, _ in chosen:
            print("%s/%s  %s" % (g, tid, doc))
        return 0
    replay = not args.no_replay
    if replay and not harness.REAL_PMD3:
        print("NOTE: the real pymobiledevice3 was not found, so the recorded commands are not checked against its CLI "
              "(set IPHONE_TEST_REAL_PMD3, or: pipx install pymobiledevice3)")
        replay = False
    if replay and not safety_selfcheck():
        print("ABORT: dead-usbmuxd self-check failed, refusing to replay calls against the real CLI")
        return 2
    passed = failed = skipped = 0
    for g, tid, doc, fn in chosen:
        t0 = time.time()
        try:
            r = fn()
            if replay and r is not None:
                problems = harness.replay_syntax(r)
                harness.ok(not problems, "invalid command line vs real CLI: " + " | ".join(problems))
            print("PASS  %s/%s  (%.1fs)  %s" % (g, tid, time.time() - t0, doc))
            passed += 1
        except harness.Skip as why:
            skipped += 1
            print("SKIP  %s/%s  %s\n      %s" % (g, tid, doc, why))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL  %s/%s  %s\n      %s: %s" % (g, tid, doc, type(exc).__name__, exc))
            r = getattr(exc, "run", None)
            if not isinstance(exc, AssertionError):
                traceback.print_exc(limit=3)
    print("\n%d passed, %d failed%s" % (passed, failed, ", %d skipped" % skipped if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
