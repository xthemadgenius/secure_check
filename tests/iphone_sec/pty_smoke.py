#!/usr/bin/env python3
"""The parts of iphone_sec.sh that only a real terminal shows, run on a pseudo-terminal: colours and `clear`, a password that is
not echoed, the terminal left as it was after Ctrl-C, and what a closed window does. The pipe-driven groups cannot see any of these.

Same stubs, fake HOME and dead usbmuxd redirect as the other groups (the run folder is separate), so no phone can be reached.

python3 pty_smoke.py [-k substring]
"""
import argparse
import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("IPHONE_RUN", str(HERE / "run_pty"))
sys.path.insert(0, str(HERE))
from harness import ANSI, BASH, SCRIPT, UDID, Run, base_scenario, no_leak, ok  # noqa: E402
from run_tests import safety_selfcheck  # noqa: E402

PW = "-Pa ss'\"$HOME\\x*?[ "          # nothing the terminal driver treats as an editing key
SHOWN = "Pa ss"                       # a stretch of it that would show if the terminal echoed what was typed
COLOUR = re.compile(r"\x1b\[(?:0|1);(?:3[0-7]|90)m")
CLEARED = re.compile(r"\x1b\[[0-9;]*J")
FACTS = []


class Tty:
    """The script on a pseudo-terminal, in a session of its own with that terminal as its controlling one: a ^C typed here becomes
    SIGINT and a closed terminal becomes SIGHUP, as in Terminal.app. The output is kept raw; text() drops colours and carriage returns."""

    def __init__(self, run, args=()):
        self.r = run
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        self.start = termios.tcgetattr(self.slave)
        self.p = subprocess.Popen([BASH, str(SCRIPT)] + list(args), stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                  env=run.env, cwd=str(run.cwd), start_new_session=True,
                                  preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.set_blocking(self.master, False)
        self.buf = b""
        self.pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        """Whatever still runs in the terminal's process group goes, then both ends of the terminal are closed."""
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):       # macOS answers EPERM, not ESRCH, for a group of zombies
            pass
        end = time.time() + 15
        while self.p.poll() is None and time.time() < end:  # a session leader that is exiting waits for its terminal's output to be read
            self._pump(0.1)
        for fd in (self.master, self.slave):
            if fd is not None:
                os.close(fd)
        self.master = self.slave = None
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("WARNING: process %d did not end" % self.p.pid)

    def hangup(self):
        """The terminal window goes away: the master end is closed."""
        os.close(self.master)
        self.master = None

    def _pump(self, timeout):
        """True: output arrived. False: none within the timeout. None: nothing can arrive any more."""
        if self.master is None:
            return None
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return None
        if not chunk:
            return None
        self.buf += chunk
        return True

    def raw_text(self):
        return self.buf.decode("utf-8", "replace")

    def text(self):
        return ANSI.sub("", self.raw_text()).replace("\r", "")

    def until(self, text, timeout=40):
        """Block until `text` shows up in the output not yet consumed; consume up to the end of it."""
        end = time.time() + timeout
        while True:
            seen = self.text()[self.pos:]
            i = seen.find(text)
            if i >= 0:
                self.pos += i + len(text)
                return seen[:i + len(text)]
            if time.time() > end:
                raise AssertionError("timed out waiting for %r; unconsumed output: %r" % (text, seen[-400:]))
            got = self._pump(0.2)
            if got is None or (got is False and self.p.poll() is not None):
                raise AssertionError("the script ended (exit %r) while waiting for %r; unconsumed output: %r"
                                     % (self.p.returncode, text, seen[-400:]))

    def send(self, text):
        os.write(self.master, text.encode())

    def lflag(self):
        """The terminal's local flags, read through the master end: once the script (the session leader) has exited the slave end
        is revoked, and opening it again would show fresh defaults instead of what the script left behind."""
        return termios.tcgetattr(self.master)[3]

    def wait_echo(self, want, timeout=10):
        """Block until the terminal's ECHO flag is `want` (a password prompt prints its text just before it turns echo off)."""
        end = time.time() + timeout
        while bool(self.lflag() & termios.ECHO) != want:
            if time.time() > end:
                raise AssertionError("the terminal's echo never became %s" % ("on" if want else "off"))
            self._pump(0.05)

    def wait_exit(self, timeout=60):
        """Wait for the script to end, reading its output meanwhile: a script that has written more than the terminal holds
        cannot finish (or even exit) until the other end reads it."""
        end = time.time() + timeout
        while self.p.poll() is None:
            if time.time() > end:
                raise AssertionError("the script was still running %ss later" % timeout)
            self._pump(0.1)
        while self._pump(0.1):
            pass
        self.r.rc, self.r.raw = self.p.returncode, self.raw_text()
        self.r.out, self.r.err = self.text(), ""
        (self.r.root / "screen.txt").write_text(self.r.out)
        (self.r.root / "screen.raw").write_bytes(self.buf)
        return self.r


def to_deep_prompt(t):
    t.until("Enter your name")
    t.send("alice\n")
    t.until("(y/n): ")
    t.send("y\n")
    t.until("Press Enter once")
    t.send("\n")
    t.until("Run the deep scan? (y/n): ")


def hidden(t, prompt, secret):
    """Answer a hidden prompt, once the terminal has stopped echoing."""
    t.until(prompt)
    t.wait_echo(False)
    t.send(secret + "\n")


def to_backup(r, t):
    to_deep_prompt(t)
    t.send("y\n")
    t.until("Turn on backup encryption? (y/n): ")
    t.send("n\n")
    t.until("Making the backup.")
    end = time.time() + 30
    while not list(r.work_root().glob("iphone_*/backup/*/Info.plist")):
        ok(time.time() < end, "the backup never started")
        t._pump(0.1)


def echo_state(t):
    return "on" if t.lflag() & termios.ECHO else "OFF"


def full_flow():
    r = Run("pty_full", dict(base_scenario(), mvt_fake={}))
    with Tty(r) as t:
        to_deep_prompt(t)
        t.send("y\n")
        t.until("Turn on backup encryption? (y/n): ")
        t.send("y\n")
        hidden(t, "New backup password: ", PW)
        hidden(t, "Type it again: ", PW)
        t.until("Delete the folder and keep only the ZIP? (y/n): ")
        t.send("n\n")
        t.until("Delete the private folder (the backup and MVT's raw results)? (y/n): ")
        t.send("n\n")
        t.wait_exit()
        raw = t.raw_text()
        FACTS.append("full flow: the screen starts %r, %d colour codes" % (raw[:24], len(COLOUR.findall(raw))))
        ok(r.rc == 0, "exit code %r" % r.rc)
        ok(CLEARED.search(raw[:64]), "the screen was not cleared at the start: %r" % raw[:64])
        ok(COLOUR.search(raw) and "\x1b[0m" in raw, "no colours on a terminal")
        ok("Deep scan (optional)" in r.out and "Summary:" in r.out, "sections missing from the screen")
        ok(PW not in r.out and SHOWN not in r.out, "the typed password was echoed to the terminal")
        ok(t.lflag() == t.start[3], "the terminal was left with other flags (echo %s)" % echo_state(t))
        ok(r.zip_path().exists() and r.report_dir().exists(), "no report or ZIP")
        ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())
        no_leak(r, UDID, PW, SHOWN)


def ctrl_c_at_password():
    r = Run("pty_ctrlc", dict(base_scenario(), mvt_fake={}))
    with Tty(r) as t:
        to_deep_prompt(t)
        t.send("y\n")
        t.until("Turn on backup encryption? (y/n): ")
        t.send("y\n")
        t.until("New backup password: ")
        t.wait_echo(False)
        t.send("\x03")
        t.wait_exit(30)
        ok(r.rc == 130, "exit code %r" % r.rc)
        ok(t.lflag() == t.start[3], "the terminal was left with other flags (echo %s)" % echo_state(t))
        ok(r.work_dirs() == [] and [c for c in r.order() if c.startswith("pmd:backup2")] == [], "went on: %r" % r.order())
        ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())


def closed_window():
    r = Run("pty_hup", dict(base_scenario(), backup_sleep="60", mvt_fake={}))
    with Tty(r) as t:
        to_backup(r, t)
        t0 = time.time()
        t.hangup()
        t.wait_exit(30)
        FACTS.append("closed window: the script ended with status %r after %.1fs" % (r.rc, time.time() - t0))
        ok(r.rc != 0, "exit code 0 after the terminal went away")
        ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())
        ok(len(r.work_dirs()) == 1, "the partial backup's folder: %r" % r.work_dirs())
        ok(not r.report_dir().exists() and r.zip_names() is None, "a report was left")
        left = subprocess.run(["pgrep", "-f", "backup2 backup.*" + str(r.root)], capture_output=True, text=True).stdout.split()
        ok(left == [], "the backup tool was still running: %r" % left)


def killed_window():
    """The check above has to be able to fail: a script that is killed outright cannot clean up after itself."""
    r = Run("pty_kill", dict(base_scenario(), backup_sleep="60", mvt_fake={}))
    with Tty(r) as t:
        to_backup(r, t)
        os.killpg(t.p.pid, signal.SIGKILL)
        t.wait_exit(30)
        ok(r.tmp_leftovers() != [], "a killed script left no temp files, so a clean folder proves nothing")


CHECKS = [("full flow on a terminal: clear, colours, hidden password, terminal left as it was", full_flow),
          ("Ctrl-C at the hidden password prompt: exit 130, echo back on", ctrl_c_at_password),
          ("closed window during the backup: the script and the backup end, temp files removed", closed_window),
          ("control: a script killed outright leaves its temp files behind", killed_window)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="")
    args = ap.parse_args()
    if not safety_selfcheck():
        print("ABORT: dead-usbmuxd self-check failed, refusing to run")
        return 2
    passed = failed = 0
    for name, fn in CHECKS:
        if args.k not in name:
            continue
        t0 = time.time()
        try:
            fn()
            print("PASS  %s  (%.1fs)" % (name, time.time() - t0))
            passed += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL  %s\n      %s: %s" % (name, type(exc).__name__, exc))
            if not isinstance(exc, AssertionError):
                traceback.print_exc(limit=4)
    for f in FACTS:
        print("FACT  " + f)
    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
