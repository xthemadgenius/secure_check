#!/usr/bin/env python3
"""Hermetic test harness for iphone_sec.sh.

Every test gets a fresh fake HOME (with a space in its path), PATH = stubs + /usr/bin:/bin, and a
dead usbmuxd address, so a real phone and the network are unreachable. The script runs under the
macOS system bash (/bin/bash, 3.2).

Environment variables, all optional:
  IPHONE_SCRIPT          the script under test (default: iphone_sec.sh at the top of the repo)
  IPHONE_RUN             where the per-test folders go (default: run/ next to this file)
  IPHONE_TEST_SHEBANG    first line of the stand-in tool launchers (default: #! + the Python running the tests)
  IPHONE_TEST_REAL_PMD3  the real pymobiledevice3, to check every recorded command line against its CLI
  IPHONE_TEST_REAL_MVT   the real mvt-ios, which the deep-scan tests run on a synthetic backup
The two real tools are looked for on PATH and in ~/.local/bin when the variable is not set.
"""
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = Path(os.environ.get("IPHONE_RUN", HERE / "run"))
FIX = HERE / "fixtures"
STUBS = HERE / "stubs"
SCRIPT = Path(os.environ.get("IPHONE_SCRIPT", HERE.parents[1] / "iphone_sec.sh"))
BASH = "/bin/bash"
UDID = "00008150-0000000000000001"
UDID2 = "00008150-0000000000000002"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1bc")


def find_tool(name, env_var):
    """A real tool some tests call: $env_var when it is set (and nothing else then), else PATH, else
    ~/.local/bin (where pipx puts it). None when it is not there."""
    given = os.environ.get(env_var)
    for cand in [given] if given else [shutil.which(name), str(Path.home() / ".local" / "bin" / name)]:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


REAL_PMD3 = find_tool("pymobiledevice3", "IPHONE_TEST_REAL_PMD3")
REAL_MVT = find_tool("mvt-ios", "IPHONE_TEST_REAL_MVT")


class Skip(Exception):
    """The test needs a real tool this machine does not have."""


TESTS = []


def test(group, tid, doc=""):
    def deco(fn):
        TESTS.append((group, tid, doc or (fn.__doc__ or "").strip(), fn))
        return fn
    return deco


def device(name="Test iPhone", udid=UDID, ios="27.2", model="iPhone18,2", build="24B119"):
    return {"BuildVersion": build, "ConnectionType": "USB", "DeviceClass": "iPhone", "DeviceName": name,
            "Identifier": udid, "ProductType": model, "ProductVersion": ios, "UniqueDeviceID": udid}


def app(bundle, name, kind="User", signer="Apple iPhone OS Application Signing"):
    entry = {"CFBundleIdentifier": bundle, "CFBundleDisplayName": name, "ApplicationType": kind}
    if signer is not None:
        entry["SignerIdentity"] = signer
    return entry


def profile_response(*profiles):
    """profiles: (identifier, display name, organization)"""
    return {"Status": "Acknowledged",
            "OrderedIdentifiers": [p[0] for p in profiles],
            "ProfileManifest": {p[0]: {"Description": "stub", "IsEncrypted": False} for p in profiles},
            "ProfileMetadata": {p[0]: {"PayloadDisplayName": p[1], "PayloadOrganization": p[2],
                                       "PayloadVersion": 1, "PayloadUUID": "UUID-" + p[0]} for p in profiles}}


def base_scenario():
    apps = {}
    for a in (app("com.apple.mobilesafari", "Safari", "System"), app("com.apple.Preferences", "Settings", "System"),
              app("com.example.notes", "Notes Plus"), app("com.example.chat", "Chatty")):
        apps[a["CFBundleIdentifier"]] = a
    return {
        "devices": [device()],
        "lockdown_info": {"DeviceName": "Test iPhone", "ProductType": "iPhone18,2", "ProductVersion": "27.2",
                          "BuildVersion": "24B119", "DeviceClass": "iPhone", "UniqueDeviceID": UDID,
                          "SerialNumber": "SECRETSERIAL123", "PhoneNumber": "+1 555 000 1234",
                          "InternationalMobileEquipmentIdentity": "359999999999999", "PasswordProtected": False},
        "apps": apps,
        "profiles": profile_response(),
        "backup_flags": [],
    }


STUB_PY = sys.executable


def make_launcher(dst, tool, shebang):
    """A pipx-style launcher: first line is the shebang the script reads, then it runs the stub."""
    dst.write_text("%s\nimport os, sys\nos.execv(%r, ['python3', %r] + sys.argv[1:])\n"
                   % (shebang, STUB_PY, str(STUBS / tool)))
    dst.chmod(0o755)


def sysbin_nopython():
    """/usr/bin + /bin as symlinks minus every python/pip, to test the 'no Python at all' path."""
    d = RUN / "_sysbin_nopy"
    if not d.exists():
        d.mkdir(parents=True)
        for src in ("/usr/bin", "/bin"):
            for name in os.listdir(src):
                if name.startswith(("python", "pip")) or (d / name).exists():
                    continue
                os.symlink(os.path.join(src, name), d / name)
    return d


def force_rmtree(path):
    """rmtree that also removes folders a test made read-only (a test that fails half way must not poison the next run)."""
    def fix(func, p, _exc):
        os.chmod(os.path.dirname(p), 0o700)
        os.chmod(p, 0o700)
        func(p)
    path = str(path)
    if not os.path.lexists(path):
        return
    for dirpath, dirnames, _files in os.walk(path):
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if not os.path.islink(full):
                os.chmod(full, 0o700)
    shutil.rmtree(path, onerror=fix)


class Run:
    def __init__(self, tid, scenario=None, tools=("pymobiledevice3", "mvt-ios"), home_tools=(),
                 env_extra=None, env_drop=(), shebang=None, nopython=False):
        self.tid = tid
        self.root = RUN / tid
        if self.root.exists():
            force_rmtree(self.root)
        self.home = self.root / "home dir"
        self.stub = self.root / "stub"
        self.bin = self.root / "bin"
        self.cwd = self.root / "cwd"
        self.tmp = self.root / "tmp"
        self.mvtdata = self.root / "mvtdata"
        for d in (self.home, self.stub, self.bin, self.cwd, self.tmp):
            d.mkdir(parents=True)
        self.scenario = scenario if scenario is not None else base_scenario()
        (self.stub / "scenario.json").write_text(json.dumps(self.scenario))
        (self.stub / "state.json").write_text(json.dumps({
            "encrypted": bool(self.scenario.get("encrypted_initial", False)),
            "password": self.scenario.get("password_initial"), "removed_apps": [], "removed_profiles": []}))
        for name in self.scenario.get("indicators_preseed", []):        # an older copy of the indicators already on this Mac
            (self.mvtdata / "indicators").mkdir(parents=True, exist_ok=True)
            if name.endswith("/"):                                      # a folder (not a file) with that name
                (self.mvtdata / "indicators" / name.rstrip("/")).mkdir()
            else:
                shutil.copy(FIX / name, self.mvtdata / "indicators" / name)
        shebang = shebang or os.environ.get("IPHONE_TEST_SHEBANG") or "#!" + sys.executable

        def put(folder, tool):
            make_launcher(folder / tool, tool, shebang)
        for t in tools:
            put(self.bin, t)
        if home_tools:
            hb = self.home / ".local" / "bin"
            hb.mkdir(parents=True)
            for t in home_tools:
                put(hb, t)
        sysdirs = str(sysbin_nopython()) if nopython else "/usr/bin:/bin"
        self.env = {"HOME": str(self.home), "PATH": "%s:%s" % (self.bin, sysdirs), "TERM": "xterm",
                    "LANG": "en_US.UTF-8", "TMPDIR": str(self.tmp), "STUB_DIR": str(self.stub),
                    "STUB_FIXTURES": str(FIX), "MVT_DATA_FOLDER": str(self.mvtdata), "IPHONE_TEST_REAL_MVT": REAL_MVT or "",
                    "USBMUXD_SOCKET_ADDRESS": "127.0.0.1:9", "PYMOBILEDEVICE3_USBMUX": "127.0.0.1:9"}
        self.env.update(env_extra or {})
        for k in env_drop:
            self.env.pop(k, None)
        self.out = self.err = self.raw = ""
        self.rc = None

    def fake_cmd(self, name, body='echo "$0 $*" >> "$STUB_DIR/installer.log"\nexit 0'):
        """Drop a tiny shell command first on PATH (e.g. a fake uname, or pipx/brew that record calls)."""
        p = self.bin / name
        p.write_text("#!/bin/sh\n%s\n" % body)
        p.chmod(0o755)

    def installer_calls(self):
        p = self.stub / "installer.log"
        return p.read_text().splitlines() if p.exists() else []

    def tmp_leftovers(self):
        return sorted(p.name for p in self.tmp.iterdir())

    def go(self, answers="", args=(), timeout=420):
        p = subprocess.run([BASH, str(SCRIPT)] + list(args), input=answers, text=True, capture_output=True,
                           env=self.env, cwd=str(self.cwd), timeout=timeout)
        self.raw, self.rc = p.stdout, p.returncode
        self.out = ANSI.sub("", p.stdout)
        self.err = ANSI.sub("", p.stderr)
        self.skip_if_real_mvt_missing()
        return self

    def skip_if_real_mvt_missing(self):
        """The mvt-ios stand-in hands check-backup and the like to the real tool and leaves a marker when it is not there."""
        if (self.stub / "real_mvt_missing").exists():
            raise Skip("needs the real mvt-ios (set IPHONE_TEST_REAL_MVT, or: pipx install mvt)")

    # --- recorded calls ---
    def calls(self):
        p = self.stub / "calls.log"
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []

    def pmd(self):
        return [c["argv"] for c in self.calls() if c["tool"] == "pymobiledevice3"]

    def mvt(self):
        return [c["argv"] for c in self.calls() if c["tool"] == "mvt-ios"]

    def pmd_cmds(self):
        return [" ".join(a[:2]) for a in self.pmd()]

    def order(self):
        """Compact ordered call list, e.g. ['mvt:download-iocs', 'pmd:backup2 backup']."""
        seq = []
        for c in self.calls():
            if c["tool"] == "pymobiledevice3":
                seq.append("pmd:" + " ".join(c["argv"][:2]))
            else:
                a = [x for x in c["argv"] if not x.startswith("--disable-")]
                seq.append("mvt:" + (a[0] if a else ""))
        return seq

    # --- files ---
    def desktop(self):
        return self.home / "Desktop"

    def report_dir(self, name="alice"):
        return self.desktop() / ("%s.iPhone_Security_Check" % name)

    def zip_path(self, name="alice"):
        return self.desktop() / ("%s.iPhone_Security_Check.zip" % name)

    def report(self, name="alice"):
        p = self.report_dir(name) / "iphone_security_report.txt"
        return p.read_text() if p.exists() else ""

    def zip_names(self, name="alice"):
        z = self.zip_path(name)
        if not z.exists():
            return None
        with zipfile.ZipFile(z) as zf:
            return sorted(zf.namelist())

    def zip_text(self, name="alice"):
        z = self.zip_path(name)
        if not z.exists():
            return ""
        with zipfile.ZipFile(z) as zf:
            return "\n".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())

    def work_root(self):
        return self.home / "Library" / "Application Support" / "secure_check"

    def work_dirs(self):
        wr = self.work_root()
        return sorted(p for p in wr.iterdir() if p.is_dir()) if wr.exists() else []


class Session:
    """Drive the script interactively over pipes: wait for a prompt, inspect state, then answer.
    Lets a test assert what had (not) happened at the moment a prompt was on screen."""

    def __init__(self, run, args=(), new_session=False):
        """new_session=True puts the script in its own process group, so interrupt() can signal it and its
        children together the way a terminal's Ctrl-C does."""
        self.r = run
        self.p = subprocess.Popen([BASH, str(SCRIPT)] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=run.env, cwd=str(run.cwd), start_new_session=new_session)
        os.set_blocking(self.p.stdout.fileno(), False)
        self.buf = b""
        self.pos = 0

    def _pump(self, timeout):
        ready, _, _ = select.select([self.p.stdout], [], [], timeout)
        if ready:
            chunk = os.read(self.p.stdout.fileno(), 65536)
            if chunk:
                self.buf += chunk
                return True
            return None          # EOF
        return False

    def until(self, text, timeout=30):
        """Block until `text` shows up in the not-yet-consumed output; consumes up to the end of the
        match (not the whole buffer, so a later prompt that arrived in the same read is still found)
        and returns what was consumed. `pos` indexes the ANSI-stripped text."""
        end = time.time() + timeout
        while True:
            seen = ANSI.sub("", self.buf.decode("utf-8", "replace"))[self.pos:]
            i = seen.find(text)
            if i >= 0:
                self.pos += i + len(text)
                return seen[:i + len(text)]
            if time.time() > end:
                self.p.kill()
                self.r.skip_if_real_mvt_missing()
                raise AssertionError("timed out waiting for %r; unconsumed output: %r" % (text, seen[-400:]))
            if self._pump(0.2) is None:
                self.r.skip_if_real_mvt_missing()
                raise AssertionError("script ended while waiting for %r; unconsumed output: %r" % (text, seen[-400:]))

    def send(self, line):
        self.p.stdin.write(line.encode())
        self.p.stdin.flush()

    def wait_path(self, path, timeout=30):
        """Block until a file exists (e.g. the backup tool has started writing)."""
        end = time.time() + timeout
        while not Path(path).exists():
            if time.time() > end:
                self.p.kill()
                self.r.skip_if_real_mvt_missing()
                raise AssertionError("timed out waiting for %s" % path)
            self._pump(0.1)

    def interrupt(self):
        """Ctrl-C: SIGINT to the whole process group (only meaningful with new_session=True)."""
        os.killpg(self.p.pid, signal.SIGINT)

    def finish(self, timeout=420):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        end = time.time() + timeout
        while self._pump(0.2) is not None:
            if time.time() > end:
                self.p.kill()
                raise AssertionError("script did not finish")
        self.p.wait(timeout=30)
        err = self.p.stderr.read().decode("utf-8", "replace")
        self.r.raw, self.r.rc = self.buf.decode("utf-8", "replace"), self.p.returncode
        self.r.out, self.r.err = ANSI.sub("", self.r.raw), ANSI.sub("", err)
        self.r.skip_if_real_mvt_missing()
        return self.r


# --- assertion helpers (raise AssertionError with a readable message) ---
def ok(cond, msg):
    if not cond:
        raise AssertionError(msg)


def has(r, text, where="out"):
    hay = getattr(r, where)
    ok(text in hay, "expected %r in %s" % (text, where))


def lacks(r, text, where="out"):
    hay = getattr(r, where)
    ok(text not in hay, "did not expect %r in %s" % (text, where))


def rc(r, want):
    ok(r.rc == want, "exit code %r, wanted %r" % (r.rc, want))


def no_leak(r, *needles, name="alice"):
    """None of needles may appear on screen, in stderr, in the report folder or inside the ZIP."""
    blobs = {"stdout": r.out, "stderr": r.err, "zip": r.zip_text(name)}
    rd = r.report_dir(name)
    if rd.exists():
        for f in rd.rglob("*"):
            if f.is_file():
                blobs[str(f.name)] = f.read_text(errors="replace")
    for n in needles:
        for where, blob in blobs.items():
            ok(n not in blob, "%r leaked into %s" % (n, where))


def tag_lines(r, tag, where="out"):
    return [ln for ln in getattr(r, where).splitlines() if ln.lstrip().startswith("[%s]" % tag)]


def rtag_lines(r, tag, name="alice"):
    """The same tagged lines, as written to the report file."""
    return [ln for ln in r.report(name).splitlines() if ln.startswith("[%s]" % tag)]


# --- syntax replay: every recorded pymobiledevice3 call must parse against the REAL CLI ---
USAGE_MARKERS = ("No such option", "No such command", "Missing argument", "Missing option",
                 "Invalid value", "Got unexpected extra", "Usage: pymobiledevice3")
REPLAY_ROOT = RUN / "_replay"
_replayed = {}


def replay_syntax(r):
    """Replay each distinct recorded call against the real pymobiledevice3 with a dead usbmuxd.
    A usage error (exit 2 / click markers) means the script built an invalid command line.
    Double safety: dead socket AND a fake UDID that matches no real device. Nothing to replay against when the
    real CLI is not installed."""
    problems = []
    for argv in r.pmd() if REAL_PMD3 else []:
        norm = [a.replace(str(r.root), str(REPLAY_ROOT)) for a in argv]
        key = tuple(norm)
        if key not in _replayed:
            for flag in ("-b", "--backup-directory"):
                if flag in norm:
                    os.makedirs(norm[norm.index(flag) + 1], exist_ok=True)
            if norm[:2] == ["backup2", "backup"]:
                os.makedirs(norm[-1], exist_ok=True)
            env = {"HOME": str(REPLAY_ROOT / "home"), "PATH": "/usr/bin:/bin", "USBMUXD_SOCKET_ADDRESS": "127.0.0.1:9",
                   "PYMOBILEDEVICE3_USBMUX": "127.0.0.1:9", "LANG": "en_US.UTF-8"}
            os.makedirs(env["HOME"], exist_ok=True)
            p = subprocess.run([REAL_PMD3] + norm, capture_output=True, text=True, env=env, timeout=120)
            bad = p.returncode == 2 or any(m in p.stderr for m in USAGE_MARKERS)
            _replayed[key] = (bad, p.returncode, p.stderr.strip()[-300:])
        bad, code, tail = _replayed[key]
        if bad:
            problems.append("%s -> exit %s: %s" % (" ".join(argv[:4]), code, tail))
    return problems
