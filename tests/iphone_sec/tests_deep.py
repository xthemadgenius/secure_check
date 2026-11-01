"""Group `deep`: the optional deep scan (public indicator lists, a backup into a private folder, MVT) and what it adds to the
screen, the report and the private folder. X05 of group `fix` ("any [DETECTED] suppresses fixes") lives here as D05b."""
import json
import os
import re
import shutil
import time

from harness import FIX, UDID, Run, Session, base_scenario, has, lacks, no_leak, ok, rc, rtag_lines, tag_lines, test
from tests_fix import ALPHA, NONE_TAKEN, UNSAFE_APP_IDS, UNSAFE_PROFILE_IDS, VPN, removal_calls, scen, stub_state, subsequence
from tests_report import REASSURING, VERDICT_LOOK, VERDICT_OK, in_order, section

BASE = "alice\ny\n\n"                      # name, "this is my phone", Enter at the Trust pause
DEEP = BASE + "y\n"                        # ... then yes to the deep scan
TRICKY = "-Pa ss'\"$HOME\\x*?[ "           # a dash first, spaces, quotes, $, a backslash, glob characters, a trailing space
OLD = "  -old'\"`$(x) pä\\"            # the password already on a phone whose backups are encrypted
UNI = "-pä ss'\"\\é "                      # a password with letters outside ASCII: JSON shows it two ways (ä or ä), Python a third
FULL = DEEP + "y\n%s\n%s\n" % (TRICKY, TRICKY)     # ... yes to "Turn on backup encryption?", the new password twice
PLAIN = DEEP + "n\n"                       # ... no to it: an unencrypted backup
ENC_ON = {"encrypted_initial": True, "password_initial": OLD}
FAKE = {"mvt_fake": {}}                    # MVT's check-backup replaced by a fake that finds nothing (the real one is used where it is the point)
# A fake du that notes whether the private folder still held a decrypted copy at the moment the script measured it
DU_SPY = '''for p; do :; done
if [ -d "$p/decrypted" ]; then echo "present $p" >> "$STUB_DIR/du.log"; else echo "absent $p" >> "$STUB_DIR/du.log"; fi
printf '4.0K\\t%s\\n' "$p"'''
# A fake du that notes how many private folders existed at the moment the script measured something
WORK_SPY = '''for p; do :; done
n=0
for d in "$HOME/Library/Application Support/secure_check"/iphone_*; do
    if [ -e "$d" ]; then n=$((n + 1)); fi
done
echo "folders $n" >> "$STUB_DIR/work.log"
printf '4.0K\\t%s\\n' "$p"'''

DEEP_PROMPT ="Run the deep scan? (y/n): "
ENC_PROMPT = "Turn on backup encryption? (y/n): "
DECLINED = "The deep scan was not run, so the phone's data was not checked against spyware indicators."
STALE = "The indicator lists could not be updated, so the copy already on this Mac is used (it may be out of date)."
DETECTED_VERDICT = "Something known to be linked to spyware was found: do not wipe or remove anything yet, and talk to an expert."
NOT_ENCRYPTED = ("The backup was not encrypted, so it may be missing data that only encrypted backups hold (saved passwords, "
                 "Wi-Fi settings, website history, Health data, call history), and that data was not checked.")
PRIVATE = "~/Library/Application Support/secure_check/iphone_"
INFO_NONE = re.compile(r"^\[INFO\] No known indicators matched in the backup \(checked against [0-9]+ indicator entries\)\. "
                       r"This does not rule out spyware that is not in the public lists\.$")
FOLDER_LINE = re.compile(r"^Private folder: ~/Library/Application Support/secure_check/iphone_\S+ \([0-9.]+[BKMGTP]?\)$", re.M)


def fake(**kw):
    return {"mvt_fake": kw}


def alert(level, module, message, matched=None):
    a = {"level": level, "module": module, "message": message, "event_time": "", "event": {}}
    if matched is not None:
        a["matched_indicator"] = {"value": matched, "type": "file_names", "name": "X", "stix2_file_name": "x.stix2"}
    return a


def go(tid, answers, extra=None, env=None, **kw):
    sc = base_scenario()
    sc.update(extra or {})
    return Run(tid, sc, env_extra=env or {}, **kw).go(answers)


def go_recorded(tid, answers, extra=None):
    """go(), with a python3 first on PATH that notes every argument the script's helper is started with (`-I -c ...`) and is then
    the real one: what `ps` would show any other user of this Mac. The phone tool's own command line is left out: it holds the
    new backup password by design (`backup2 encryption ... on PASSWORD`, said in a comment in the script)."""
    sc = base_scenario()
    sc.update(extra or {})
    r = Run(tid, sc, shebang="#!/usr/bin/env python3")
    r.fake_cmd("python3", 'if [ "$1" = "-I" ] && [ "$2" = "-c" ]; then printf \'%s\\n\' "$@" >> "$STUB_DIR/python_argv.log"; fi\n'
                          'exec /usr/bin/python3 "$@"')
    return r.go(answers)


def python_argv(r):
    """The text of every argument the helper was started with (its own source included), one per line."""
    p = r.stub / "python_argv.log"
    return p.read_text(errors="replace") if p.exists() else ""


def must_tag(r, tag, needle):
    """A [TAG] line holding NEEDLE, on the screen and in the report."""
    for where, lines in (("screen", tag_lines(r, tag)), ("report", rtag_lines(r, tag))):
        ok(any(needle in ln for ln in lines), "no [%s] line with %r on the %s; the [%s] lines were %r" % (tag, needle, where, tag, lines))


def no_tag(r, tag, needle):
    for where, lines in (("screen", tag_lines(r, tag)), ("report", rtag_lines(r, tag))):
        bad = [ln for ln in lines if needle in ln]
        ok(not bad, "unexpected [%s] line with %r on the %s: %r" % (tag, needle, where, bad))


def matched_none(r):
    """Whether the 'no known indicators matched' line is shown (on screen and in the report: both or neither)."""
    scr = any(INFO_NONE.match(ln) for ln in tag_lines(r, "INFO"))
    rep = any(INFO_NONE.match(ln) for ln in rtag_lines(r, "INFO"))
    ok(scr == rep, "the 'no known indicators matched' line is %s on screen but %s in the report" % (scr, rep))
    return scr


def pcalls(r, cmd):
    return [a for a in r.pmd() if a[:2] == cmd.split()]


def mcalls(r, sub):
    return [a for a in r.mvt() if sub in a]


def work(r):
    dirs = r.work_dirs()
    ok(len(dirs) == 1, "expected exactly one private folder, found %r" % [d.name for d in dirs])
    return dirs[0]


def touched_phone(r):
    """Any call that downloads, changes or copies: the lists, the encryption setting, the backup."""
    o = r.order()
    return [c for c in o if c.startswith("mvt:") or c.startswith("pmd:backup2") or c == "pmd:lockdown get"]


def loose_modes(path):
    bad = []
    for p in [path] + list(path.rglob("*")):
        if not p.is_symlink() and p.stat().st_mode & 0o077:
            bad.append((str(p.relative_to(path)), oct(p.stat().st_mode & 0o777)))
    return bad


def files_with(path, needle):
    hits = []
    for p in path.rglob("*"):
        if p.is_file() and not p.is_symlink() and needle.encode() in p.read_bytes():
            hits.append(str(p.relative_to(path)))
    return hits


def crashing_helper(tid, scenario, subcommand, partial=None, env=None):
    """A Run whose python3 dies (exit 3) when the script calls its helper with SUBCOMMAND, after printing PARTIAL (one shell-quoted
    word), and is the real one for everything else."""
    r = Run(tid, scenario, env_extra=env or {}, shebang="#!/usr/bin/env python3")
    show = "printf '%s\\n' " + partial + "\n    " if partial else ""
    r.fake_cmd("python3", 'if [ "$1" = "-I" ] && [ "$2" = "-c" ] && [ "$4" = "' + subcommand + '" ]; then\n    ' + show
               + 'exit 3\nfi\nexec /usr/bin/python3 "$@"')
    return r


def injecting_helper(tid, scenario, line, env=None):
    """A Run whose helper answers `mvt` with LINE put in front of its END line (the real helper does the rest): what a helper
    with a fault of its own would hand the script."""
    r = Run(tid, scenario, env_extra=env or {}, shebang="#!/usr/bin/env python3")
    r.fake_cmd("python3", 'if [ "$1" = "-I" ] && [ "$2" = "-c" ] && [ "$4" = "mvt" ]; then\n'
                          '    /usr/bin/python3 "$@" | while IFS= read -r row; do\n'
                          "        if [ \"$row\" = END ]; then printf '%s\\n' '" + line + "'; fi\n"
                          "        printf '%s\\n' \"$row\"\n"
                          "    done\n    exit 0\nfi\nexec /usr/bin/python3 \"$@\"")
    return r


def wait_for_backup(r, s, timeout=30):
    end = time.time() + timeout
    while not list(r.work_root().glob("iphone_*/backup/*/Info.plist")):
        if time.time() > end:
            s.p.kill()
            raise AssertionError("the backup never started")
        s._pump(0.1)


def wait_for_marker(r, s, name, timeout=30):
    """Block until the stub has written the marker file `name`: the slow call it was told to make has started."""
    end = time.time() + timeout
    while not (r.stub / name).exists():
        if time.time() > end:
            s.p.kill()
            raise AssertionError("the stub never wrote %s" % name)
        s._pump(0.1)


def report_files(r):
    """Names in the report folder, or None if the folder is not there (a stray y can delete it when the prompts are not as expected)."""
    d = r.report_dir()
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else None


def du_seen(r, folder):
    """What the fake du saw for FOLDER: ['present ...'] or ['absent ...'] per call (see DU_SPY)."""
    p = r.stub / "du.log"
    lines = p.read_text().splitlines() if p.exists() else []
    return [ln for ln in lines if ln.endswith(" " + str(folder))]


def work_seen(r):
    """How many private folders existed each time the fake du ran (see WORK_SPY)."""
    p = r.stub / "work.log"
    return [int(ln.split()[1]) for ln in p.read_text().splitlines()] if p.exists() else []


def udid_everywhere(r, label):
    """Every call to a phone names it (--udid ID); left out, a tool would use whichever phone it finds first."""
    for a in r.pmd():
        if a[0] != "usbmux":
            i = a.index("--udid") if "--udid" in a else -1
            ok(i >= 0 and a[i + 1:i + 2] == [UDID], "%s: a call that does not name the phone: %r" % (label, a[:4]))


def to_deep_prompt(s):
    s.until("Enter your name")
    s.send("alice\n")
    s.until("(y/n): ")
    s.send("y\n")
    s.until("Press Enter once")
    s.send("\n")
    s.until(DEEP_PROMPT)


# ---------------------------------------------------------------------------------------------------------------------
# asking first, and the order of things
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D01", "anything but y at the deep-scan prompt skips it: one INFO line, no download, no backup, no private folder")
def d01():
    for label, tail in (("n", "n\n"), ("enter", "\n"), ("eof", ""), ("maybe", "maybe\n"), ("yesplease", "yes please\n")):
        r = go("d01_" + label, BASE + tail)
        rc(r, 0)
        has(r, DEEP_PROMPT)
        must_tag(r, "INFO", DECLINED)
        ok(touched_phone(r) == [], "%s: calls %r" % (label, r.order()))
        ok(r.work_dirs() == [], "%s: private folders %r" % (label, r.work_dirs()))
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions %r" % (label, section(r.report(), "ACTIONS TAKEN")))
        for text in ("Private folder", "Downloading the public", "Making the backup"):
            ok(text not in r.out and text not in r.report(), "%s: did not expect %r" % (label, text))
    return r


@test("deep", "D02", "the deep scan runs in a fixed order: lists, encryption state, encryption, state again, backup, decrypt, MVT")
def d02():
    r = go("d02", FULL, FAKE)
    rc(r, 0)
    udid_everywhere(r, "d02")
    ok("Backup progress: 100%" in r.out + r.err, "the backup tool's own progress is not shown: %r" % (r.out + r.err)[-300:])
    want = ["mvt:download-iocs", "pmd:lockdown get", "pmd:backup2 encryption", "pmd:lockdown get", "pmd:backup2 backup",
            "mvt:decrypt-backup", "mvt:check-backup"]
    ok(subsequence(r.order(), want), "call order %r" % r.order())
    i = r.order().index("pmd:backup2 backup")
    ok([c for c in r.order()[i + 1:] if c.startswith("pmd:")] == [], "the phone was contacted after the backup: %r" % r.order()[i + 1:])
    in_order(r.out, ["Deep scan (optional)", DEEP_PROMPT, "Downloading the public spyware indicator lists...", ENC_PROMPT,
                     "New backup password: ", "Type it again: ", "Backup encryption is now on.", "Making the backup.",
                     "Checking the backup against the indicator lists", "Summary:"])
    return r


@test("deep", "D02b", "nothing is downloaded, changed or made before the prompt that asks for it (encryption off)")
def d02b():
    r = Run("d02b", dict(base_scenario(), **FAKE))
    s = Session(r)
    to_deep_prompt(s)
    ok(touched_phone(r) == [] and r.work_dirs() == [], "before the answer: %r %r" % (r.order(), r.work_dirs()))
    s.send("y\n")
    s.until(ENC_PROMPT)
    o = r.order()
    ok(o.count("mvt:download-iocs") == 1 and o.count("pmd:lockdown get") == 1, "at the encryption prompt: %r" % o)
    ok(not any(c.startswith("pmd:backup2") for c in o) and r.work_dirs() == [], "at the encryption prompt: %r %r" % (o, r.work_dirs()))
    s.send("y\n")
    s.until("New backup password: ")
    ok(not any(c.startswith("pmd:backup2") for c in r.order()) and r.work_dirs() == [], "at the first password prompt")
    s.send(TRICKY + "\n")
    s.until("Type it again: ")
    ok(not any(c.startswith("pmd:backup2") for c in r.order()) and r.work_dirs() == [], "at the second password prompt")
    s.send(TRICKY + "\n")
    r = s.finish()
    rc(r, 0)
    return r


@test("deep", "D02c", "with encryption already on, the password is asked (with the Reset All Settings route) before anything is copied")
def d02c():
    r = Run("d02c", dict(base_scenario(), **ENC_ON, **FAKE))
    s = Session(r)
    to_deep_prompt(s)
    s.send("y\n")
    shown = s.until("Backup password (press Enter to stop): ")
    ok("Reset All Settings" in shown, "no Reset All Settings route before the prompt: %r" % shown[-600:])
    o = r.order()
    ok(not any(c.startswith("pmd:backup2") for c in o) and r.work_dirs() == [], "at the password prompt: %r %r" % (o, r.work_dirs()))
    s.send(OLD + "\n")
    r = s.finish()
    rc(r, 0)
    return r


@test("deep", "D02d", "every tool the script runs gets /dev/null as its input: none can swallow a prompt answer or read the terminal")
def d02d():
    r = go("d02d", FULL, FAKE)
    rc(r, 0)
    seen = r.order()
    for need in ("pmd:usbmux list", "pmd:lockdown info", "pmd:profile list", "pmd:apps list", "mvt:download-iocs", "pmd:lockdown get",
                 "pmd:backup2 encryption", "pmd:backup2 backup", "mvt:decrypt-backup", "mvt:check-backup"):
        ok(need in seen, "the run never made the call %r, so this test would prove nothing: %r" % (need, seen))
    loose = [" ".join(c["argv"][:2]) for c in r.calls() if not c.get("stdin_null")]
    ok(loose == [], "these calls were given something other than /dev/null as input: %r" % loose)
    return r


# ---------------------------------------------------------------------------------------------------------------------
# the public indicator lists
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D03", "lists that cannot be downloaded: UNKNOWN and nothing changed or copied; with an older copy on this Mac it carries on")
def d03():
    for label, extra, why in (("fail", {"ioc_download_fail": True}, "Unable to download indicators"),
                              ("network", {"ioc_download_mode": "network_down"}, "Failed to retrieve indicators index"),
                              ("nothing", {"ioc_download_mode": "nothing"}, "no indicator files were found"),
                              ("stray", {"ioc_download_mode": "nothing", "indicators_preseed": ["notes.txt"]}, "no indicator files were found"),
                              ("folder", {"ioc_download_mode": "nothing", "indicators_preseed": ["dir.stix2/"]}, "no indicator files were found")):
        r = go("d03_" + label, DEEP, dict(extra, **FAKE))      # the scan stops here: more answers would go to the folder prompt
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: the spyware indicator lists could not be downloaded (")
        must_tag(r, "UNKNOWN", why)
        must_tag(r, "UNKNOWN", "). Nothing was changed on the phone.")
        o = r.order()
        ok("mvt:download-iocs" in o, "%s: no download attempt: %r" % (label, o))
        ok([c for c in o if c.startswith("pmd:backup2") or c == "pmd:lockdown get"] == [] and "mvt:check-backup" not in o,
           "%s: went on: %r" % (label, o))
        ok(r.work_dirs() == [], "%s: private folders %r" % (label, r.work_dirs()))
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions" % label)
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
        lacks(r, VERDICT_OK)
    r = go("d03_old", FULL, dict({"ioc_download_mode": "network_down", "indicators_preseed": ["synth.stix2"]}, **FAKE))
    rc(r, 0)
    must_tag(r, "INFO", STALE)
    ok("pmd:backup2 backup" in r.order() and "mvt:check-backup" in r.order(), "did not go on with the old lists: %r" % r.order())
    ok(matched_none(r), "no 'nothing matched' line with the old lists")
    no_tag(r, "UNKNOWN", "indicator lists")
    return r


@test("deep", "D03b", "lists in a folder whose name has a space (MVT_DATA_FOLDER) are found; so are the ones in MVT's default folder")
def d03b():
    r = Run("d03b", dict(base_scenario(), backup_flags=["--evil"], ioc_download_fail=True))
    spaced = r.root / "mvt data"
    (spaced / "indicators").mkdir(parents=True)
    shutil.copy(FIX / "synth.stix2", spaced / "indicators" / "synth.stix2")
    r.env["MVT_DATA_FOLDER"] = str(spaced)
    r.go(PLAIN)
    rc(r, 0)
    must_tag(r, "INFO", STALE)
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "manifest" check: Found a known suspicious file name "evil.db"')
    r = Run("d03b_default", dict(base_scenario()), env_drop=("MVT_DATA_FOLDER",)).go(PLAIN)
    rc(r, 0)
    ok((r.home / "Library" / "Application Support" / "mvt" / "indicators" / "synth.stix2").is_file(), "the stub did not use the default folder")
    ok(matched_none(r), "the lists in the default folder were not used")
    no_tag(r, "UNKNOWN", "indicator")
    return r


# ---------------------------------------------------------------------------------------------------------------------
# encryption: off -> on
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D04", "off -> on: the password reaches only the encryption call (after --) and the decrypt environment; the rest is scanned and reported")
def d04():
    r = go("d04", FULL)
    rc(r, 0)
    enc = pcalls(r, "backup2 encryption")
    ok(len(enc) == 1, "encryption calls %r" % enc)
    w = work(r)
    a = enc[0]
    ok(a[-3:] == ["--", "on", TRICKY], "the call ends %r" % a[-3:])
    ok(a[a.index("-b") + 1] == str(w), "-b is %r, the private folder is %s" % (a[a.index("-b") + 1], w))
    ok(a[a.index("--udid") + 1] == UDID, "--udid in %r" % a)
    ok(stub_state(r)["password"] == TRICKY and stub_state(r)["encrypted"] is True, "the phone's state: %r" % stub_state(r))
    for argv in r.pmd() + r.mvt():
        if argv is not a and argv != a:
            ok(TRICKY not in " ".join(argv) and TRICKY.strip() not in " ".join(argv), "the password is on a command line: %r" % argv[:3])
    dec = [c for c in r.calls() if c["tool"] == "mvt-ios" and "decrypt-backup" in c["argv"]]
    ok(len(dec) == 1 and dec[0]["env_pw"] == TRICKY, "decrypt calls %r" % dec)
    ok([c for c in r.calls() if c != dec[0] and c.get("env_pw")] == [], "the password was passed to another call")
    leaks = [(c["tool"], c["argv"][:3], c["env_leak"]) for c in r.calls() if c.get("env_leak")]
    ok(leaks == [] and all("env_leak" in c for c in r.calls()), "the password was in the environment of: %r" % leaks)
    da = dec[0]["argv"]
    ok(da[:da.index("decrypt-backup")] == ["--disable-update-check"], "decrypt options %r" % da)
    ok(da[da.index("-d") + 1] == str(w / "decrypted") and da[-1] == str(w / "backup" / UDID), "decrypt paths %r" % da[-4:])
    ok("-p" not in da and "--password" not in da, "a password option on the decrypt call")
    dl = mcalls(r, "download-iocs")
    ok(len(dl) == 1 and dl[0] == ["--disable-update-check", "download-iocs"], "download call %r" % dl)
    chk = mcalls(r, "check-backup")[0]
    i = chk.index("check-backup")
    ok(chk[:i] == ["--disable-update-check", "--disable-indicator-update-check"], "check options %r" % chk[:i])
    ok(chk[chk.index("-o") + 1] == str(w / "mvt_results") and chk[-1] == str(w / "decrypted"), "check paths %r" % chk[i:])
    ok(matched_none(r), "no 'nothing matched' line: %r" % tag_lines(r, "INFO"))
    for text in (r.out, r.report()):
        ok(section(text, "Summary:") == [VERDICT_OK], "verdict %r" % section(text, "Summary:"))
        words = (section(text, "Summary:") or []) + [ln for ln in text.splitlines() if "No known indicators matched" in ln]
        ok(not REASSURING.search("\n".join(words)), "the verdict or the 'nothing matched' line sounds like a guarantee: %r" % words)
    ok(loose_modes(w) == [], "group/other access in the private folder: %r" % loose_modes(w)[:3])
    ok(files_with(w, TRICKY) == [] and files_with(w, TRICKY.strip()) == [], "the password is in %r" % files_with(w, TRICKY))
    acts = section(r.report(), "ACTIONS TAKEN")
    in_order("\n".join(acts), ["Turned on backup encryption on the phone (a backup password you chose; it stays until you turn it off).",
                               "Made a backup of the phone into a private folder on this Mac (not part of the ZIP)."])
    ok(NONE_TAKEN not in acts, "actions %r" % acts)
    in_order(r.report(), ["ACTIONS TAKEN", "Private folder (backup and raw MVT results, not part of this ZIP): " + PRIVATE, "WHAT THIS SCAN CANNOT SEE"])
    in_order(r.out, ["You need this password to use the backup. Write it down.", ENC_PROMPT])
    for text in ('untick "Encrypt local backup"', "briefly see the password"):
        in_order(r.out, [text, ENC_PROMPT])
    ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())
    no_leak(r, TRICKY, TRICKY.strip(), UDID, "00008150", "SYNTH0001")
    return r


@test("deep", "D04b", "a real decrypt is the stub's job, but the decrypted copy is removed and the evidence is kept in the private folder")
def d04b():
    r = go("d04b", FULL, FAKE)
    rc(r, 0)
    w = work(r)
    ok((w / "backup" / UDID / "Manifest.db").is_file(), "no backup in %s" % w)
    ok((w / "mvt_results" / "info.json").is_file() and (w / "mvt_console.txt").is_file(), "no MVT results: %r" % sorted(p.name for p in w.iterdir()))
    ok(not (w / "decrypted").exists(), "the decrypted copy was left behind")
    ok(r.zip_names() == ["iphone_security_report.txt"], "ZIP holds %r" % r.zip_names())
    ok(report_files(r) == ["iphone_security_report.txt"], "report folder holds %r" % report_files(r))
    no_leak(r, "FAKESERIAL-IN-MVT-RESULTS", UDID)
    return r


@test("deep", "D04c", "the decrypted copy is removed as soon as MVT has run, not only when the script exits")
def d04c():
    r = Run("d04c", dict(base_scenario(), **FAKE))
    r.fake_cmd("du", DU_SPY)
    r.go(FULL + "n\nn\n")
    rc(r, 0)
    w = work(r)
    ok(mcalls(r, "check-backup")[0][-1] == str(w / "decrypted"), "MVT did not check the decrypted copy: %r" % mcalls(r, "check-backup"))
    ok(du_seen(r, w) == ["absent " + str(w)], "when the script measured the private folder: %r" % du_seen(r, w))
    ok(not (w / "decrypted").exists(), "the decrypted copy was left behind")
    return r


@test("deep", "D05a", "a real MVT detection: [DETECTED], the expert advice, nothing reassuring, the folder kept, only the report in the ZIP")
def d05a():
    r = go("d05a", PLAIN, {"backup_flags": ["--evil"]})
    rc(r, 0)
    line = ('[DETECTED] MVT HIGH alert in the "manifest" check: Found a known suspicious file name "evil.db" '
            'matching indicators from "SyntheticTestMalware"')
    ok(line in tag_lines(r, "DETECTED") and line in rtag_lines(r, "DETECTED"), "detected lines %r / %r" % (tag_lines(r, "DETECTED"), rtag_lines(r, "DETECTED")))
    for text in (r.out, r.report()):
        ok("Summary: 1 DETECTED, " in text, "summary %r" % [ln for ln in text.splitlines() if ln.startswith("Summary")])
        ok(section(text, "Summary:") == [DETECTED_VERDICT], "verdict %r" % section(text, "Summary:"))
        first = section(text, "What to do first:")
        ok(first is not None and len(first) == 3, "what to do first: %r" % first)
        ok("destroy evidence" in first[0] and "https://securitylab.amnesty.org/get-help/?c=mvt" in first[1] and "do not email" in first[2], "block %r" % first)
        ok(not REASSURING.search(DETECTED_VERDICT + " ".join(first)), "reassuring word")
    in_order(r.out, ["Summary:", "What to do first:", "What this scan cannot see:"])
    nxt = section(r.out, "Next steps:")
    ok(nxt is not None and len(nxt) == 4 and nxt[0].strip().startswith("FIRST:"), "next steps %r" % nxt)
    ok(r.zip_names() == ["iphone_security_report.txt"], "ZIP holds %r" % r.zip_names())
    ok(len(r.work_dirs()) == 1, "the private folder was not kept")
    has(r, "Delete the private folder anyway? An expert may need it as evidence. (y/n): ")
    return r


@test("deep", "D05b", "any [DETECTED] switches the fixes off, even with APPLY=1 and a y for each: nothing is removed (was X05)")
def d05b():
    r = Run("d05b", scen(apps=[ALPHA], profiles=[VPN], backup_flags=["--evil"]), env_extra={"APPLY": "1"}).go(PLAIN + "y\ny\n")
    rc(r, 0)
    ok('[DETECTED] MVT HIGH alert in the "manifest" check' in r.out, "no detection: %r" % tag_lines(r, "DETECTED"))
    ok(removal_calls(r) == [], "removal calls %r" % removal_calls(r))
    st = stub_state(r)
    ok(st["removed_apps"] == [] and st["removed_profiles"] == [], "the phone was changed: %r" % st)
    has(r, "Fixes are switched off because something known to be linked to spyware was found: removing apps or profiles can "
           "destroy the evidence an expert needs. Talk to an expert first.")
    for text in ("Remove the app", "Remove the configuration profile", "APPLY=1 ./iphone_sec.sh", "can be removed from here",
                 "Only the items listed above", "by hand"):
        lacks(r, text)
    in_order(r.out, ['[REVIEW] App "Alpha Sideload"', "Fixes:", "Fixes are switched off", "Summary:"])
    ok("[DETECTED] MVT HIGH alert" in r.zip_text(), "the ZIP's report has no detection")
    ok(NONE_TAKEN not in r.zip_text() or "backup" in r.zip_text(), "actions")
    return r


@test("deep", "D05c", "without a [DETECTED] the fixes stay available after a deep scan (a REVIEW or UNKNOWN does not switch them off)")
def d05c():
    sc = scen(apps=[ALPHA], **fake(alerts=[alert("MEDIUM", "m", "something odd")]))
    r = Run("d05c", sc, env_extra={"APPLY": "1"}).go(PLAIN + "y\n")
    rc(r, 0)
    must_tag(r, "REVIEW", 'MVT MEDIUM alert in the "m" check: something odd')      # the deep scan really ran (the y above is for the fix prompt)
    ok(removal_calls(r) == [["apps", "uninstall", "--udid", UDID, "com.dev.alpha"]], "removal calls %r" % removal_calls(r))
    has(r, "Fixes:")
    lacks(r, "Fixes are switched off")
    return r


@test("deep", "D05d", "with a [DETECTED] nothing is listed to remove by hand either (the same phone without one lists them)")
def d05d():
    apps = [(b, "Name%d" % i) for i, b in enumerate(UNSAFE_APP_IDS)]
    profs = [(p, "Prof%d" % i, "Org") for i, p in enumerate(UNSAFE_PROFILE_IDS)]
    answers = PLAIN + "y\ny\ny\ny\n"
    r = Run("d05d", scen(apps=apps, profiles=profs, backup_flags=["--evil"]), env_extra={"APPLY": "1"}).go(answers)
    rc(r, 0)
    ok('[DETECTED] MVT HIGH alert in the "manifest" check' in r.out, "no detection: %r" % tag_lines(r, "DETECTED"))
    has(r, "Fixes are switched off")
    for text in ("cannot be removed from here", "yourself:", "can be removed from here."):
        lacks(r, text)
    ok(removal_calls(r) == [], "removal calls %r" % removal_calls(r))
    r = Run("d05d_ctl", scen(apps=apps, profiles=profs, **FAKE), env_extra={"APPLY": "1"}).go(answers)
    rc(r, 0)
    lacks(r, "Fixes are switched off")
    for text in ("15 flagged apps cannot be removed from here. Remove them yourself: press and hold the app's icon",
                 "5 flagged configuration profiles cannot be removed from here. Remove them yourself: Settings > General"):
        has(r, text)
    return r


# ---------------------------------------------------------------------------------------------------------------------
# encryption already on
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D06", "encryption already on: the password decrypts via the environment only; no encryption call; it never leaves")
def d06():
    r = go("d06", DEEP + OLD + "\n", dict(ENC_ON, **FAKE))
    rc(r, 0)
    udid_everywhere(r, "d06")
    ok(pcalls(r, "backup2 encryption") == [], "encryption calls %r" % pcalls(r, "backup2 encryption"))
    dec = [c for c in r.calls() if c["tool"] == "mvt-ios" and "decrypt-backup" in c["argv"]]
    ok(len(dec) == 1 and dec[0]["env_pw"] == OLD, "decrypt calls %r" % dec)
    ok([c for c in r.calls() if c != dec[0] and c.get("env_pw")] == [], "the password was passed to another call")
    leaks = [(c["tool"], c["argv"][:3], c["env_leak"]) for c in r.calls() if c.get("env_leak")]
    ok(leaks == [] and all("env_leak" in c for c in r.calls()), "the password was in the environment of: %r" % leaks)
    for argv in r.pmd() + r.mvt():
        ok(OLD not in " ".join(argv) and OLD.strip() not in " ".join(argv), "the password is on a command line: %r" % argv[:3])
    in_order(r.out, ["Backup password (press Enter to stop): ", "Making the backup."])
    ok(matched_none(r), "scan did not complete: %r" % tag_lines(r, "UNKNOWN"))
    acts = section(r.report(), "ACTIONS TAKEN")
    ok(not any("Turned on backup encryption" in ln for ln in acts) and any("Made a backup" in ln for ln in acts), "actions %r" % acts)
    w = work(r)
    ok(files_with(w, OLD) == [] and loose_modes(w) == [], "password in the private folder or loose modes")
    no_leak(r, OLD, OLD.strip(), UDID)
    return r


@test("deep", "D07", "wrong passwords are asked again (3 tries in all, Enter gives up); the encrypted backup stays in the private folder")
def d07():
    r = go("d07_ok", DEEP + "bad1\nbad2\n" + OLD + "\n", dict(ENC_ON, **FAKE))
    rc(r, 0)
    ok(r.out.count("That password did not open the backup.") == 2, "messages: %d" % r.out.count("That password did not open the backup."))
    has(r, "MVT said: ")
    lacks(r, UDID)
    ok(matched_none(r), "did not carry on after the right password")
    r = go("d07_bad", DEEP + "bad1\nbad2\nbad3\nignored\n", dict(ENC_ON, **FAKE))
    rc(r, 0)
    ok(r.out.count("That password did not open the backup.") == 3, "messages: %d" % r.out.count("That password did not open the backup."))
    must_tag(r, "UNKNOWN", "The deep scan could not check the backup: it could not be opened with the password(s) given.")
    ok(mcalls(r, "check-backup") == [], "MVT ran on an unopened backup")
    w = work(r)
    ok((w / "backup" / UDID / "Manifest.db").is_file() and not (w / "decrypted").exists(), "private folder holds %r" % sorted(p.name for p in w.iterdir()))
    ok(not matched_none(r), "claimed nothing matched")
    r = go("d07_enter", DEEP + "bad1\n\n", dict(ENC_ON, **FAKE))
    rc(r, 0)
    ok(r.out.count("That password did not open the backup.") == 1, "messages: %d" % r.out.count("That password did not open the backup."))
    must_tag(r, "UNKNOWN", "it could not be opened with the password(s) given.")
    no_leak(r, "bad1", "bad2", "bad3")
    return r


@test("deep", "D07b", "a decrypt that exits 0 but leaves no usable Manifest.db is not a success: asked again, the empty copy removed, MVT not run")
def d07b():
    for label, mode in (("empty", True), ("missing", "missing")):
        r = Run("d07b_" + label, dict(base_scenario(), decrypt_empty=mode, **ENC_ON, **FAKE))
        r.fake_cmd("du", DU_SPY)
        r.go(DEEP + (OLD + "\n") * 3 + "n\nn\n")
        rc(r, 0)
        ok(r.out.count("That password did not open the backup.") == 3, "%s: messages: %d" % (label, r.out.count("That password did not open the backup.")))
        ok(len(mcalls(r, "decrypt-backup")) == 3, "%s: decrypt calls %r" % (label, mcalls(r, "decrypt-backup")))
        must_tag(r, "UNKNOWN", "The deep scan could not check the backup: it could not be opened with the password(s) given.")
        ok(mcalls(r, "check-backup") == [], "%s: MVT ran on an unopened backup" % label)
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
        w = work(r)
        ok(du_seen(r, w) == ["absent " + str(w)], "%s: when the script measured the private folder: %r" % (label, du_seen(r, w)))
    return r


@test("deep", "D07c", "a decrypt tool that prints the password back: it never reaches the screen, in any spelling or past the length cap")
def d07c():
    for label, pw, said in (("mid", TRICKY, "Could not decrypt with the password {pw} (stub)"),
                            ("end", TRICKY, "Could not decrypt with the password {pw}"),
                            ("cap", TRICKY, "x" * 136 + " {pw} tail"),            # "CRITICAL: " is 10 more, so the password starts at character 147
                            ("repr", TRICKY, "Could not decrypt with the password {repr} (stub)"),
                            ("json", TRICKY, "Could not decrypt with the password {json} (stub)"),
                            ("uni", UNI, "Could not decrypt with the password {pw} (stub)"),
                            ("unijson", UNI, "Could not decrypt with the password {json} (stub)"),
                            ("unijsonu", UNI, "Could not decrypt with the password {jsonu} (stub)")):
        r = go_recorded("d07c_" + label, DEEP + pw + "\n" + OLD + "\n", dict(ENC_ON, decrypt_echoes_password=said, **FAKE))
        rc(r, 0)
        ok(r.out.count("That password did not open the backup.") == 1, "%s: messages: %d" % (label, r.out.count("That password did not open the backup.")))
        shown = [ln for ln in r.out.splitlines() if "MVT said: " in ln]
        ok(len(shown) == 1 and "(password)" in shown[0], "%s: the 'MVT said' lines: %r" % (label, shown))
        ok(matched_none(r), "%s: did not carry on after the right password" % label)
        no_leak(r, pw, pw.strip(), pw.strip()[:6], repr(pw)[1:-1], json.dumps(pw)[1:-1], json.dumps(pw, ensure_ascii=False)[1:-1], OLD, OLD.strip())
        argv = python_argv(r)
        ok("\nreason\n" in "\n" + argv, "%s: the helper was never asked to read the tool's output" % label)
        ok(pw.strip() not in argv and OLD.strip() not in argv, "%s: a password was on a command line, where ps shows it" % label)
    return r


@test("deep", "D08","no password for an encrypted phone: UNKNOWN, no backup, no private folder (Enter and end of input alike)")
def d08():
    for label, tail in (("enter", "\n"), ("eof", "")):
        r = go("d08_" + label, DEEP + tail, dict(ENC_ON, **FAKE))
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: no backup password was given. Nothing was changed on the phone.")
        in_order(r.out, ["Reset All Settings", "Backup password (press Enter to stop): "])
        ok([c for c in r.order() if c.startswith("pmd:backup2")] == [] and r.work_dirs() == [], "%s: %r" % (label, r.order()))
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions" % label)
    return r


# ---------------------------------------------------------------------------------------------------------------------
# what real MVT leaves behind when something goes wrong
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D09", "a module that crashed inside MVT (exit 0, 0 alerts) is UNKNOWN, never 'nothing matched'")
def d09():
    r = go("d09", PLAIN, {"ioc_fixture": "synth_fileonly.stix2"})
    rc(r, 0)
    must_tag(r, "UNKNOWN", "MVT logged an error, so part of the check did not run: Error when checking indicators from module Manifest")
    ok(not matched_none(r), "claimed nothing matched")
    for text in (r.out, r.report()):
        ok(section(text, "Summary:") == [VERDICT_LOOK], "verdict %r" % section(text, "Summary:"))
    return r


@test("deep", "D10", "an incomplete or partial backup is UNKNOWN, never 'nothing matched'")
def d10():
    for label, flag in (("partial", "--partial"), ("incomplete", "--incomplete")):
        r = go("d10_" + label, PLAIN, {"backup_flags": [flag]})
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The backup may be incomplete, so part of it was not checked. MVT said: ")
        must_tag(r, "UNKNOWN", "missing from the backup folder")
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
    return r


@test("deep", "D11", "a backup that did not finish (failed, empty, failed at the end) is UNKNOWN with the folder shown; MVT is not run")
def d11():
    for label, extra, said in (("fail", {"backup_fail": "Backup failed: the device was locked"}, "Backup failed: the device was locked"),
                               ("empty", {"backup_empty": True}, None),
                               ("after", {"backup_fail_after": "Backup finished with an error"}, "Backup finished with an error"),
                               ("nodb", {"backup_flags": ["--no-db"]}, None),
                               ("noplist", {"backup_flags": ["--no-plist"]}, None)):      # exit 0, but a file is missing
        r = go("d11_" + label, PLAIN, dict(extra, **FAKE))
        rc(r, 0)
        ok(said is None or said in r.out + r.err, "%s: the backup tool's own message is not shown (the finding says 'see the messages above')" % label)
        must_tag(r, "UNKNOWN", "The backup did not finish (see the messages above), so the deep scan could not check the phone. "
                               "The partial backup is in the private folder: " + PRIVATE)
        ok(mcalls(r, "check-backup") == [] and mcalls(r, "decrypt-backup") == [], "%s: MVT ran" % label)
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
        acts = section(r.report(), "ACTIONS TAKEN")
        ok(any("Started a backup of the phone into a private folder on this Mac; it did not finish." in ln for ln in acts)
           and not any("Made a backup" in ln for ln in acts), "%s: actions %r" % (label, acts))
        ok("Private folder (backup and raw MVT results, not part of this ZIP): " + PRIVATE in r.report(), "%s: no folder line" % label)
        ok(len(r.work_dirs()) == 1, "%s: private folder removed" % label)
    return r


@test("deep", "D12", "the backup's own passcode flag: INFO, REVIEW or UNKNOWN; the 'not checked' block goes only when the answer is known")
def d12():
    block = "Not checked by this script:"
    for label, flag, tag, text, shown in (
            ("true", "true", "INFO", "The backup says a passcode is set on the iPhone (from the backup).", False),
            ("false", "false", "REVIEW", "The backup says no passcode is set on the iPhone (from the backup). Set one under Settings > Face ID & Passcode.", False),
            ("missing", "missing", "UNKNOWN", "The backup did not say whether a passcode is set (from the backup).", True)):
        r = go("d12_" + label, PLAIN, dict(FAKE, backup_flags=["--passcode", flag]))
        rc(r, 0)
        must_tag(r, tag, text)
        ok((block in r.out) == shown, "%s: 'not checked' block on screen: %s" % (label, block in r.out))
        ok(block not in r.report(), "%s: the report has the screen-only block" % label)
        ok("1. Passcode:" in r.report(), "%s: the checklist lost its passcode item" % label)
    r = go("d12_declined", BASE + "n\n")
    ok(block in r.out, "declined deep scan: the 'not checked' block is gone")
    return r


@test("deep", "D13", "the private folder keeps the backup and MVT's raw results, and nothing else")
def d13():
    r = go("d13", FULL, FAKE)
    w = work(r)
    ok(sorted(p.name for p in w.iterdir()) == ["backup", "mvt_console.txt", "mvt_results"], "holds %r" % sorted(p.name for p in w.iterdir()))
    ok((w / "mvt_results" / "info.json").is_file() and (w / "backup" / UDID / "Manifest.plist").is_file(), "missing files")
    ok(re.fullmatch(r"iphone_\d{8}_\d{6}\.[A-Za-z0-9]{6}", w.name), "folder name %r" % w.name)
    return r


@test("deep", "D15", "an unreadable encryption state: UNKNOWN, nothing changed or copied")
def d15():
    for label, extra, why in (("fail", {"willencrypt_fail": "boom: cannot talk to the phone"}, "boom: cannot talk to the phone"),
                              ("garbage", {"willencrypt_raw": "maybe"}, "the answer was not true or false"),
                              ("empty", {"willencrypt_raw": ""}, "the answer was empty")):
        r = go("d15_" + label, DEEP, dict(extra, **FAKE))      # the scan stops here: more answers would go to the folder prompt
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: the phone did not say whether its backups are encrypted (")
        must_tag(r, "UNKNOWN", why)
        must_tag(r, "UNKNOWN", "). Nothing was changed on the phone.")
        ok([c for c in r.order() if c.startswith("pmd:backup2")] == [] and r.work_dirs() == [], "%s: went on: %r" % (label, r.order()))
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions" % label)
    return r


@test("deep", "D16", "the ZIP and the report folder hold only the report; the private folder is never inside either")
def d16():
    r = go("d16", FULL, FAKE)
    work(r)                                                     # a private folder was made, and it is somewhere else
    ok(r.zip_names() == ["iphone_security_report.txt"], "ZIP holds %r" % r.zip_names())
    ok(report_files(r) == ["iphone_security_report.txt"], "folder holds %r" % report_files(r))
    has(r, "Files included (1):")
    return r


# ---------------------------------------------------------------------------------------------------------------------
# the private folder: asking before it goes, and never deleting the wrong thing
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D17", "the private folder is deleted only on y; the evidence wording is used when something was detected")
def d17():
    q = "Delete the private folder (the backup and MVT's raw results)? (y/n): "
    for label, tail, gone in (("y", "n\ny\n", True), ("yes", "n\nyes\n", True), ("n", "n\nn\n", False), ("eof", "n\n", False),
                              ("junk", "n\nmaybe\n", False)):
        r = go("d17_" + label, PLAIN + tail, FAKE)
        rc(r, 0)
        ok(FOLDER_LINE.search(r.out), "no folder line with a size: %r" % r.out[-900:])
        has(r, "It holds the iPhone's data (the backup and MVT's raw results) and is not part of the ZIP.")
        has(r, q)
        lacks(r, "anyway")
        ok((r.work_dirs() == []) == gone, "%s: private folders %r" % (label, r.work_dirs()))
        has(r, "Private folder deleted." if gone else "The private folder was kept: " + PRIVATE)
        lacks(r, "stopped before it finished")
        ok(r.report_dir().exists(), "%s: the report folder prompt took the wrong answer" % label)
    det = dict(fake(alerts=[alert("HIGH", "m", "bad")]))
    qd = "Delete the private folder anyway? An expert may need it as evidence. (y/n): "
    r = go("d17_det", PLAIN + "n\nn\n", det)
    has(r, qd)
    lacks(r, q)
    ok(len(r.work_dirs()) == 1, "kept by default when something was detected")
    r = go("d17_det_y", PLAIN + "y\ny\n", det)
    ok(r.work_dirs() == [] and not r.report_dir().exists() and r.zip_path().exists(), "y,y: %r %s" % (r.work_dirs(), r.report_dir().exists()))
    has(r, "Private folder deleted.")
    return r


@test("deep", "D17c", "a private folder that cannot be fully removed is never reported as deleted, whether rm fails or only pretends")
def d17c():
    q = "Delete the private folder (the backup and MVT's raw results)? (y/n): "
    for label in ("locked", "liar"):
        if label == "locked":
            r = Run("d17c_locked", dict(base_scenario(), **fake(locked_dir=True)))      # a file inside a read-only folder
        else:
            r = Run("d17c_liar", dict(base_scenario(), **FAKE))
            r.fake_cmd("rm", 'case "$*" in *iphone_2*) exit 0 ;; esac\nexec /bin/rm "$@"')       # says yes, removes nothing
        try:
            r.go(PLAIN + "n\ny\n")
            rc(r, 0)
            has(r, q)
            has(r, "The private folder could not be fully removed: " + PRIVATE)
            lacks(r, "Private folder deleted.")
            ok(len(r.work_dirs()) == 1, "%s: private folders %r" % (label, r.work_dirs()))
        finally:
            for p in r.root.rglob("*"):
                if p.is_dir() and not p.is_symlink():
                    p.chmod(0o700)
    return r


@test("deep", "D17b", "the sizes shown for the private folder and the ZIP ignore du's padding; when du cannot say, the line says size unknown")
def d17b():
    last = 'for p; do :; done\n'
    for label, body, want in (("padded", last + "printf ' 44K\\t%s\\n' \"$p\"", "44K"),      # macOS pads 2-digit sizes with a space
                              ("plain", last + "printf '4.0K\\t%s\\n' \"$p\"", "4.0K"),
                              ("fails", last + "printf ' 44K\\t%s\\n' \"$p\"\nexit 1", "size unknown"),
                              ("silent", "exit 0", "size unknown")):
        r = Run("d17b_" + label, dict(base_scenario(), **FAKE))
        r.fake_cmd("du", body)
        r.go(PLAIN + "n\nn\n")
        rc(r, 0)
        folder = [ln for ln in r.out.splitlines() if ln.startswith("Private folder: ")]
        ok(len(folder) == 1 and folder[0].endswith(" (%s)" % want), "%s: folder line %r" % (label, folder))
        zipl = [ln for ln in r.out.splitlines() if ln.startswith("   ZIP: ")]      # the first one (the start banner) has no size
        ok(len(zipl) == 2 and zipl[1].endswith(" (%s)" % want), "%s: ZIP lines %r" % (label, zipl))
    return r


@test("deep", "D18", "Ctrl-C during the backup: exit 130, the partial backup is kept and its folder shown, no temp files, no report")
def d18():
    r = Run("d18", dict(base_scenario(), backup_sleep="60", **FAKE))
    s = Session(r, new_session=True)
    to_deep_prompt(s)
    s.send("y\n")
    s.until(ENC_PROMPT)
    s.send("n\n")
    s.until("Making the backup.")
    wait_for_backup(r, s)
    s.interrupt()
    r = s.finish(timeout=60)
    rc(r, 130)
    has(r, "The script stopped before it finished.")
    has(r, PRIVATE)
    w = work(r)
    ok((w / "backup" / UDID / "Info.plist").is_file(), "the partial backup is gone")
    ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())
    ok(not r.report_dir().exists() and r.zip_names() is None, "a report was left")
    return r


@test("deep", "D18b", "Ctrl-C at a password prompt: exit 130, no private folder, nothing changed on the phone")
def d18b():
    r = Run("d18b", dict(base_scenario(), **FAKE))
    s = Session(r, new_session=True)
    to_deep_prompt(s)
    s.send("y\n")
    s.until(ENC_PROMPT)
    s.send("y\n")
    s.until("New backup password: ")
    s.interrupt()
    r = s.finish(timeout=60)
    rc(r, 130)
    ok(r.work_dirs() == [] and [c for c in r.order() if c.startswith("pmd:backup2")] == [], "went on: %r" % r.order())
    lacks(r, "The script stopped before it finished.")
    ok(r.tmp_leftovers() == [], "temp files left: %r" % r.tmp_leftovers())
    return r


@test("deep", "D18c", "Ctrl-C while backup encryption is being turned on or confirmed: exit 130 and a note that the phone's setting may have changed; no note once it is on")
def d18c():
    cases = (("call", dict(encryption_sleep="60"), "encryption_started", True),
             ("confirm", dict(confirm_sleep="60"), "confirm_started", True),
             ("backup", dict(backup_sleep="60"), None, False))        # encryption is on by then, and the screen said so
    for label, extra, marker, noted in cases:
        r = Run("d18c_" + label, dict(base_scenario(), **dict(extra, **FAKE)))
        s = Session(r, new_session=True)
        to_deep_prompt(s)
        s.send("y\n")
        s.until(ENC_PROMPT)
        s.send("y\n")
        s.until("New backup password: ")
        s.send(TRICKY + "\n")
        s.until("Type it again: ")
        s.send(TRICKY + "\n")
        if marker:
            wait_for_marker(r, s, marker)
        else:
            wait_for_backup(r, s)
        s.interrupt()
        r = s.finish(timeout=60)
        rc(r, 130)
        if noted:
            has(r, "The script stopped while it was turning on backup encryption on the phone.")
            has(r, "Encrypt local backup")
            has(r, "the password you just typed is its backup password")
            lacks(r, "The script stopped before it finished.")
            ok(pcalls(r, "backup2 backup") == [], "%s: the backup was started: %r" % (label, r.order()))
            ok(r.work_dirs() == [], "%s: private folders %r" % (label, r.work_dirs()))
        else:
            lacks(r, "turning on backup encryption")
            has(r, "The script stopped before it finished.")
            has(r, PRIVATE)
        ok(r.tmp_leftovers() == [], "%s: temp files left: %r" % (label, r.tmp_leftovers()))
        ok(not r.report_dir().exists() and r.zip_names() is None, "%s: a report was left" % label)
        no_leak(r, UDID, TRICKY, TRICKY.strip())
    return r


@test("deep", "D19","turning encryption on fails: UNKNOWN that says the setting may have changed, no backup, the folder is removed, the attempt is in ACTIONS")
def d19():
    for label, extra in (("plain", {}), ("files", {"encryption_writes_file": True})):
        sc = base_scenario()
        sc.update(extra, encryption_on_fail="Could not turn encryption on for " + UDID, **FAKE)
        r = Run("d19_" + label, sc)
        r.fake_cmd("du", WORK_SPY)
        r.go(FULL)
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: turning backup encryption on failed (")
        must_tag(r, "UNKNOWN", "Check the phone's backup setting in Finder: it may have changed. No backup was made.")
        ok("pmd:backup2 backup" not in r.order() and mcalls(r, "check-backup") == [], "%s: went on: %r" % (label, r.order()))
        ok(r.work_dirs() == [], "%s: private folders %r" % (label, r.work_dirs()))
        acts = section(r.report(), "ACTIONS TAKEN")
        tried = [ln for ln in acts if "Tried to turn on backup encryption on the phone" in ln]
        ok(len(tried) == 1, "%s: actions %r" % (label, acts))
        unknown = [ln for ln in tag_lines(r, "UNKNOWN") if "The deep scan could not run" in ln]
        ok(len(unknown) == 1, "%s: UNKNOWN lines %r" % (label, unknown))
        ok(len(pcalls(r, "lockdown get")) == 1, "%s: the encryption state was read again after the failure: %r" % (label, pcalls(r, "lockdown get")))
        seen = work_seen(r)        # the exit cleanup would remove a folder left behind, so look while the script is still running
        ok(seen != [] and set(seen) == {0}, "%s: private folders when the script measured the ZIP: %r" % (label, seen))
        has(r, "(phone ID)")
        no_leak(r, UDID, TRICKY, TRICKY.strip())
        ok("Private folder" not in r.report(), "%s: the report names a folder that was removed" % label)
    return r


@test("deep", "D19c", "a tool that prints the new backup password back in its error: it never reaches the screen, in any spelling or past the length cap")
def d19c():
    lead = "  zq' wlk"                  # leading spaces are what the message's own whitespace swallows
    for label, pw, said in (("mid", TRICKY, "rejected the backup password %s as invalid" % TRICKY),
                            ("end", TRICKY, "rejected the backup password " + TRICKY),
                            ("start", lead, lead + " is not allowed"),
                            ("cap", TRICKY, "x" * 146 + " " + TRICKY + " tail"),
                            ("repr", TRICKY, "rejected the backup password " + repr(TRICKY) + " as invalid"),
                            ("json", TRICKY, "rejected the backup password " + json.dumps(TRICKY) + " as invalid"),
                            ("uni", UNI, "rejected the backup password " + UNI + "as invalid"),
                            ("unijson", UNI, "rejected the backup password " + json.dumps(UNI) + " as invalid"),
                            ("unijsonu", UNI, "rejected the backup password " + json.dumps(UNI, ensure_ascii=False) + " as invalid")):
        r = go_recorded("d19c_" + label, DEEP + "y\n%s\n%s\n" % (pw, pw), dict(encryption_on_fail=said, **FAKE))
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: turning backup encryption on failed (")
        must_tag(r, "UNKNOWN", "(password)")
        no_leak(r, pw, pw.strip(), pw.strip()[:6], repr(pw)[1:-1], json.dumps(pw)[1:-1], json.dumps(pw, ensure_ascii=False)[1:-1])
        argv = python_argv(r)
        ok("\nreason\n" in "\n" + argv, "%s: the helper was never asked to read the tool's output" % label)
        ok(pw.strip() not in argv, "%s: the password was on a command line, where ps shows it" % label)
    return r


@test("deep", "D21", "backup password entry: empty and mismatched tries are refused (3 tries); end of input counts as empty")
def d21():
    r = go("d21_ok", DEEP + "y\n\n" + "a1\nb2\n" + TRICKY + "\n" + TRICKY + "\n", FAKE)
    rc(r, 0)
    has(r, "The password cannot be empty.")
    has(r, "The two passwords did not match. Try again.")
    ok(len(pcalls(r, "backup2 encryption")) == 1 and pcalls(r, "backup2 encryption")[0][-1] == TRICKY, "the third try was not used")
    for label, tail in (("empty3", "y\n\n\n\n"), ("mismatch3", "y\na\nb\na\nb\na\nb\n"), ("eof", "y\n"),
                        ("fourth", "y\n\na\nb\na\nb\n" + TRICKY + "\n" + TRICKY + "\n")):        # a valid pair, but only as the fourth try
        r = go("d21_" + label, DEEP + tail, FAKE)
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: no backup password was set. Nothing was changed on the phone.")
        ok(pcalls(r, "backup2 encryption") == [] and pcalls(r, "backup2 backup") == [] and r.work_dirs() == [], "%s: went on" % label)
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions" % label)
    no_leak(r, "a1", "b2")
    return r


@test("deep", "D22", "not turning encryption on (n, Enter, end of input, anything else) gives an unencrypted backup and says what that misses")
def d22():
    for label, tail in (("n", "n\n"), ("enter", "\n"), ("eof", ""), ("junk", "yes please\n")):
        r = go("d22_" + label, DEEP + tail, FAKE)
        rc(r, 0)
        udid_everywhere(r, "d22_" + label)
        must_tag(r, "INFO", NOT_ENCRYPTED)
        ok(pcalls(r, "backup2 encryption") == [] and mcalls(r, "decrypt-backup") == [], "%s: encrypted anyway" % label)
        ok(mcalls(r, "check-backup")[0][-1] == str(work(r) / "backup" / UDID), "%s: checked %r" % (label, mcalls(r, "check-backup")[0][-1]))
        acts = section(r.report(), "ACTIONS TAKEN")
        ok(not any("Turned on" in ln for ln in acts) and any("Made a backup" in ln for ln in acts), "%s: actions %r" % (label, acts))
    return r


@test("deep", "D23", "encryption that the phone does not confirm: UNKNOWN, no backup, the attempt is in ACTIONS")
def d23():
    r = Run("d23", dict(base_scenario(), encryption_on_noop=True, **FAKE))
    r.fake_cmd("du", WORK_SPY)
    r.go(FULL)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "The deep scan could not run: the phone did not confirm that backup encryption is on.")
    ok("pmd:backup2 backup" not in r.order() and r.work_dirs() == [], "went on: %r" % r.order())
    acts = section(r.report(), "ACTIONS TAKEN")
    ok(any("Tried to turn on backup encryption on the phone" in ln for ln in acts), "actions %r" % acts)
    seen = work_seen(r)        # the exit cleanup would remove a folder left behind, so look while the script is still running
    ok(seen != [] and set(seen) == {0}, "private folders when the script measured the ZIP: %r" % seen)
    return r


# ---------------------------------------------------------------------------------------------------------------------
# judging MVT's results (a fake check-backup in the real formats, so every outcome can be produced)
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D24", "an MVT that exits non-zero is UNKNOWN, never 'nothing matched'")
def d24():
    r = go("d24", PLAIN, fake(exit=3))
    rc(r, 0)
    must_tag(r, "UNKNOWN", "MVT did not finish normally (exit status 3), so the backup was not fully checked.")
    ok(not matched_none(r), "claimed nothing matched")
    return r


@test("deep", "D25", "alert levels map to tags: CRITICAL/HIGH DETECTED, MEDIUM REVIEW, LOW INFO, informational counted in one INFO line")
def d25():
    alerts = [alert("CRITICAL", "m1", "msg-critical"), alert("HIGH", "m2", "msg-high"), alert("MEDIUM", "m3", "msg-medium"),
              alert("LOW", "m4", "msg-low"), alert("INFORMATIONAL", "m5", "msg-i1"), alert("INFORMATIONAL", "m5", "msg-i2")]
    r = go("d25", PLAIN, fake(alerts=alerts))
    rc(r, 0)
    must_tag(r, "DETECTED", 'MVT CRITICAL alert in the "m1" check: msg-critical')
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "m2" check: msg-high')
    must_tag(r, "REVIEW", 'MVT MEDIUM alert in the "m3" check: msg-medium')
    must_tag(r, "INFO", 'MVT LOW alert in the "m4" check: msg-low')
    must_tag(r, "INFO", "MVT also recorded 2 informational alerts.")
    ok("msg-i1" not in r.out and "msg-i2" not in r.out, "informational alerts were listed one by one")
    ok("Summary: 2 DETECTED, 1 REVIEW, " in r.out and "Summary: 2 DETECTED, 1 REVIEW, " in r.report(), "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    ok(not matched_none(r), "claimed nothing matched")
    ok(tag_lines(r, "DETECTED") == rtag_lines(r, "DETECTED"), "screen and report disagree")
    r = go("d25_one", PLAIN, fake(alerts=[alert("INFORMATIONAL", "m", "x")]))
    must_tag(r, "INFO", "MVT also recorded 1 informational alert.")
    r = go("d25_count", PLAIN, fake(alerts=[], counts={"INFORMATIONAL": 3}))        # MVT's own summary counts them, its file lists none
    rc(r, 0)
    must_tag(r, "INFO", "MVT also recorded 3 informational alerts.")
    must_tag(r, "UNKNOWN", "MVT's summary says 3 INFORMATIONAL alerts but its alerts file lists 0, so the findings may be incomplete.")
    return r


@test("deep", "D26", "at most 25 alerts per level are listed; the rest are counted in one line, and the counts stay true")
def d26():
    r = go("d26", PLAIN, fake(alerts=[alert("HIGH", "m", "msg %02d" % i) for i in range(30)]))
    rc(r, 0)
    listed = [ln for ln in tag_lines(r, "DETECTED") if "MVT HIGH alert in" in ln]
    ok(len(listed) == 25 and "msg 24" in listed[-1] and not any("msg 25" in ln for ln in listed), "listed %d" % len(listed))
    must_tag(r, "DETECTED", "...and 5 more MVT HIGH alerts (see alerts.json in the private folder).")
    ok("Summary: 30 DETECTED, " in r.out and "Summary: 30 DETECTED, " in r.report(), "summary")
    r = go("d26_one", PLAIN, fake(alerts=[alert("HIGH", "m", "msg %02d" % i) for i in range(26)]))
    must_tag(r, "DETECTED", "...and 1 more MVT HIGH alert (see alerts.json in the private folder).")
    r = go("d26_med", PLAIN, fake(alerts=[alert("MEDIUM", "m", "msg %02d" % i) for i in range(27)]))
    must_tag(r, "REVIEW", "...and 2 more MVT MEDIUM alerts (see alerts.json in the private folder).")
    ok("Summary: 0 DETECTED, 27 REVIEW, " in r.out, "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    return r


@test("deep", "D27", "an alert with a level this script does not know is UNKNOWN (never dropped, never 'nothing matched')")
def d27():
    r = go("d27", PLAIN, fake(alerts=[alert("SEVERE", "m", "weird thing")]))
    rc(r, 0)
    must_tag(r, "UNKNOWN", 'MVT reported an alert with an unrecognised level ("SEVERE"), so it was not sorted: weird thing')
    ok(not matched_none(r), "claimed nothing matched")
    return r


@test("deep", "D28", "MVT's own counts must agree with its alerts file: a gap is UNKNOWN, and missing HIGH/CRITICAL alerts still count as DETECTED")
def d28():
    r = go("d28_more", PLAIN, fake(alerts=[alert("HIGH", "m", "one")], counts={"HIGH": 2}))
    rc(r, 0)
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "m" check: one')
    must_tag(r, "DETECTED", "MVT's own summary counts 1 more HIGH alert than its alerts file lists (see the private folder).")
    must_tag(r, "UNKNOWN", "MVT's summary says 2 HIGH alerts but its alerts file lists 1, so the findings may be incomplete.")
    ok("Summary: 2 DETECTED, " in r.out and ", 1 UNKNOWN" in r.out, "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    r = go("d28_less", PLAIN, fake(alerts=[alert("HIGH", "m", "one")], counts={}))
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "m" check: one')
    must_tag(r, "UNKNOWN", "MVT's summary says 0 HIGH alerts but its alerts file lists 1, so the findings may be incomplete.")
    ok("Summary: 1 DETECTED, " in r.out, "summary")
    r = go("d28_nofile", PLAIN, fake(counts={"CRITICAL": 2}))
    must_tag(r, "DETECTED", "MVT's own summary counts 2 more CRITICAL alerts than its alerts file lists (see the private folder).")
    must_tag(r, "UNKNOWN", "MVT's summary says 2 CRITICAL alerts but its alerts file lists 0, so the findings may be incomplete.")
    ok("Summary: 2 DETECTED, " in r.out, "summary")
    r = go("d28_unreadable", PLAIN, fake(alerts_raw="{oops", counts={"HIGH": 1}))
    must_tag(r, "UNKNOWN", "MVT's alerts file could not be read, so its findings are not known.")
    must_tag(r, "DETECTED", "MVT's own summary counts 1 more HIGH alert than its alerts file lists (see the private folder).")
    no_tag(r, "UNKNOWN", "summary says")
    r = go("d28_med", PLAIN, fake(alerts=[], counts={"MEDIUM": 1}))
    must_tag(r, "REVIEW", "MVT's own summary counts 1 more MEDIUM alert than its alerts file lists (see the private folder).")
    return r


@test("deep", "D29", "an MVT summary panel that cannot be found, or an alerts file that cannot be read, is UNKNOWN")
def d29():
    r = go("d29_panel", PLAIN, fake(alerts=[alert("MEDIUM", "m", "still shown")], console_raw="nothing useful\n"))
    rc(r, 0)
    must_tag(r, "UNKNOWN", "MVT's summary of alerts could not be found in its output, so the alert counts were not cross-checked.")
    must_tag(r, "REVIEW", 'MVT MEDIUM alert in the "m" check: still shown')
    ok(not matched_none(r), "claimed nothing matched")
    for label, raw in (("badjson", "{not json"), ("object", '{"a": 1}'), ("numbers", "[1, 2]"), ("empty", "")):
        r = go("d29_" + label, PLAIN, fake(alerts_raw=raw))
        must_tag(r, "UNKNOWN", "MVT's alerts file could not be read, so its findings are not known.")
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
    return r


@test("deep", "D30", "text MVT hands back is cleaned: control characters become ?, | becomes /, the phone's ID is masked, the serial never shows")
def d30():
    msg = "bad \x1b[31mred\x1b[0m | pipe %s end" % UDID
    r = go("d30", PLAIN, fake(alerts=[alert("HIGH", "mod|\x07x", msg)]))
    rc(r, 0)
    line = '[DETECTED] MVT HIGH alert in the "mod/?x" check: bad ?[31mred?[0m / pipe (phone ID) end'
    ok(line in tag_lines(r, "DETECTED") and line in rtag_lines(r, "DETECTED"), "lines %r / %r" % (tag_lines(r, "DETECTED"), rtag_lines(r, "DETECTED")))
    ok("\x1b[31mred" not in r.raw and "\x07" not in r.raw, "raw control characters from MVT reached the screen")
    no_leak(r, UDID, "FAKESERIAL-IN-MVT-RESULTS")
    return r


@test("deep", "D30b", "text MVT hands back is capped: a module name at 40 characters, an alert at 200, a logged error at 160, each ending in ...")
def d30b():
    module, msg, err = "abcdefghij" * 10, "ABCDEFGHIJ" * 40, "klmnopqrst" * 30       # none holds a run that looks like a phone ID
    r = go("d30b", PLAIN, fake(alerts=[alert("HIGH", module, msg)], log=[["mvt.ios.modules.x", "ERROR", err]]))
    rc(r, 0)
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "%s..." check: %s...' % (module[:37], msg[:197]))
    must_tag(r, "UNKNOWN", "MVT logged an error, so part of the check did not run: %s..." % err[:157])
    for what, text in (("module name", module[:38]), ("alert", msg[:198]), ("logged error", err[:158])):
        ok(text not in r.out and text not in r.report(), "the %s was not cut at its cap" % what)
    return r


@test("deep", "D31","MVT's 'outdated iOS' warning is a REVIEW; it does not hide the 'nothing matched' line")
def d31():
    text = "This phone is running an outdated iOS version: 26.0 (latest is 27.2)"
    r = go("d31", PLAIN, fake(log=[["mvt.ios.cmd_check_backup", "WARNING", text]]))
    rc(r, 0)
    must_tag(r, "REVIEW", text)
    must_tag(r, "REVIEW", "Settings > General > Software Update")
    ok(matched_none(r), "the outdated warning hid the 'nothing matched' line")
    return r


@test("deep", "D32", "no indicators loaded (0, or no line saying so) is UNKNOWN: nothing was checked against anything")
def d32():
    for label, kw in (("zero", {"indicators": 0}), ("noline", {"no_indicator_line": True})):
        r = go("d32_" + label, PLAIN, fake(**kw))
        rc(r, 0)
        must_tag(r, "UNKNOWN", "MVT did not report loading any indicators, so nothing was checked against them.")
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
    return r


@test("deep", "D33", "an MVT run without its completion marker or its log is UNKNOWN")
def d33():
    r = go("d33_info", PLAIN, fake(no_info=True))
    must_tag(r, "UNKNOWN", "MVT did not finish (it left no completion marker), so the backup was not fully checked.")
    ok(not matched_none(r), "no marker: claimed nothing matched")
    r = go("d33_log", PLAIN, fake(no_log=True))
    must_tag(r, "UNKNOWN", "MVT's log could not be read, so it is not known whether every check ran.")
    no_tag(r, "UNKNOWN", "did not report loading")
    ok(not matched_none(r), "no log: claimed nothing matched")
    return r


@test("deep", "D34", "logged errors: each distinct one is UNKNOWN (capped at 25), but a CRITICAL line that is only a detection's own log is not")
def d34():
    r = go("d34_same", PLAIN, fake(alerts=[alert("CRITICAL", "m", "Known bad thing")],
                                  log=[["mvt.ios.modules.x", "CRITICAL", "Known bad thing"]]))
    rc(r, 0)
    must_tag(r, "DETECTED", 'MVT CRITICAL alert in the "m" check: Known bad thing')
    ok("Summary: 1 DETECTED, 0 REVIEW, " in r.out and ", 0 UNKNOWN" in r.out, "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    r = go("d34_other", PLAIN, fake(alerts=[alert("CRITICAL", "m", "Known bad thing")],
                                   log=[["mvt.ios.modules.x", "CRITICAL", "Something else broke"], ["mvt.ios.modules.x", "ERROR", "Something else broke"]]))
    ok(len([ln for ln in tag_lines(r, "UNKNOWN") if "Something else broke" in ln]) == 1, "duplicates: %r" % tag_lines(r, "UNKNOWN"))
    must_tag(r, "UNKNOWN", "MVT logged an error, so part of the check did not run: Something else broke")
    r = go("d34_many", PLAIN, fake(log=[["mvt.ios.modules.x", "ERROR", "failure %02d" % i] for i in range(30)]))
    ok(len([ln for ln in tag_lines(r, "UNKNOWN") if "MVT logged an error" in ln]) == 25, "listed %r" % len(tag_lines(r, "UNKNOWN")))
    must_tag(r, "UNKNOWN", "...and 5 more MVT errors (see command.log in the private folder).")
    ok(", 30 UNKNOWN" in r.out, "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    r = go("d34_critical", PLAIN, fake(log=[["mvt.ios.modules.x", "CRITICAL", "Standalone critical problem"]]))      # CRITICAL alone, no ERROR line
    rc(r, 0)
    must_tag(r, "UNKNOWN", "MVT logged an error, so part of the check did not run: Standalone critical problem")
    return r


@test("deep", "D35","a matched indicator on a LOW alert also withholds the 'nothing matched' line; a LOW alert with no match does not")
def d35():
    r = go("d35_plain", PLAIN, fake(alerts=[alert("LOW", "m", "meh")]))
    must_tag(r, "INFO", 'MVT LOW alert in the "m" check: meh')
    ok(matched_none(r), "a LOW alert with no match hid the line")
    r = go("d35_match", PLAIN, fake(alerts=[alert("LOW", "m", "meh", matched="evil.db")]))
    must_tag(r, "INFO", 'MVT LOW alert in the "m" check: meh')
    ok(not matched_none(r), "claimed nothing matched with a matched indicator")
    return r


# ---------------------------------------------------------------------------------------------------------------------
# guards and failures of the script's own parts
# ---------------------------------------------------------------------------------------------------------------------
@test("deep", "D41", "a backup whose own state cannot be read (no encryption flag, not a plist, the wrong kind of plist) is UNKNOWN: MVT does not run")
def d41():
    for label, flag, why in (("noflag", "--no-encflag", "it did not say whether it is encrypted"),
                             ("garbage", "--bad-plist", "the backup's Manifest.plist could not be read"),
                             ("list", "--list-plist", "the backup's Manifest.plist was not in the expected format")):
        r = go("d41_" + label, PLAIN, dict(FAKE, backup_flags=[flag]))
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not check the backup: its state could not be read (%s)." % why)
        ok(mcalls(r, "check-backup") == [] and mcalls(r, "decrypt-backup") == [], "%s: MVT ran" % label)
        ok(not matched_none(r), "%s: claimed nothing matched" % label)
        no_tag(r, "INFO", "The backup says a passcode")
        acts = section(r.report(), "ACTIONS TAKEN")
        ok(any("Made a backup" in ln for ln in acts), "%s: actions %r" % (label, acts))
        ok(len(r.work_dirs()) == 1, "%s: the backup was not kept" % label)
    return r


@test("deep", "D38", "the private folder is deleted only if it is still the folder the script made (a swapped-in symlink is refused)")
def d38():
    r = Run("d38", dict(base_scenario(), **FAKE))
    s = Session(r)
    to_deep_prompt(s)
    s.send("y\n")
    s.until(ENC_PROMPT)
    s.send("n\n")
    s.until("Delete the folder and keep only the ZIP? (y/n): ")
    s.send("n\n")
    s.until("Delete the private folder (the backup and MVT's raw results)? (y/n): ")
    w = work(r)
    moved = w.with_name(w.name + ".moved")
    w.rename(moved)
    decoy = r.root / "decoy"
    decoy.mkdir()
    (decoy / "keep.txt").write_text("keep")
    os.symlink(decoy, w)
    s.send("y\n")
    r = s.finish()
    rc(r, 0)
    has(r, "The private folder was not removed because it is not the folder this script made: " + PRIVATE)
    ok((decoy / "keep.txt").read_text() == "keep" and moved.is_dir() and w.is_symlink(), "something was removed")
    lacks(r, "Private folder deleted.")
    return r


@test("deep", "D38b", "a private folder swapped for a symlink before the end is not shown or offered for deletion at all")
def d38b():
    r = Run("d38b", dict(base_scenario(), **FAKE))
    s = Session(r)
    to_deep_prompt(s)
    s.send("y\n")
    s.until(ENC_PROMPT)
    s.send("n\n")
    s.until("Delete the folder and keep only the ZIP? (y/n): ")
    w = work(r)
    moved = w.with_name(w.name + ".moved")
    w.rename(moved)
    decoy = r.root / "decoy"
    decoy.mkdir()
    (decoy / "keep.txt").write_text("keep")
    os.symlink(decoy, w)
    s.send("n\n")
    r = s.finish()
    rc(r, 0)
    for text in ("Private folder:", "It holds the iPhone's data", "Delete the private folder", "The private folder was kept", "Private folder deleted."):
        lacks(r, text)
    ok((decoy / "keep.txt").read_text() == "keep" and moved.is_dir() and w.is_symlink(), "something was removed")
    return r


@test("deep", "D39", "a private-folder parent that is a symlink is refused before the phone is changed (encryption off or on)")
def d39():
    for label, answers in (("plain", PLAIN), ("enc", FULL)):
        r = Run("d39_" + label, dict(base_scenario(), **FAKE))
        decoy = r.root / "decoy"
        decoy.mkdir()
        (r.home / "Library" / "Application Support").mkdir(parents=True)
        os.symlink(decoy, r.work_root())
        r.go(answers)
        rc(r, 0)
        must_tag(r, "UNKNOWN", "The deep scan could not run: the private folder for the backup could not be made (")
        must_tag(r, "UNKNOWN", "). Nothing was changed on the phone.")
        ok([c for c in r.order() if c.startswith("pmd:backup2")] == [], "%s: went on: %r" % (label, r.order()))
        unknown = [ln for ln in tag_lines(r, "UNKNOWN") if "The deep scan could not run" in ln]
        ok(len(unknown) == 1, "%s: UNKNOWN lines %r" % (label, unknown))
        ok(len(pcalls(r, "lockdown get")) == 1, "%s: the encryption state was read again: %r" % (label, pcalls(r, "lockdown get")))
        ok(list(decoy.iterdir()) == [], "%s: something was written through the symlink: %r" % (label, list(decoy.iterdir())))
        ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "%s: actions" % label)
    return r


@test("deep", "D39b", "a private-folder parent that is a plain file is refused (and called that), and the file is left alone")
def d39b():
    r = Run("d39b", dict(base_scenario(), **FAKE))
    (r.home / "Library" / "Application Support").mkdir(parents=True)
    r.work_root().write_text("not a folder")
    r.go(PLAIN)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "The deep scan could not run: the private folder for the backup could not be made (")
    must_tag(r, "UNKNOWN", "is a link or not a folder")
    ok(r.work_root().is_file() and r.work_root().read_text() == "not a folder", "the file was changed")
    ok([c for c in r.order() if c.startswith("pmd:backup2")] == [], "went on: %r" % r.order())
    ok(section(r.report(), "ACTIONS TAKEN") == [NONE_TAKEN], "actions")
    return r


@test("deep", "D40", "if the script's own helper dies, the deep scan says UNKNOWN (and still shows what it already had)")
def d40():
    r = crashing_helper("d40_enc", dict(base_scenario(), **FAKE), "willencrypt").go(DEEP)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "the phone did not say whether its backups are encrypted (its answer could not be read)")
    ok([c for c in r.order() if c.startswith("pmd:backup2")] == [] and r.work_dirs() == [], "went on: %r" % r.order())
    r = crashing_helper("d40_state", dict(base_scenario(), **FAKE), "backupstate").go(PLAIN)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "The deep scan could not check the backup: its state could not be read (")
    ok(mcalls(r, "check-backup") == [] and mcalls(r, "decrypt-backup") == [], "MVT ran")
    has(r, "Not checked by this script:")
    r = crashing_helper("d40_mvt", dict(base_scenario(), **FAKE), "mvt",
                        partial="'F|DETECTED|1|MVT HIGH alert in the \"x\" check: boom'").go(PLAIN)
    rc(r, 0)
    must_tag(r, "DETECTED", 'MVT HIGH alert in the "x" check: boom')
    must_tag(r, "UNKNOWN", "MVT finished, but its results could not be read, so the backup was not fully checked.")
    ok(not matched_none(r), "claimed nothing matched")
    ok("Summary: 1 DETECTED, " in r.out, "summary")
    # A helper that answers with a tag the script does not know, or a weight that is not a number
    r = injecting_helper("d40_badtag", dict(base_scenario(), **FAKE), "F|ZZZ|1|text from nowhere").go(PLAIN)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "MVT finished, but its results could not be read, so the backup was not fully checked.")
    for text in ("[ZZZ]", "text from nowhere"):
        ok(text not in r.out and text not in r.report(), "an unknown tag was shown: %r" % text)
    ok(not matched_none(r), "claimed nothing matched")
    r = injecting_helper("d40_weight", dict(base_scenario(), **FAKE), "F|UNKNOWN|abc|a weird weight").go(PLAIN)
    rc(r, 0)
    must_tag(r, "UNKNOWN", "a weird weight")
    ok(", 1 UNKNOWN" in r.out and ", 1 UNKNOWN" in r.report(), "summary %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    return r
