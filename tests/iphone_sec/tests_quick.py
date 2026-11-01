"""Group `quick`: the read-only checks (phone details, profiles, apps) and what happens to text the phone sends."""
import json
import re

from harness import (UDID, UDID2, Run, app, base_scenario, device, has, no_leak, ok, profile_response, rc, rtag_lines,
                     tag_lines, test)

ANSWERS = "alice\ny\n\nn\n"        # name, "this is my phone", Enter at the Trust pause, "n" to the deep scan
STORE = "Apple iPhone OS Application Signing"


def scen(**changes):
    sc = base_scenario()
    sc.update(changes)
    return sc


def about(r, tag, word):
    return [ln for ln in tag_lines(r, tag) if word in ln.lower()]


def same_in_report(r, tag):
    ok(tag_lines(r, tag) == rtag_lines(r, tag), "[%s] lines differ between screen and report:\n%r\n%r"
       % (tag, tag_lines(r, tag), rtag_lines(r, tag)))


@test("quick", "Q01", "clean phone -> INFO lines only; serial, phone number, IMEI and phone ID never appear")
def q01():
    r = Run("q01").go(ANSWERS)
    rc(r, 0)
    for tag in ("DETECTED", "REVIEW", "UNKNOWN"):
        ok(not tag_lines(r, tag) and not rtag_lines(r, tag), "unexpected [%s] lines: %r" % (tag, tag_lines(r, tag)))
    info = tag_lines(r, "INFO")
    ok(any("No configuration profiles are installed" in ln for ln in info), "no profiles line: %r" % info)
    ok(any("App Store signature present on all 2 apps you installed" in ln for ln in info), "no apps line: %r" % info)
    same_in_report(r, "INFO")
    rep = r.report()
    for text in ("Test iPhone", "iPhone18,2", "27.2", "24B119"):
        ok(text in rep, "report lacks %r" % text)
    no_leak(r, "SECRETSERIAL123", "+1 555 000 1234", "359999999999999", UDID)
    return r


@test("quick", "Q02", "an installed profile is REVIEW with its name, organisation and id (none -> INFO)")
def q02():
    r = Run("q02", scen(profiles=profile_response(("com.acme.mdm.wifi", "Acme Wi-Fi", "Acme Corp")))).go(ANSWERS)
    rc(r, 0)
    lines = tag_lines(r, "REVIEW")
    ok(len(lines) == 1, "REVIEW lines: %r" % lines)
    for text in ("Acme Wi-Fi", "Acme Corp", "com.acme.mdm.wifi"):
        ok(text in lines[0], "%r missing from %r" % (text, lines[0]))
    ok(not any("No configuration profiles" in ln for ln in tag_lines(r, "INFO")), "also claims no profiles")
    same_in_report(r, "REVIEW")
    return r


@test("quick", "Q03", "user apps without Apple's App Store signature are REVIEW; system apps are never judged")
def q03():
    sc = base_scenario()
    sc["apps"]["com.side.load"] = app("com.side.load", "Side Loaded", signer="iPhone Developer: Some One (ABCDE12345)")
    sc["apps"]["com.look.alike"] = app("com.look.alike", "Look Alike", signer=STORE + " Inc")
    sc["apps"]["com.apple.odd"] = app("com.apple.odd", "Odd System", "System", signer="Somebody Else")
    r = Run("q03", sc).go(ANSWERS)
    rc(r, 0)
    lines = tag_lines(r, "REVIEW")
    ok(len(lines) == 2, "REVIEW lines: %r" % lines)
    side = [ln for ln in lines if "Side Loaded" in ln]
    look = [ln for ln in lines if "Look Alike" in ln]
    ok(len(side) == 1 and all(t in side[0] for t in ("com.side.load", "iPhone Developer: Some One (ABCDE12345)")), lines)
    ok(len(look) == 1 and all(t in look[0] for t in ("com.look.alike", STORE + " Inc")), lines)
    ok("Odd System" not in r.out and "Notes Plus" not in " ".join(lines), "wrong apps were judged")
    ok(any("App Store signature present on 2 of the 4 apps you installed" in ln for ln in tag_lines(r, "INFO")),
       "INFO lines: %r" % tag_lines(r, "INFO"))
    same_in_report(r, "REVIEW")
    return r


@test("quick", "Q04", "apps list fails -> UNKNOWN with the reason, never INFO; other checks still run; phone ID masked")
def q04():
    r = Run("q04", scen(apps_fail="Device not found: %s (unplug and retry)" % UDID)).go(ANSWERS)
    rc(r, 0)
    unk = about(r, "UNKNOWN", "apps")
    ok(len(unk) == 1 and "unplug and retry" in unk[0], "UNKNOWN lines: %r" % tag_lines(r, "UNKNOWN"))
    ok(len(tag_lines(r, "UNKNOWN")) == 1, "more than one UNKNOWN: %r" % tag_lines(r, "UNKNOWN"))
    ok(not any("App Store" in ln for ln in tag_lines(r, "INFO")), "apps reported as checked")
    ok(any("No configuration profiles" in ln for ln in tag_lines(r, "INFO")), "the profile check did not run")
    same_in_report(r, "UNKNOWN")
    no_leak(r, UDID)
    return r


BAD_PROFILE_ANSWERS = [
    ("not JSON", "this is not json"),
    ("empty", ""),
    ("a list", "[]"),
    ("no profile lists at all", json.dumps({"Status": "Acknowledged"})),
    ("not acknowledged", json.dumps({"Status": "Error", "OrderedIdentifiers": []})),
    ("identifiers not a list", json.dumps({"Status": "Acknowledged", "OrderedIdentifiers": "abc"})),
    ("metadata not a dict", json.dumps({"Status": "Acknowledged", "ProfileMetadata": []})),
]


@test("quick", "Q05", "profile list garbage, or a failing command -> exactly one UNKNOWN, never 'no profiles'")
def q05():
    last = None
    for i, (label, raw) in enumerate(BAD_PROFILE_ANSWERS):
        r = Run("q05_%d" % i, scen(profiles_raw=raw)).go(ANSWERS)
        ok(r.rc == 0, "%s: exit %r" % (label, r.rc))
        ok(len(tag_lines(r, "UNKNOWN")) == 1 and about(r, "UNKNOWN", "profile"), "%s: %r" % (label, tag_lines(r, "UNKNOWN")))
        ok(not any("No configuration profiles" in ln for ln in tag_lines(r, "INFO")), "%s: claims no profiles" % label)
        ok(not tag_lines(r, "REVIEW"), "%s: REVIEW lines %r" % (label, tag_lines(r, "REVIEW")))
        ok(any("App Store" in ln for ln in tag_lines(r, "INFO")), "%s: the apps check did not run" % label)
        last = r
    r = Run("q05_fail", scen(profiles_fail="Lockdown said no (try again)")).go(ANSWERS)
    rc(r, 0)
    unk = tag_lines(r, "UNKNOWN")
    ok(len(unk) == 1 and "try again" in unk[0] and "profile" in unk[0].lower(), "failing command: %r" % unk)
    same_in_report(r, "UNKNOWN")
    return last


EMPTY_PROFILE_ANSWERS = [
    {"Status": "Acknowledged", "OrderedIdentifiers": [], "ProfileManifest": {}, "ProfileMetadata": {}},
    {"Status": "Acknowledged", "ProfileMetadata": {}},
    {"Status": "Acknowledged", "OrderedIdentifiers": []},
]


@test("quick", "Q06", "an acknowledged, explicitly empty profile list -> INFO 'none installed' (three accepted shapes)")
def q06():
    last = None
    for i, answer in enumerate(EMPTY_PROFILE_ANSWERS):
        r = Run("q06_%d" % i, scen(profiles=answer)).go(ANSWERS)
        ok(r.rc == 0, "shape %d: exit %r" % (i, r.rc))
        ok(any("No configuration profiles are installed" in ln for ln in tag_lines(r, "INFO")), "shape %d: %r" % (i, r.out))
        ok(not tag_lines(r, "UNKNOWN") and not tag_lines(r, "REVIEW"), "shape %d: unexpected findings" % i)
        last = r
    return last


@test("quick", "Q07", "no SignerIdentity on any user app -> exactly one UNKNOWN, no REVIEW, no 'App Store' claim")
def q07():
    sc = base_scenario()
    for a in sc["apps"].values():
        a.pop("SignerIdentity", None)
    r = Run("q07", sc).go(ANSWERS)
    rc(r, 0)
    unk = tag_lines(r, "UNKNOWN")
    ok(len(unk) == 1 and "did not say who signed any of the 2 apps" in unk[0], "UNKNOWN lines: %r" % unk)
    ok(not tag_lines(r, "REVIEW"), "REVIEW lines: %r" % tag_lines(r, "REVIEW"))
    ok(not any("App Store" in ln for ln in tag_lines(r, "INFO")), "claims App Store signatures")
    same_in_report(r, "UNKNOWN")
    return r


@test("quick", "Q08", "some user apps without a signer -> one UNKNOWN for those, the rest are still judged")
def q08():
    sc = base_scenario()
    sc["apps"]["com.example.chat"].pop("SignerIdentity")
    sc["apps"]["com.side.load"] = app("com.side.load", "Side Loaded", signer="Dev Person")
    r = Run("q08", sc).go(ANSWERS)
    rc(r, 0)
    unk = tag_lines(r, "UNKNOWN")
    ok(len(unk) == 1 and "1 of the 3 apps you installed did not say who signed" in unk[0], "UNKNOWN lines: %r" % unk)
    ok(len(tag_lines(r, "REVIEW")) == 1 and "Side Loaded" in tag_lines(r, "REVIEW")[0], tag_lines(r, "REVIEW"))
    ok(any("App Store signature present on 1 of the 3 apps you installed" in ln for ln in tag_lines(r, "INFO")),
       "INFO lines: %r" % tag_lines(r, "INFO"))
    return r


EVIL = "\x1b[2J\x1b]0;PWNED\x07Evil‮Name\r\nINJECTED|[INFO] fake finding %s %n \\033[31m"


@test("quick", "Q09", "escape codes, newlines, pipes, bidi marks and printf codes in names are neutralised on screen AND in the report")
def q09():
    sc = base_scenario()
    bundle = "com.evil.app\x1b[1m;rm"
    sc["apps"][bundle] = app(bundle, EVIL, signer="Dev \x1b[31mRED\x1b[0m\r\nINJECTED2" + "x" * 300)
    sc["profiles"] = profile_response(("com.evil.profile", EVIL, "Org|\x1b[1mBold\x07"))
    r = Run("q09", sc).go(ANSWERS)
    rc(r, 0)
    rep = r.report()
    for where, text in (("screen", r.raw), ("stderr", r.err), ("report", rep)):
        for bad in ("\x1b", "\x07", "\r", "‮"):
            ok(bad not in text, "%r reached the %s" % (bad, where))
        for ln in text.splitlines():
            ok(not ln.startswith(("INJECTED", "[INFO] fake")), "injected line on the %s: %r" % (where, ln))
            ok(len(ln) < 500, "overlong line on the %s: %r" % (where, ln[:80]))
    ok(len(tag_lines(r, "REVIEW")) == 2, "REVIEW lines: %r" % tag_lines(r, "REVIEW"))
    has(r, "%s %n \\033[31m")                 # printf codes and backslashes stay literal text
    ok("%s %n \\033[31m" in rep, "report altered the literal text")
    same_in_report(r, "REVIEW")
    return r


@test("quick", "Q10", "lockdown info fails or is unreadable -> says the phone did not answer, how to retry, exit 1, nothing written")
def q10():
    last = None
    for i, changes in enumerate(({"lockdown_fail": "Pairing dialog still pending"}, {"lockdown_raw": "garbage"},
                                 {"lockdown_raw": "{}"}, {"lockdown_raw": json.dumps([1, 2])})):
        r = Run("q10_%d" % i, scen(**changes)).go(ANSWERS)
        ok(r.rc == 1, "case %d: exit %r" % (i, r.rc))
        ok("ERROR:" in r.out and "Trust" in r.out and "run this script again" in r.out, "case %d: no guidance:\n%s" % (i, r.out[-600:]))
        ok(r.pmd_cmds() == ["usbmux list", "lockdown info"], "case %d: calls %r" % (i, r.pmd_cmds()))
        ok(not r.report_dir().exists() and not r.zip_path().exists(), "case %d: files were written" % i)
        ok(not any(tag_lines(r, t) for t in ("INFO", "REVIEW", "UNKNOWN", "DETECTED")), "case %d: findings were printed" % i)
        ok(r.tmp_leftovers() == [], "case %d: temp files left" % i)
        last = r
    has(Run("q10_msg", scen(lockdown_fail="Pairing dialog still pending")).go(ANSWERS), "Pairing dialog still pending")
    return last


@test("quick", "Q11", "the passcode is a manual item: named as not checked, never claimed on/off, no lockdown get")
def q11():
    r = Run("q11").go(ANSWERS)
    rc(r, 0)
    lines = [ln for ln in r.out.splitlines() if "passcode" in ln.lower()]
    ok(lines, "passcode is not mentioned at all")
    ok(not any(ln.lstrip().startswith("[") for ln in lines), "passcode is a tagged finding: %r" % lines)
    ok("not checked" in r.out.lower(), "no 'not checked' note")
    ok(not re.search(r"passcode\W+(is|was|appears)\b", r.out, re.I), "claims a passcode state")
    ok("lockdown get" not in r.pmd_cmds(), "asked the phone for a passcode value: %r" % r.pmd_cmds())
    return r


@test("quick", "Q12", "every command that talks to the chosen phone carries its --udid (second of two phones)")
def q12():
    sc = base_scenario()
    sc["devices"] = [device(), device("BB8", UDID2)]
    r = Run("q12", sc).go("alice\ny\n2\n\nn\n")
    rc(r, 0)
    talking = [a for a in r.pmd() if a[:2] != ["usbmux", "list"]]
    ok([" ".join(a[:2]) for a in talking] == ["lockdown info", "profile list", "apps list"], "calls: %r" % talking)
    for a in talking:
        ok(a[a.index("--udid") + 1:a.index("--udid") + 2] == [UDID2] if "--udid" in a else False, "no right --udid in %r" % a)
    ok("apps list" in " ".join(" ".join(a) for a in talking) and ["--type", "Any"] == talking[2][talking[2].index("--type"):][:2],
       "apps list is not asking for --type Any: %r" % talking[2])
    return r


@test("quick", "Q13", "the apps answer is empty, a list, garbage or has no ApplicationType -> one UNKNOWN, never INFO")
def q13():
    cases = [("empty dict", {"apps": {}}), ("empty list", {"apps_raw": "[]"}), ("garbage", {"apps_raw": "nonsense"}),
             ("a list of apps", {"apps_raw": json.dumps([app("com.a.b", "AB")])}),
             ("values not objects", {"apps_raw": json.dumps({"com.a.b": "x"})}),
             ("no ApplicationType", {"apps": {"com.a.b": {"CFBundleIdentifier": "com.a.b", "SignerIdentity": STORE}}})]
    last = None
    for i, (label, changes) in enumerate(cases):
        r = Run("q13_%d" % i, scen(**changes)).go(ANSWERS)
        ok(r.rc == 0, "%s: exit %r" % (label, r.rc))
        unk = tag_lines(r, "UNKNOWN")
        ok(len(unk) == 1 and "apps" in unk[0].lower(), "%s: UNKNOWN lines %r" % (label, unk))
        ok(not any("App Store" in ln or "no apps" in ln.lower() for ln in tag_lines(r, "INFO")), "%s: reassuring INFO line" % label)
        ok(not tag_lines(r, "REVIEW"), "%s: REVIEW lines" % label)
        last = r
    return last


@test("quick", "Q14", "a phone with only system apps -> INFO 'no apps installed by you' (not UNKNOWN)")
def q14():
    sc = base_scenario()
    sc["apps"] = {k: v for k, v in sc["apps"].items() if v["ApplicationType"] == "System"}
    r = Run("q14", sc).go(ANSWERS)
    rc(r, 0)
    ok(any("no apps installed by you" in ln for ln in tag_lines(r, "INFO")), "INFO lines: %r" % tag_lines(r, "INFO"))
    ok(not tag_lines(r, "UNKNOWN") and not tag_lines(r, "REVIEW"), "unexpected findings")
    return r


@test("quick", "Q15", "a profile that only shows up in ProfileMetadata (not OrderedIdentifiers) is still listed")
def q15():
    prof = profile_response(("com.listed.one", "Listed", "Org A"))
    prof["ProfileMetadata"]["com.hidden.two"] = {"PayloadDisplayName": "Hidden Two", "PayloadOrganization": "Org B"}
    r = Run("q15", scen(profiles=prof)).go(ANSWERS)
    rc(r, 0)
    lines = tag_lines(r, "REVIEW")
    ok(len(lines) == 2 and "Listed" in lines[0] and "Hidden Two" in lines[1] and "Org B" in lines[1], "REVIEW lines: %r" % lines)
    return r


@test("quick", "Q16", "more than 25 flagged apps (or profiles) -> 25 listed plus one line saying how many more")
def q16():
    sc = base_scenario()
    for i in range(30):
        b = "com.side.app%02d" % i
        sc["apps"][b] = app(b, "Side %02d" % i, signer="Dev Person")
    r = Run("q16", sc).go(ANSWERS)
    rc(r, 0)
    lines = tag_lines(r, "REVIEW")
    ok(len(lines) == 26 and "5 more apps" in lines[-1] and "Side 24" in lines[24] and "Side 25" not in r.out, "REVIEW lines: %d, last: %r" % (len(lines), lines[-1:]))
    same_in_report(r, "REVIEW")
    ids = ["com.p.%02d" % i for i in range(27)]
    r2 = Run("q16b", scen(profiles=profile_response(*[(i, "Prof " + i[-2:], "Org") for i in ids]))).go(ANSWERS)
    rc(r2, 0)
    lines = tag_lines(r2, "REVIEW")
    ok(len(lines) == 26 and "2 more configuration profiles" in lines[-1], "profile REVIEW lines: %d, last %r" % (len(lines), lines[-1:]))
    return r


def crashing_python(tid, subcommand, partial=""):
    """A Run whose python3 (first on PATH, found through an env-style shebang) dies when the script's helper is asked
    for SUBCOMMAND and otherwise hands over to the real one. PARTIAL is a line the fake prints before dying: a helper
    that crashes half-way through its answer. A script cannot be another script's #! interpreter on macOS, so the
    fake sits on PATH instead of in the shebang."""
    r = Run(tid, shebang="#!/usr/bin/env python3")
    say = "printf '%%s\\n' '%s'; " % partial if partial else ""
    r.fake_cmd("python3", 'if [ "$1" = "-I" ] && [ "$2" = "-c" ] && [ "$4" = "%s" ]; then %sexit 3; fi\n'
                          'exec /usr/bin/python3 "$@"' % (subcommand, say))
    return r


@test("quick", "Q17", "the helper crashing on profiles or apps -> UNKNOWN for that check (never INFO); on info -> exit 1")
def q17():
    r = crashing_python("q17a", "profiles").go(ANSWERS)
    ok(tool_python(r) == str(r.bin / "python3"), "the fake python3 was not the one used: %r" % tool_python(r))
    rc(r, 0)
    unk = about(r, "UNKNOWN", "profile")
    ok(len(unk) == 1 and len(tag_lines(r, "UNKNOWN")) == 1, "profiles crash: %r" % tag_lines(r, "UNKNOWN"))
    ok(not any("No configuration profiles" in ln for ln in tag_lines(r, "INFO")), "profiles crash reported as none")
    ok(any("App Store" in ln for ln in tag_lines(r, "INFO")), "apps check did not run")
    r = crashing_python("q17b", "apps").go(ANSWERS)
    rc(r, 0)
    ok(len(about(r, "UNKNOWN", "apps")) == 1 and len(tag_lines(r, "UNKNOWN")) == 1, "apps crash: %r" % tag_lines(r, "UNKNOWN"))
    ok(not any("App Store" in ln for ln in tag_lines(r, "INFO")), "apps crash reported as checked")
    r = crashing_python("q17c", "info").go(ANSWERS)
    ok(r.rc == 1 and "ERROR:" in r.out and r.pmd_cmds() == ["usbmux list", "lockdown info"], "info crash: rc %r calls %r" % (r.rc, r.pmd_cmds()))
    return r


def tool_python(r):
    """The interpreter path the 'Using:' block shows."""
    m = re.search(r"^\s*python\s{2,}(\S.*)$", r.out, re.M)
    return m.group(1).strip() if m else ""


@test("quick", "Q18", "a pipe inside a name, organisation or signer cannot shift the fields of the helper's answer")
def q18():
    sc = base_scenario()
    sc["apps"]["com.pipe.app"] = app("com.pipe.app", "Left|Right", signer="Dev|Team")
    sc["profiles"] = profile_response(("com.pipe.profile", "Prof|Name", "Org|Name"))
    r = Run("q18", sc).go(ANSWERS)
    rc(r, 0)
    want = ['[REVIEW] Configuration profile "Prof/Name" from Org/Name (com.pipe.profile) - check that you recognise it.',
            '[REVIEW] App "Left/Right" (com.pipe.app) is signed by "Dev/Team", not by the App Store - check that you recognise it.']
    ok(tag_lines(r, "REVIEW") == want, "REVIEW lines: %r" % tag_lines(r, "REVIEW"))
    ok(rtag_lines(r, "REVIEW") == want, "report REVIEW lines: %r" % rtag_lines(r, "REVIEW"))
    ok(tag_lines(r, "UNKNOWN") == [], "unexpected UNKNOWN: %r" % tag_lines(r, "UNKNOWN"))
    return r


@test("quick", "Q19", "a helper that crashes half-way through its answer counts as crashed: its partial output is never used")
def q19():
    r = crashing_python("q19a", "profiles", partial="NONE").go(ANSWERS)
    ok(tool_python(r) == str(r.bin / "python3"), "the fake python3 was not the one used: %r" % tool_python(r))
    rc(r, 0)
    ok(len(about(r, "UNKNOWN", "profile")) == 1 and len(tag_lines(r, "UNKNOWN")) == 1, "profiles: %r" % tag_lines(r, "UNKNOWN"))
    ok(not any("No configuration profiles" in ln for ln in tag_lines(r, "INFO")), "partial 'none installed' was used")
    r = crashing_python("q19b", "apps", partial="CNT|1|1|0").go(ANSWERS)
    rc(r, 0)
    ok(len(about(r, "UNKNOWN", "apps")) == 1 and len(tag_lines(r, "UNKNOWN")) == 1, "apps: %r" % tag_lines(r, "UNKNOWN"))
    ok(not any("App Store" in ln for ln in tag_lines(r, "INFO")), "partial 'all signed' was used")
    r = crashing_python("q19c", "info", partial="PHONE|Fake|iPhone1,1|1.0|1A1").go(ANSWERS)
    ok(r.rc == 1 and "ERROR:" in r.out, "info: rc %r" % r.rc)
    ok(r.pmd_cmds() == ["usbmux list", "lockdown info"], "info: calls %r" % r.pmd_cmds())
    ok("Fake" not in r.out, "partial phone details were shown")
    return r
