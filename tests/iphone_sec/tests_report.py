"""Group `report`: the report file, the ZIP, the manual checklist, and how a finished run ends."""
import os
import re
import stat
import zipfile

from harness import (UDID, Run, app, base_scenario, has, lacks, no_leak, ok, profile_response, rc, rtag_lines,
                     tag_lines, test)

ANSWERS = "alice\ny\n\nn\n"        # name, "this is my phone", Enter at the Trust pause, "n" to the deep scan; the delete prompt then sees end of input
REPORT = "iphone_security_report.txt"
SECRETS = (UDID, "SECRETSERIAL123", "+1 555 000 1234", "359999999999999")

LIMITS = ('"Nothing found" means nothing KNOWN was found.', "iCloud", "Apple ID", "SIM swap", "Android",
          "A computer cannot clean an iPhone like a Mac", "Jailbreak")
CHECKLIST = ("Passcode:", "iOS update:", "Apple Account:", "Find My:", "VPN & Device Management:", "App permissions:",
             "Messages:", "Lockdown Mode")
VERDICT_OK = "No known problem was found by the checks that ran."
VERDICT_LOOK = "Some items need a look: check each [REVIEW] item, and do not treat an [UNKNOWN] item as passed."
REASSURING = re.compile(r"\b(clean|safe|secure|ok|fine|healthy|protected|no threats?)\b", re.I)


def section(text, heading):
    """The lines under HEADING, up to the next blank line (None when there is no such heading)."""
    out, on = [], False
    for ln in text.splitlines():
        if on:
            if not ln.strip():
                break
            out.append(ln)
        elif ln.startswith(heading):
            on = True
    return out if on else None


def on_screen(r, heading):
    """Same, for the screen text."""
    return section(r.out, heading)


def checklist_items(rep):
    """[(label line, [continuation lines])] of the checklist section of a report."""
    items = []
    for ln in section(rep, "CHECK THESE YOURSELF") or []:
        if re.match(r"^\s*\d+\. ", ln):
            items.append((ln, []))
        elif items:
            items[-1][1].append(ln.strip())
    return items


def in_order(text, markers):
    pos = 0
    for m in markers:
        i = text.find(m, pos)
        ok(i >= 0, "%r not found, in this order, after offset %d" % (m, pos))
        pos = i + len(m)


def flagged_scenario(extra_apps=2):
    sc = base_scenario()
    sc["profiles"] = profile_response(("com.corp.mdm", "Corp", "Corp Inc"))
    for i in range(extra_apps):
        b = "com.sideload.app%d" % i
        sc["apps"][b] = app(b, "Side %d" % i, signer="Dev Co")
    return sc


@test("report", "R01", "report and ZIP are written privately; the ZIP holds exactly the report and replaces an older ZIP")
def r01():
    r = Run("r01")
    r.desktop().mkdir(parents=True)
    with zipfile.ZipFile(r.zip_path(), "w") as zf:          # a ZIP left over from an earlier run
        zf.writestr("old_backup_dump.bin", "stale")
    r.go(ANSWERS)
    rc(r, 0)
    has(r, "an earlier report with this name will be replaced")
    ok((r.report_dir() / REPORT).is_file(), "report file missing")
    ok(r.zip_names() == [REPORT], "ZIP members: %r" % r.zip_names())
    ok(r.zip_text() == r.report(), "the copy in the ZIP differs from the report file")
    for p in (r.report_dir(), r.report_dir() / REPORT, r.zip_path()):
        mode = stat.S_IMODE(p.stat().st_mode)
        ok(mode & 0o077 == 0, "%s can be read by other users: %o" % (p.name, mode))
    ok(r.tmp_leftovers() == [], "temp files left behind: %r" % r.tmp_leftovers())
    no_leak(r, *SECRETS)
    r2 = Run("r01b")
    r2.report_dir().mkdir(parents=True)
    (r2.report_dir() / REPORT).write_text("earlier report")
    r2.go(ANSWERS)
    rc(r2, 0)
    has(r2, "an earlier report with this name will be replaced")
    ok("earlier report" not in r2.report() and r2.report().startswith("iPhone Security Report"), "the old report was not replaced")
    ok(sorted(p.name for p in r2.report_dir().iterdir()) == [REPORT], "extra files in the folder: %r" % sorted(p.name for p in r2.report_dir().iterdir()))
    return r


@test("report", "R02", "report layout: header, summary, findings, actions, what the scan cannot see, checklist; the screen agrees")
def r02():
    r = Run("r02").go(ANSWERS)
    rc(r, 0)
    rep = r.report()
    head = rep.splitlines()[:4]
    ok(head[0] == "iPhone Security Report" and head[1] == "Prepared for: alice" and head[2].startswith("Date: ")
       and head[3] == "Phone: Test iPhone - iPhone18,2 - iOS 27.2 (24B119)", "header: %r" % head)
    summary = "Summary: 0 DETECTED, 0 REVIEW, 3 INFO, 0 UNKNOWN"
    ok(summary in rep and summary in r.out, "summary line missing from the report or the screen")
    in_order(rep, ["Summary:", "FINDINGS", "ACTIONS TAKEN", "WHAT THIS SCAN CANNOT SEE", "CHECK THESE YOURSELF"])
    for tag in ("DETECTED", "REVIEW", "INFO", "UNKNOWN"):
        ok(tag_lines(r, tag) == rtag_lines(r, tag), "[%s] lines differ between screen and report" % tag)
    ok(section(rep, "ACTIONS TAKEN") == ["None. Nothing was changed on the phone."], "actions: %r" % section(rep, "ACTIONS TAKEN"))
    limits = section(rep, "WHAT THIS SCAN CANNOT SEE")
    ok(limits is not None and len(limits) == 4, "limits section: %r" % limits)
    for phrase in LIMITS:
        ok(any(phrase in ln for ln in limits), "the report does not say %r" % phrase)
    ok(on_screen(r, "What this scan cannot see:") == limits, "screen and report list different limits:\n%r\n%r"
       % (on_screen(r, "What this scan cannot see:"), limits))
    for where, text in (("report", rep), ("screen", r.out)):
        under = section(text, "Summary:")
        ok(under == [VERDICT_OK], "the line under the counts on the %s: %r" % (where, under))
        ok(not REASSURING.search("\n".join(under)), "the verdict on the %s sounds like a guarantee" % where)
    lacks(r, "will be replaced")
    return r


@test("report", "R03", "the summary counts every flagged item, including the ones a long list only mentions")
def r03():
    sc = flagged_scenario(extra_apps=27)
    r = Run("r03", sc).go(ANSWERS)
    rc(r, 0)
    want = "Summary: 0 DETECTED, 28 REVIEW, 2 INFO, 0 UNKNOWN"          # 1 profile + 25 listed apps + "2 more"; one INFO is the "deep scan not run" line
    ok(want in r.out and want in r.report(), "summary: %r" % [ln for ln in r.out.splitlines() if ln.startswith("Summary")])
    for where, text in (("report", r.report()), ("screen", r.out)):
        under = section(text, "Summary:")
        ok(under == [VERDICT_LOOK], "the line under the counts on the %s: %r" % (where, under))
        ok(not REASSURING.search("\n".join(under)), "the verdict on the %s sounds like a guarantee" % where)
    vpn = " ".join([i for i in checklist_items(r.report()) if "VPN & Device Management:" in i[0]][0][1])
    ok("This scan found 27 apps not signed by the App Store." in vpn and "This scan found 1 configuration profile." in vpn,
       "the checklist counts: %r" % vpn)
    sc = base_scenario()
    sc["apps_fail"] = "service unavailable"
    r2 = Run("r03b", sc).go(ANSWERS)
    ok("Summary: 0 DETECTED, 0 REVIEW, 2 INFO, 1 UNKNOWN" in r2.out, "summary with an unknown: %r" % r2.out[-400:])
    ok(section(r2.out, "Summary:") == [VERDICT_LOOK], "an unknown check got the verdict %r" % section(r2.out, "Summary:"))
    return r


@test("report", "R04", "the checklist always has the same 8 numbered items, in order, with nothing added for a plain phone")
def r04():
    r = Run("r04").go(ANSWERS)
    rc(r, 0)
    items = checklist_items(r.report())
    ok(len(items) == 8, "items: %r" % [i[0] for i in items])
    for n, (label, rest), want in zip(range(1, 9), items, CHECKLIST):
        ok(re.match(r"^\s*%d\. %s" % (n, re.escape(want)), label), "item %d is %r, wanted %r" % (n, label, want))
        ok(rest, "item %d has no instructions" % n)
    text = "\n".join(section(r.report(), "CHECK THESE YOURSELF"))
    for extra in ("This scan found", "Run this scan again"):
        ok(extra not in text, "%r on a plain phone" % extra)
    ok(not re.search(r"passcode\W+(is|was|appears)", r.report(), re.I), "the report claims something about the passcode")
    return r


@test("report", "R05", "the checklist points at what this scan found (profiles, apps) and at checks that did not run")
def r05():
    r = Run("r05", flagged_scenario()).go(ANSWERS)
    rc(r, 0)
    items = checklist_items(r.report())
    vpn = [i for i in items if "VPN & Device Management:" in i[0]]
    ok(len(vpn) == 1, "VPN items: %r" % vpn)
    joined = " ".join(vpn[0][1])
    ok("This scan found 1 configuration profile." in joined, "profile hint: %r" % vpn[0][1])
    ok("This scan found 2 apps not signed by the App Store." in joined, "app hint: %r" % vpn[0][1])
    ok(len(items) == 8, "flagged items should not add checklist items: %d" % len(items))
    two = profile_response(("com.corp.mdm", "Corp", "Corp Inc"), ("com.school.mdm", "School", "School District"))
    r2 = Run("r05b", dict(base_scenario(), profiles=two)).go(ANSWERS)
    j2 = " ".join([i for i in checklist_items(r2.report()) if "VPN & Device Management:" in i[0]][0][1])
    ok("This scan found 2 configuration profiles." in j2 and "not signed by the App Store" not in j2, "profile-only hint: %r" % j2)
    sc = base_scenario()
    sc["apps"]["com.x.one"] = app("com.x.one", "One", signer="Dev Co")
    j3 = " ".join([i for i in checklist_items(Run("r05c", sc).go(ANSWERS).report()) if "VPN & Device Management:" in i[0]][0][1])
    ok("This scan found 1 app not signed by the App Store." in j3 and "configuration profile" not in j3, "one app hint: %r" % j3)
    sc = base_scenario()
    sc["apps_fail"] = "service unavailable"
    items = checklist_items(Run("r05d", sc).go(ANSWERS).report())
    ok(len(items) == 9 and "Run this scan again" in items[-1][0] and "1 check" in " ".join(items[-1][1]),
       "unknown check items: %r" % items[-2:])
    return r


@test("report", "R06", "the run ends like mac_sec.sh: summary, limits, SCAN COMPLETE, folder + ZIP, contents, prompt, next steps")
def r06():
    r = Run("r06").go(ANSWERS)
    rc(r, 0)
    in_order(r.out, ["[INFO] App Store signature present", "Summary: 0 DETECTED", "Not checked by this script:",
                     "What this scan cannot see:", "SCAN COMPLETE", "Folder: ~/Desktop/alice.iPhone_Security_Check/",
                     "ZIP: ~/Desktop/alice.iPhone_Security_Check.zip (", "Files included (1):", "1. " + REPORT,
                     "ZIP contents:", REPORT, "Delete the folder and keep only the ZIP? (y/n):",
                     "Both folder and ZIP kept on Desktop.", "Next steps:", "Scan completed at "])
    tail = r.out[r.out.index("SCAN COMPLETE"):]
    ok(re.search(r"ZIP: ~/Desktop/alice\.iPhone_Security_Check\.zip \(\S+\)", tail), "no ZIP size shown")
    ok(r.out.rstrip().splitlines()[-1].startswith("Scan completed at "), "last line: %r" % r.out.rstrip().splitlines()[-1])
    nxt = section(tail, "Next steps:")
    ok(nxt and len(nxt) == 3 and "CHECK THESE YOURSELF" in nxt[0] and "alice.iPhone_Security_Check.zip" in nxt[2], "next steps: %r" % nxt)
    ok("[UNKNOWN]" in nxt[1] and "did NOT pass" in nxt[1], "the next steps do not warn about unknown checks: %r" % nxt)
    return r


@test("report", "R07", "deleting the folder removes only what the script wrote; any other answer keeps everything")
def r07():
    r = Run("r07").go(ANSWERS + "y\n")
    rc(r, 0)
    ok(not r.report_dir().exists(), "the folder is still there")
    ok(r.zip_names() == [REPORT], "ZIP after deleting the folder: %r" % r.zip_names())
    has(r, "Folder deleted. ZIP remains at ~/Desktop/alice.iPhone_Security_Check.zip")
    for i, yes in enumerate(("Y\n", "yes\n")):
        r2 = Run("r07y%d" % i).go(ANSWERS + yes)
        ok(not r2.report_dir().exists() and r2.zip_path().exists(), "reply %r did not delete the folder" % yes)
    for i, tail in enumerate(("n\n", "", "maybe\n", "\n")):
        r3 = Run("r07n%d" % i).go(ANSWERS + tail)
        ok((r3.report_dir() / REPORT).is_file() and r3.zip_names() == [REPORT], "reply %r removed something" % tail)
        has(r3, "Both folder and ZIP kept on Desktop.")
    r4 = Run("r07x")
    r4.report_dir().mkdir(parents=True)
    (r4.report_dir() / "notes.txt").write_text("mine")
    r4.go(ANSWERS + "y\n")
    rc(r4, 0)
    ok((r4.report_dir() / "notes.txt").read_text() == "mine", "someone else's file in the folder was touched")
    ok(not (r4.report_dir() / REPORT).exists(), "the script's own report was left in the folder")
    ok(r4.zip_names() == [REPORT], "ZIP: %r" % r4.zip_names())
    has(r4, "the folder stays because it holds other files")
    return r


@test("report", "R08", "ZIP creation fails -> exit 1 with a clear error, the report stays, nothing is left in the temp folder")
def r08():
    r = Run("r08")
    r.fake_cmd("zip", "exit 1")
    r.go(ANSWERS)
    rc(r, 1)
    has(r, "ERROR: Failed to create ZIP file.")
    lacks(r, "SCAN COMPLETE")
    ok((r.report_dir() / REPORT).is_file(), "the finished report was thrown away")
    ok(not r.zip_path().exists(), "a ZIP exists")
    ok(r.tmp_leftovers() == [], "temp files left behind: %r" % r.tmp_leftovers())
    r2 = Run("r08b")
    r2.fake_cmd("zip", 'echo partial > "$2"\nexit 12')       # leaves a broken file at the ZIP path, then fails
    r2.go(ANSWERS)
    rc(r2, 1)
    has(r2, "ERROR: Failed to create ZIP file.")
    ok(not r2.zip_path().exists(), "a broken ZIP was left on the Desktop")
    r3 = Run("r08c")
    r3.fake_cmd("zip", "exit 0")                    # says it worked and made nothing
    r3.go(ANSWERS)
    rc(r3, 1)
    has(r3, "ERROR: Failed to create ZIP file.")
    lacks(r3, "SCAN COMPLETE")
    return r


@test("report", "R09", "an output path that is a symlink or the wrong kind of thing is refused before the phone is contacted")
def r09():
    last = None
    kinds = ("report dir is a file", "report dir is a symlink", "zip is a folder", "zip is a symlink",
             "report file is a symlink", "report file is a folder")
    for i, kind in enumerate(kinds):
        r = Run("r09_%d" % i)
        r.desktop().mkdir(parents=True)
        elsewhere = r.home / "elsewhere"
        elsewhere.mkdir()
        if kind == "report dir is a file":
            r.report_dir().write_text("not a folder")
        elif kind == "report dir is a symlink":
            os.symlink(elsewhere, r.report_dir())
        elif kind == "zip is a folder":
            r.zip_path().mkdir()
        elif kind == "zip is a symlink":
            os.symlink(elsewhere / "target.zip", r.zip_path())
        elif kind == "report file is a symlink":
            r.report_dir().mkdir()
            os.symlink(elsewhere / "target.txt", r.report_dir() / REPORT)
        else:
            (r.report_dir() / REPORT).mkdir(parents=True)
        r.go(ANSWERS)
        ok(r.rc == 1, "%s: exit %r" % (kind, r.rc))
        ok("already exists" in r.out, "%s: no explanation: %r" % (kind, r.out[-300:]))
        ok(r.calls() == [], "%s: the phone was contacted" % kind)
        ok(list(elsewhere.iterdir()) == [], "%s: something was written through the link" % kind)
        ok(r.tmp_leftovers() == [], "%s: temp files left behind" % kind)
        last = r
    return last


@test("report", "R10", "a report that cannot be written -> error, exit 1; nothing the script made is left; an earlier report is untouched")
def r10():
    def finish(label, run, message="ERROR: Could not write the report."):
        try:
            run.go(ANSWERS)
        finally:                                    # a read-only folder would block the harness's own clean-up
            if run.report_dir().exists():
                os.chmod(run.report_dir(), 0o700)
        try:
            rc(run, 1)
            has(run, message)
            lacks(run, "SCAN COMPLETE")
            ok(not run.zip_path().exists(), "a ZIP exists")
            ok(run.tmp_leftovers() == [], "temp files left behind: %r" % run.tmp_leftovers())
        except AssertionError as e:
            raise AssertionError("%s: %s" % (label, e))

    r = Run("r10a")                                 # the script makes the folder, which then cannot be written to
    r.fake_cmd("mkdir", '/bin/mkdir "$@" || exit $?\nfor last; do :; done\n/bin/chmod 500 "$last"')
    finish("folder made by the script cannot take files", r)
    ok(not r.report_dir().exists(), "an empty folder made by the script was left behind")

    r2 = Run("r10b")                                # an earlier report sits in a folder that cannot take new files
    r2.report_dir().mkdir(parents=True)
    (r2.report_dir() / REPORT).write_text("earlier report")
    os.chmod(r2.report_dir(), 0o500)
    finish("earlier report in a folder that cannot take files", r2)
    ok((r2.report_dir() / REPORT).read_text() == "earlier report", "the earlier report was changed or removed")
    ok(sorted(p.name for p in r2.report_dir().iterdir()) == [REPORT], "something else was left in the folder")

    r3 = Run("r10c")                                # the last step fails: the half-finished file must not stay
    r3.fake_cmd("mv", "exit 1")
    finish("the final move fails", r3)
    ok(not r3.report_dir().exists(), "the folder or a temporary file was left behind: %r"
       % (sorted(p.name for p in r3.report_dir().iterdir()) if r3.report_dir().exists() else None))

    r4 = Run("r10d")                                # writing the report itself fails, with an earlier report in place
    r4.fake_cmd("mktemp", 'd=$(/usr/bin/mktemp "$@") || exit 1\n/bin/mkdir "$d/%s"\necho "$d"' % REPORT)   # a folder where the report goes
    r4.report_dir().mkdir(parents=True)
    (r4.report_dir() / REPORT).write_text("earlier report")
    finish("the report cannot be written", r4)
    ok((r4.report_dir() / REPORT).read_text() == "earlier report", "the earlier report was changed or removed")
    ok(sorted(p.name for p in r4.report_dir().iterdir()) == [REPORT], "something else was left in the folder")

    r5 = Run("r10e")                                # the report folder cannot be created at all
    r5.fake_cmd("mkdir", "exit 1")
    finish("the folder cannot be created", r5, "ERROR: Could not create ~/Desktop/alice.iPhone_Security_Check")
    ok(not r5.report_dir().exists(), "the folder exists")

    r6 = Run("r10f")                                # as r10d, but nothing earlier: no report may appear at all
    r6.fake_cmd("mktemp", 'd=$(/usr/bin/mktemp "$@") || exit 1\n/bin/mkdir "$d/%s"\necho "$d"' % REPORT)
    finish("the report cannot be written (no earlier report)", r6)
    ok(not r6.report_dir().exists(), "a folder or a report was left behind")
    return r


@test("report", "R11", "a run that stops before the report is made leaves earlier results and an existing folder alone")
def r11():
    sc = dict(base_scenario(), devices=[])          # no phone: the run ends at the search, after the paths are chosen
    r = Run("r11a", sc)
    r.report_dir().mkdir(parents=True)              # an empty folder that was already there
    r.go("alice\ny\n")
    rc(r, 1)
    has(r, "No iPhone found")
    ok(r.report_dir().is_dir() and list(r.report_dir().iterdir()) == [], "the existing folder was removed or filled")

    r2 = Run("r11b", sc)                            # an earlier report and ZIP: announced as 'will be replaced', but only a finished run replaces them
    r2.report_dir().mkdir(parents=True)
    (r2.report_dir() / REPORT).write_text("earlier report")
    r2.zip_path().write_text("earlier zip")
    r2.go("alice\ny\n")
    rc(r2, 1)
    ok((r2.report_dir() / REPORT).read_text() == "earlier report", "the earlier report was changed or removed")
    ok(r2.zip_path().read_text() == "earlier zip", "the earlier ZIP was changed or removed")
    ok(r2.tmp_leftovers() == [], "temp files left behind: %r" % r2.tmp_leftovers())
    return r
