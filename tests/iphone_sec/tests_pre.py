"""Group `pre`: banner, platform check, tool preflight, name + authorisation prompts."""
import re

from harness import (Run, has, lacks, no_leak, ok, rc, test)


def tool_line(r, label):
    """The 'Using:' line the preflight prints for a tool, e.g. '  python   /usr/bin/python3'."""
    for ln in r.out.splitlines():
        m = re.match(r"^\s*%s\s{2,}(\S.*)$" % re.escape(label), ln)
        if m:
            return m.group(1).strip()
    return None


@test("pre", "P01", "not macOS -> refuses before anything else, no tool is called")
def p01():
    r = Run("p01")
    r.fake_cmd("uname", 'echo Linux')
    r.go("")
    rc(r, 1)
    has(r, "ERROR: This script only runs on macOS.")
    ok(r.calls() == [], "tools were called: %r" % r.calls())
    return r


@test("pre", "P02", "pymobiledevice3 missing -> exit 1, install commands, nothing runs, no prompt")
def p02():
    r = Run("p02", tools=("mvt-ios",)).go("")
    rc(r, 1)
    has(r, "Required tool 'pymobiledevice3' not found")
    has(r, "pipx install pymobiledevice3")
    lacks(r, "pipx install mvt")
    has(r, "nothing is installed automatically")
    lacks(r, "Enter your name")
    ok(r.calls() == [] and not r.report_dir().exists(), "something ran or was created")
    return r


@test("pre", "P03", "mvt-ios missing -> exit 1, only the mvt install command is suggested")
def p03():
    r = Run("p03", tools=("pymobiledevice3",)).go("")
    rc(r, 1)
    has(r, "Required tool 'mvt-ios' not found")
    has(r, "pipx install mvt")
    lacks(r, "pipx install pymobiledevice3")
    ok(r.calls() == [], "tools were called")
    return r


@test("pre", "P04", "both missing, no pipx -> brew + pipx guidance, and nothing is ever auto-installed")
def p04():
    r = Run("p04", tools=())
    r.fake_cmd("brew")           # records any call; must stay unused
    r.go("")
    rc(r, 1)
    for text in ("brew install pipx", "pipx install pymobiledevice3", "pipx install mvt", "pipx ensurepath"):
        has(r, text)
    ok(r.installer_calls() == [], "script invoked an installer: %r" % r.installer_calls())
    r2 = Run("p04b", tools=())
    r2.fake_cmd("pipx")
    r2.fake_cmd("brew")
    r2.go("")
    rc(r2, 1)
    lacks(r2, "brew install pipx")     # pipx exists, so brew is not suggested
    has(r2, "pipx install mvt")
    ok(r2.installer_calls() == [], "script invoked an installer: %r" % r2.installer_calls())
    return r


@test("pre", "P05", "bad report names are refused with the mac_sec.sh messages, nothing runs")
def p05():
    cases = [("", "Name cannot be empty"), ("a b", "Name cannot contain spaces"),
             ("a/b", "Name can only contain letters"), ("../x", "Name can only contain letters"),
             ("al;ice", "Name can only contain letters"), ("al\tice", "Name cannot contain spaces")]
    last = None
    for i, (name, msg) in enumerate(cases):
        r = Run("p05_%d" % i).go(name + "\ny\n\n")
        ok(r.rc == 1, "name %r: exit %r" % (name, r.rc))
        ok(msg in r.out, "name %r: expected %r in output" % (name, msg))
        ok(r.calls() == [], "name %r: tools were called" % name)
        ok(not r.desktop().exists() or not list(r.desktop().iterdir()), "name %r: files created" % name)
        last = r
    return last


@test("pre", "P06", "authorisation declined (n, or EOF) -> exit 1 before any phone contact, nothing written")
def p06():
    for i, answers in enumerate(("alice\nn\n", "alice\n", "alice\nmaybe\n")):
        r = Run("p06_%d" % i).go(answers)
        ok(r.rc == 1, "answers %r: exit %r" % (answers, r.rc))
        ok("Cancelled" in r.out and "No phone was contacted" in r.out, "answers %r: no cancel notice" % answers)
        ok(r.calls() == [], "answers %r: phone tools were called" % answers)
        ok(not r.report_dir().exists() and not r.zip_path().exists(), "answers %r: report files exist" % answers)
        ok(r.tmp_leftovers() == [], "answers %r: temp files left: %r" % (answers, r.tmp_leftovers()))
    return r


@test("pre", "P07", "tools found in ~/.local/bin (home has a space) when not on PATH")
def p07():
    r = Run("p07", tools=(), home_tools=("pymobiledevice3", "mvt-ios")).go("alice\nn\n")
    rc(r, 1)
    lacks(r, "not found")
    lacks(r, "pipx install")
    has(r, "Cancelled")                      # got past preflight and the name prompt
    ok(tool_line(r, "pymobiledevice3") == str(r.home / ".local/bin/pymobiledevice3"), tool_line(r, "pymobiledevice3"))
    ok(tool_line(r, "mvt-ios") == str(r.home / ".local/bin/mvt-ios"), tool_line(r, "mvt-ios"))
    return r


@test("pre", "P08", "helper python comes from the pymobiledevice3 launcher shebang")
def p08():
    r = Run("p08", shebang="#!/usr/bin/python3").go("alice\nn\n")
    rc(r, 1)
    ok(tool_line(r, "python") == "/usr/bin/python3", "python line: %r" % tool_line(r, "python"))
    return r


@test("pre", "P09", "env-style shebang falls back to python3 on PATH")
def p09():
    r = Run("p09", shebang="#!/usr/bin/env python3").go("alice\nn\n")
    rc(r, 1)
    ok(tool_line(r, "python") == "/usr/bin/python3", "python line: %r" % tool_line(r, "python"))
    return r


@test("pre", "P10", "no usable Python 3 anywhere -> exit 1 with a clear message")
def p10():
    r = Run("p10", shebang="#!/usr/bin/env python3", nopython=True).go("alice\nn\n")
    rc(r, 1)
    has(r, "Python 3.8 or newer")
    lacks(r, "Enter your name")
    ok(r.calls() == [], "tools were called")
    return r


@test("pre", "P11", "--help prints usage and exits 0; unknown arguments exit 1 (no silent ignore of --apply)")
def p11():
    r = Run("p11").go("", args=["--help"])
    rc(r, 0)
    has(r, "Usage:")
    has(r, "APPLY=1")
    ok(r.calls() == [], "tools were called")
    r2 = Run("p11b").go("", args=["--apply"])
    rc(r2, 1)
    has(r2, "Usage:")
    ok(r2.calls() == [], "tools were called")
    return r


@test("pre", "P12", "banner states what the scan can and cannot do before asking anything")
def p12():
    r = Run("p12").go("alice\nn\n")
    banner = r.out.split("Enter your name")[0]
    for text in ("IPHONE SECURITY SCANNER", "USB", "cannot clean an iPhone like a Mac", "Nothing is changed"):
        ok(text in banner, "banner lacks %r" % text)
    return r
