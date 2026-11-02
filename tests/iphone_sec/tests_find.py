"""Group `find`: locating the phone over USB (never pairs), choosing between phones, refusing bad IDs."""
import json

from harness import (UDID, UDID2, Run, Session, base_scenario, device, has, lacks, ok, rc, test)


def lines(*items):
    return "".join(i + "\n" for i in items)


def usbmux_calls(r):
    return [a for a in r.pmd() if a[:2] == ["usbmux", "list"]]


QUICK_CALLS = ["lockdown info", "profile list", "apps list"]


def only_usbmux(r, n, then=()):
    """Looking for the phone is exactly N 'usbmux list' calls and nothing else; THEN are the calls that may follow
    once a phone is chosen and the Trust pause is over."""
    want = ["usbmux list"] * n + list(then)
    ok(r.pmd_cmds() == want, "pymobiledevice3 calls were %r, wanted %r" % (r.pmd_cmds(), want))
    ok(all("--usb" in a for a in usbmux_calls(r)), "usbmux list was not restricted to --usb")


@test("find", "F01", "no phone -> 3 bounded looks (Enter retries), never pairs, exit 1")
def f01():
    sc = base_scenario()
    sc["devices"] = []
    r = Run("f01", sc).go(lines("alice", "y", "", "", ""))
    rc(r, 1)
    only_usbmux(r, 3)
    has(r, "No iPhone found")
    has(r, "Trust")
    return r


@test("find", "F02", "no phone and end of input -> one look, exit 1; typing q also stops")
def f02():
    sc = base_scenario()
    sc["devices"] = []
    r = Run("f02a", sc).go(lines("alice", "y"))
    rc(r, 1)
    only_usbmux(r, 1)
    r2 = Run("f02b", sc).go(lines("alice", "y", "q", "", ""))
    rc(r2, 1)
    only_usbmux(r2, 1)
    has(r2, "Cancelled")
    return r


@test("find", "F03", "a phone that shows up on the second look is used")
def f03():
    sc = base_scenario()
    sc["devices"] = []
    r = Run("f03", sc)
    sess = Session(r)
    sess.until("Enter your name")
    sess.send("alice\n")
    sess.until("(y/n): ")
    sess.send("y\n")
    sess.until("No iPhone found")
    (r.stub / "scenario.json").write_text(json.dumps(dict(sc, devices=[device()])))   # phone gets plugged in
    sess.until("Press Enter to look again")
    sess.send("\n")
    sess.until("Found: Test iPhone")
    sess.until("Press Enter once")
    sess.send("\n")
    sess.finish()
    rc(r, 0)
    only_usbmux(r, 2, QUICK_CALLS)
    return r


@test("find", "F04", "exactly one phone -> auto-selected, no chooser")
def f04():
    r = Run("f04").go(lines("alice", "y", ""))
    rc(r, 0)
    has(r, "Found: Test iPhone (iPhone18,2, iOS 27.2)")
    lacks(r, "Which one")
    only_usbmux(r, 1, QUICK_CALLS)
    return r


@test("find", "F05", "two phones -> numbered chooser, '2' selects the second one")
def f05():
    sc = base_scenario()
    sc["devices"] = [device("First", UDID), device("Second", UDID2, model="iPhone15,2", ios="18.1")]
    r = Run("f05", sc).go(lines("alice", "y", "2", ""))
    rc(r, 0)
    has(r, "1) First (iPhone18,2, iOS 27.2, ID ...0001)")
    has(r, "2) Second (iPhone15,2, iOS 18.1, ID ...0002)")
    has(r, "Selected: Second (iPhone15,2, iOS 18.1)")
    lacks(r, "Selected: First")
    return r


@test("find", "F06", "bad or missing choice among several phones -> asked again, bounded, then exit 1")
def f06():
    sc = base_scenario()
    sc["devices"] = [device("First", UDID), device("Second", UDID2)]
    r = Run("f06a", sc).go(lines("alice", "y", "x", "0", "3", "1", ""))
    rc(r, 1)
    has(r, "No valid choice")
    lacks(r, "Selected:")
    r2 = Run("f06b", sc).go(lines("alice", "y"))
    rc(r2, 1)
    lacks(r2, "Selected:")
    r3 = Run("f06c", sc).go(lines("alice", "y", "x", "1", ""))
    rc(r3, 0)
    has(r3, "Selected: First")
    return r


@test("find", "F07", "usbmux list fails -> exit 1 with the reason, not 'no phone'")
def f07():
    sc = base_scenario()
    sc["usbmux_fail"] = True
    r = Run("f07", sc).go(lines("alice", "y", "", ""))
    rc(r, 1)
    has(r, "Could not look for connected phones")
    has(r, "Failed to connect to usbmuxd socket")
    lacks(r, "No iPhone found")
    only_usbmux(r, 1)
    return r


@test("find", "F08", "garbage or empty usbmux answer -> exit 1 as an error, not 'no phone'")
def f08():
    last = None
    for i, raw in enumerate(("this is not json", "", '{"not": "a list"}', '[1, 2]')):
        sc = base_scenario()
        sc["usbmux_raw"] = raw
        r = Run("f08_%d" % i, sc).go(lines("alice", "y", "", ""))
        ok(r.rc == 1, "raw %r: exit %r" % (raw, r.rc))
        ok("Could not read the list of connected phones" in r.out, "raw %r: no error shown" % raw)
        ok("No iPhone found" not in r.out, "raw %r: misreported as no phone" % raw)
        last = r
    return last


@test("find", "F09", "device IDs that are not real UDIDs are ignored and never reach a command line")
def f09():
    bad = ["../x", "-h", "00008150-0000000000000001; rm -rf ~", "short", "00008150-000000000000000G",
           "a" * 80, "00008150-0000000000000001\n", ""]
    sc = base_scenario()
    sc["devices"] = [device("Evil%d" % i, b) for i, b in enumerate(bad)] + [device("Good", UDID2)]
    r = Run("f09a", sc).go(lines("alice", "y", ""))
    rc(r, 0)
    has(r, "Found: Good (iPhone18,2, iOS 27.2)")
    has(r, "Ignored %d device(s)" % len(bad))
    for b in bad:
        if b:
            for argv in r.pmd():
                ok(b not in argv, "bad id %r reached a command line" % b)
    sc2 = base_scenario()
    sc2["devices"] = [device("Evil", "../x")]
    r2 = Run("f09b", sc2).go(lines("alice", "y", ""))
    rc(r2, 1)
    has(r2, "No iPhone found")
    return r


@test("find", "F10", "hostile device names are neutralised on screen (no escape codes, no pipes, capped)")
def f10():
    sc = base_scenario()
    sc["devices"] = [device("Ev\x1b[2Jil|na\nme‮" + "z" * 300)]
    r = Run("f10", sc).go(lines("alice", "y", ""))
    rc(r, 0)
    ok("\x1b" not in r.raw, "escape byte reached the terminal")
    has(r, "Found: Ev?[2Jil/na?me?zzz")
    ok(max(len(ln) for ln in r.out.splitlines() if "zz" in ln) < 200, "unbounded line length")   # the lines that show the name; tool paths are as long as the checkout is deep
    return r


@test("find", "F11", "network-only phones are not offered (USB only)")
def f11():
    sc = base_scenario()
    d = device()
    d["ConnectionType"] = "Network"
    sc["devices"] = [d]
    r = Run("f11", sc).go(lines("alice", "y"))
    rc(r, 1)
    has(r, "No iPhone found")
    only_usbmux(r, 1)
    return r


@test("find", "F12", "unlock + Trust guidance is on screen BEFORE the first command that pairs")
def f12():
    r = Run("f12")
    sess = Session(r)
    sess.until("Enter your name")
    sess.send("alice\n")
    sess.until("(y/n): ")
    sess.send("y\n")
    shown = sess.until("Press Enter once")
    ok("Trust This Computer" in shown and "Unlock" in shown, "guidance missing before the pause: %r" % shown[-300:])
    ok(r.pmd_cmds() == ["usbmux list"], "pairing-capable call made before the pause: %r" % r.pmd_cmds())
    sess.send("\n")
    sess.finish()
    rc(r, 0)
    return r
