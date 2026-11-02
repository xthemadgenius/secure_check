"""Group `fix`: removing flagged apps and profiles. Only with APPLY=1, only after a y for that item, only for items that
were listed, and every removal is checked again afterwards (X05, "any [DETECTED] suppresses fixes", lands with the
deep scan in group `deep`)."""
import json

from harness import UDID, Run, Session, app, base_scenario, has, lacks, no_leak, ok, profile_response, rc, test
from tests_report import in_order, section

ANSWERS = "alice\ny\n\nn\n"        # name, "this is my phone", Enter at the Trust pause, "n" to the deep scan; what follows answers the fix prompts
APPLY = {"APPLY": "1"}
SIDELOAD = "Sideload Co"
HINT = "APPLY=1 ./iphone_sec.sh"
NONE_TAKEN = "None. Nothing was changed on the phone."
SCANNED = "as it was when scanned"
SECRETS = (UDID, "SECRETSERIAL123", "+1 555 000 1234", "359999999999999")
ALPHA = ("com.dev.alpha", "Alpha Sideload")
BRAVO = ("com.dev.bravo", "Bravo Sideload")
VPN = ("com.example.vpn", "Work VPN", "Example Corp")
KIND = {"app": "app", "profile": "configuration profile"}
CONFIRMED = "confirmed gone from the phone's list."


def scen(apps=(), profiles=(), **extra):
    """The base phone plus flagged apps (bundle id, name) and profiles (id, name, organisation)."""
    sc = base_scenario()
    for bundle, name in apps:
        sc["apps"][bundle] = app(bundle, name, signer=SIDELOAD)
    sc["profiles"] = profile_response(*profiles)
    sc.update(extra)
    return sc


def go(tid, sc, answers="", apply="1"):
    return Run(tid, sc, env_extra={"APPLY": apply} if apply is not None else {}).go(ANSWERS + answers)


def removal_calls(r):
    return [a for a in r.pmd() if a[:2] in (["apps", "uninstall"], ["profile", "remove"])]


def removed_ids(r):
    return [a[-1] for a in removal_calls(r)]


def stub_state(r):
    return json.loads((r.stub / "state.json").read_text())


def actions(r):
    """The lines of the report's ACTIONS TAKEN section."""
    return section(r.report(), "ACTIONS TAKEN") or []


def app_prompt(bundle, name):
    return 'Remove the app "%s" (%s) from the phone? Its data on the phone is deleted. (y/n): ' % (name, bundle)


def prof_prompt(ident, name, org=None):
    return ('Remove the configuration profile "%s" (%s) from the phone? Settings it applied stop working. (y/n): '
            % (name, ident))


def removed(kind, ident, name):
    return 'Removed: %s "%s" (%s).' % (KIND[kind], name, ident)


def still(kind, ident, name):
    return 'Still present: %s "%s" (%s) is still on the phone' % (KIND[kind], name, ident)


def unconfirmed(kind, ident, name):
    return 'Could not confirm: %s "%s" (%s)' % (KIND[kind], name, ident)


def kept(kind, ident, name):
    return 'Kept: %s "%s" (%s) was not removed.' % (KIND[kind], name, ident)


def act_removed(kind, ident, name):
    return 'Removed %s "%s" (%s): %s' % (KIND[kind], name, ident, CONFIRMED)


def act_still(kind, ident, name):
    return 'Tried to remove %s "%s" (%s): it is still on the phone.' % (KIND[kind], name, ident)


def act_unconfirmed(kind, ident, name):
    return 'Tried to remove %s "%s" (%s): could not confirm whether it is gone.' % (KIND[kind], name, ident)


def subsequence(seq, want):
    it = iter(seq)
    return all(any(x == w for x in it) for w in want)


def crashing_probe(tid, sc, subcommand, partial):
    """A Run (APPLY=1) whose python3 dies half-way through re-checking ONE item (the helper is then given the item's ID
    as its 5th word), after printing PARTIAL (shell-quoted words, one line each), and is the real one for everything
    else. A script cannot be another script's #! interpreter on macOS, so the fake sits on PATH."""
    r = Run(tid, sc, env_extra=APPLY, shebang="#!/usr/bin/env python3")
    r.fake_cmd("python3", 'if [ "$1" = "-I" ] && [ "$2" = "-c" ] && [ "$4" = "%s" ] && [ -n "${5:-}" ]; then\n'
                          "    printf '%%s\\n' %s\n    exit 3\nfi\nexec /usr/bin/python3 \"$@\"" % (subcommand, partial))
    return r


@test("fix", "X01", "without APPLY=1 nothing is removed, even if you type y; the hint counts what could be; a clean phone gets none")
def x01():
    sc = scen(apps=[ALPHA, BRAVO], profiles=[VPN])
    for label, apply in (("unset", None), ("zero", "0"), ("empty", ""), ("true", "true"), ("yes", "yes")):
        r = go("x01_" + label, sc, "y\ny\ny\ny\n", apply=apply)
        ok(r.rc == 0, "%s: exit %r" % (label, r.rc))
        ok(removal_calls(r) == [], "%s: removal calls %r" % (label, removal_calls(r)))
        st = stub_state(r)
        ok(st["removed_apps"] == [] and st["removed_profiles"] == [], "%s: the phone was changed: %r" % (label, st))
        for text in ("3 flagged items can be removed from here.", HINT):
            ok(text in r.out, "%s: expected %r" % (label, text))
        for text in ("Remove the app", "Remove the configuration profile", "Only the items listed above", "The summary below shows"):
            ok(text not in r.out, "%s: did not expect %r" % (label, text))
        in_order(r.out, ['[REVIEW] App "Alpha Sideload"', "Fixes:", HINT, "Summary:"])
    r = go("x01_report", sc, "", apply=None)
    ok(NONE_TAKEN in r.report() and SCANNED not in r.report(), "dry run report: %r" % actions(r))
    r = go("x01_single", scen(apps=[ALPHA]), "", apply=None)
    has(r, "1 flagged item can be removed from here.")
    lacks(r, "1 flagged items")
    r = go("x01_clean", scen(), "", apply=None)      # a y here would answer the delete prompt and remove the report
    lacks(r, HINT)
    lacks(r, "Fixes:")
    ok(NONE_TAKEN in r.report(), "clean phone report: %r" % actions(r))
    return r


@test("fix", "X02", "APPLY=1: y removes exactly that app, a re-list confirms it, screen and report say so; n keeps the other")
def x02():
    r = go("x02", scen(apps=[ALPHA, BRAVO]), "y\nn\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "removed %r" % removed_ids(r))
    call = removal_calls(r)[0]
    ok(call[:2] == ["apps", "uninstall"] and call[call.index("--udid") + 1] == UDID, "call %r" % call)
    calls, cmds = r.pmd(), r.pmd_cmds()
    i = cmds.index("apps uninstall")
    ok(cmds[i + 1] == "apps list", "no re-list right after the removal: %r" % cmds[i:])
    relist = calls[i + 1]
    ok(relist[relist.index("--udid") + 1] == UDID and relist[relist.index("--type") + 1] == "Any", "re-list %r" % relist)
    ok(cmds[i + 2:] == [], "calls after the first re-list: %r" % cmds[i + 2:])
    ok(stub_state(r)["removed_apps"] == ["com.dev.alpha"], "stub state %r" % stub_state(r))
    in_order(r.out, ["Fixes:", "Only the items listed above are offered. Nothing is removed unless you answer y.",
                     app_prompt(*ALPHA), removed("app", *ALPHA), app_prompt(*BRAVO), kept("app", *BRAVO),
                     "The summary below shows the phone as it was when scanned, before these changes.", "Summary:"])
    lacks(r, removed("app", *BRAVO))
    lacks(r, "Still present")
    lacks(r, "Could not confirm")
    lacks(r, HINT)
    has(r, "Summary: 0 DETECTED, 2 REVIEW,")
    acts = actions(r)
    ok(len(acts) == 2 and SCANNED in acts[0] and acts[1] == act_removed("app", *ALPHA), "actions: %r" % acts)
    ok(NONE_TAKEN not in r.report(), "the report says nothing was changed")
    ok(acts[1] in r.zip_text(), "the ZIP's report lacks the action")
    no_leak(r, *SECRETS)
    return r


@test("fix", "X03", "a removal that did nothing (exit 0, item still listed) is 'Still present', never 'Removed'")
def x03():
    r = go("x03a", scen(profiles=[VPN], profile_remove_noop=True), "y\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.example.vpn"], "the removal was not tried: %r" % removed_ids(r))
    cmds = r.pmd_cmds()
    ok(cmds[cmds.index("profile remove") + 1] == "profile list", "no re-list: %r" % cmds)
    has(r, still("profile", "com.example.vpn", "Work VPN") + ".")
    has(r, "Settings > General > VPN & Device Management")
    has(r, "Remove Profile")
    lacks(r, "Removed:")
    lacks(r, "Could not confirm")
    ok(actions(r)[-1] == act_still("profile", "com.example.vpn", "Work VPN"), "actions: %r" % actions(r))
    r = go("x03b", scen(apps=[ALPHA], uninstall_noop=True), "y\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "the removal was not tried: %r" % removed_ids(r))
    cmds = r.pmd_cmds()
    ok(cmds[cmds.index("apps uninstall") + 1] == "apps list", "no re-list: %r" % cmds)
    has(r, still("app", *ALPHA) + ".")
    has(r, "Remove App")
    lacks(r, "Removed:")
    ok(actions(r)[-1] == act_still("app", *ALPHA), "actions: %r" % actions(r))
    return r


UNSAFE_APP_IDS = ["-h", "--udid", "-x", "com.dev.x;rm -rf ~", "a b", "$(id)", "`id`", "x|y", "a/b", "../x", ".hidden", "_x",
                  "com.dev.nl\n", "com.dev.café", "b" * 81]
UNSAFE_PROFILE_IDS = ["-bad", "../x", "bad id", "p;q", "c" * 81]


@test("fix", "X04", "IDs that are not plain are never offered and never reach a command line; ordinary ones are, up to 80 characters")
def x04():
    apps = [(b, "Name%d" % i) for i, b in enumerate(UNSAFE_APP_IDS)]
    profs = [(p, "Prof%d" % i, "Org") for i, p in enumerate(UNSAFE_PROFILE_IDS)]
    r = go("x04a", scen(apps=apps, profiles=profs), "y\ny\ny\ny\n")
    rc(r, 0)
    ok(removal_calls(r) == [], "calls for refused IDs: %r" % removal_calls(r))
    for argv in r.pmd():
        for bad in UNSAFE_APP_IDS + UNSAFE_PROFILE_IDS:
            if bad != "--udid":     # every command line carries that word as its real option; removal_calls() above covers it
                ok(bad not in argv, "refused ID %r reached a command line" % bad)
    for text in ("15 flagged apps cannot be removed from here. Remove them yourself: press and hold the app's icon",
                 "5 flagged configuration profiles cannot be removed from here. Remove them yourself: Settings > General",
                 "Remove App", "Remove Profile"):
        ok(text in r.out, "expected %r" % text)
    for text in ("Remove the app", "Remove the configuration profile", "Only the items listed above", "can be removed from here."):
        ok(text not in r.out, "did not expect %r" % text)
    r = go("x04b", scen(apps=apps, profiles=profs), "", apply=None)
    for text in ("15 flagged apps cannot be removed from here", "5 flagged configuration profiles cannot be removed from here"):
        ok(text in r.out, "dry run: expected %r" % text)
    lacks(r, HINT)
    lacks(r, "can be removed from here.")
    r = go("x04c", scen(apps=[ALPHA, ("-h", "Dash")], profiles=[VPN, ("-bad", "Dash profile", "Org")]), "y\ny\n")
    ok(removed_ids(r) == ["com.example.vpn", "com.dev.alpha"], "mixed: %r" % removed_ids(r))
    has(r, "1 flagged app cannot be removed from here. Remove it yourself: press and hold the app's icon")
    has(r, "1 flagged configuration profile cannot be removed from here. Remove it yourself: Settings > General")
    r = go("x04d", scen(apps=[ALPHA, ("-h", "Dash")], profiles=[VPN, ("-bad", "Dash profile", "Org")]), "", apply=None)
    has(r, "2 flagged items can be removed from here.")
    ok("1 flagged app cannot be removed from here" in r.out, "dry run: by-hand line missing")
    long80, long81 = "a" * 80, "z" * 81
    apps = [(long80, "A1"), ("com.dev.my_app-2", "A2"), ("1.2.3", "A3"), (long81, "A4")]
    r = go("x04e", scen(apps=apps, profiles=[("p" * 80, "P1", "Org")]), "y\ny\ny\ny\n")
    ok(removed_ids(r) == ["p" * 80, long80, "com.dev.my_app-2", "1.2.3"], "ordinary IDs: %r" % removed_ids(r))
    has(r, "1 flagged app cannot be removed from here")
    return r


@test("fix", "X06", "the prompt is on screen before any removal call is made; n and end of input keep the item")
def x06():
    sc = scen(apps=[ALPHA])
    r = Run("x06a", sc, env_extra=APPLY)
    sess = Session(r)
    sess.until("Enter your name")
    sess.send("alice\n")
    sess.until("(y/n): ")
    sess.send("y\n")
    sess.until("Press Enter once")
    sess.send("\n")
    sess.until("Run the deep scan? (y/n): ")
    sess.send("n\n")
    sess.until(app_prompt(*ALPHA))
    ok(removal_calls(r) == [], "removed before being asked: %r" % removal_calls(r))
    sess.send("y\n")
    sess.until(removed("app", *ALPHA))
    sess.finish()
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "removed %r" % removed_ids(r))
    for label, answers in (("n", "n\n"), ("eof", ""), ("blank", "\n"), ("word", "no\n"), ("maybe", "maybe\n")):
        r = go("x06_" + label, sc, answers)
        ok(r.rc == 0, "%s: exit %r" % (label, r.rc))
        ok(removal_calls(r) == [], "%s: removed anyway: %r" % (label, removal_calls(r)))
        ok(app_prompt(*ALPHA) in r.out and kept("app", *ALPHA) in r.out, "%s: no prompt or no 'Kept' line" % label)
        ok(NONE_TAKEN in r.report() and "Removed" not in r.report(), "%s: report: %r" % (label, actions(r)))
        ok("The summary below shows" not in r.out, "%s: 'after these changes' note without a change" % label)
    return r


@test("fix", "X07", "a removal command that fails and leaves the item -> 'Still present' with the phone's reason (phone ID masked)")
def x07():
    msg = "Device %s refused: the item is managed" % UDID
    reason = "(the removal command said: Device (phone ID) refused: the item is managed)"
    r = go("x07a", scen(apps=[ALPHA], uninstall_fail=msg), "y\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "the removal was not tried: %r" % removed_ids(r))
    has(r, still("app", *ALPHA) + " " + reason + ".")
    has(r, "Remove App")
    lacks(r, "Removed:")
    ok(actions(r)[-1] == act_still("app", *ALPHA), "actions: %r" % actions(r))
    no_leak(r, UDID)
    r = go("x07b", scen(profiles=[VPN], profile_remove_fail=msg), "y\n")
    rc(r, 0)
    has(r, still("profile", "com.example.vpn", "Work VPN") + " " + reason + ".")
    has(r, "Remove Profile")
    lacks(r, "Removed:")
    ok(actions(r)[-1] == act_still("profile", "com.example.vpn", "Work VPN"), "actions: %r" % actions(r))
    no_leak(r, UDID)
    return r


@test("fix", "X08", "a removal command that reports an error but the item is gone from the re-list -> 'Removed'")
def x08():
    r = go("x08a", scen(apps=[ALPHA], remove_fail_after="the phone closed the connection"), "y\n")
    rc(r, 0)
    has(r, removed("app", *ALPHA))
    lacks(r, "Still present")
    ok(actions(r)[-1] == act_removed("app", *ALPHA), "actions: %r" % actions(r))
    r = go("x08b", scen(profiles=[VPN], remove_fail_after="the phone closed the connection"), "y\n")
    rc(r, 0)
    has(r, removed("profile", "com.example.vpn", "Work VPN"))
    lacks(r, "Still present")
    ok(actions(r)[-1] == act_removed("profile", "com.example.vpn", "Work VPN"), "actions: %r" % actions(r))
    return r


@test("fix", "X09", "a re-list that cannot be read or crashes -> 'Could not confirm', never 'Removed' and never 'Still present'")
def x09():
    cases = (("app", "com.dev.alpha", "Alpha Sideload", lambda **kw: scen(apps=[ALPHA], **kw)),
             ("profile", "com.example.vpn", "Work VPN", lambda **kw: scen(profiles=[VPN], **kw)))
    last = None
    for kind, ident, name, build in cases:
        for label, extra in (("fail", {"relist_fail": "the phone stopped answering"}),
                             ("late", {"relist_late_fail": "the phone dropped off the cable"}),
                             ("garbage", {"relist_raw": "this is not json"}),
                             ("empty", {"relist_raw": ""}), ("emptyobject", {"relist_raw": "{}"}),
                             ("wrongshape", {"relist_raw": "[1, 2]"})):
            r = go("x09_%s_%s" % (kind, label), build(**extra), "y\n")
            tag = "%s/%s" % (kind, label)
            ok(r.rc == 0, "%s: exit %r" % (tag, r.rc))
            ok(removed_ids(r) == [ident], "%s: removal calls %r" % (tag, removed_ids(r)))
            ok(unconfirmed(kind, ident, name) in r.out, "%s: no 'Could not confirm' line" % tag)
            ok("Removed:" not in r.out and "Still present" not in r.out, "%s: claimed an outcome it did not see" % tag)
            ok(actions(r)[-1] == act_unconfirmed(kind, ident, name), "%s: actions %r" % (tag, actions(r)))
            last = r
        st = stub_state(last)
        ok(st["removed_apps" if kind == "app" else "removed_profiles"] == [ident], "%s: the stub did not remove it" % kind)
    partial = {"app": ("apps", "'SEEN|0' 'CNT|2|2|0'"), "profile": ("profiles", "'SEEN|0' 'NONE'")}
    for kind, ident, name, build in cases:
        sub, words = partial[kind]
        r = crashing_probe("x09_%s_crash" % kind, build(), sub, words).go(ANSWERS + "y\n")
        ok(r.rc == 0, "%s crash: exit %r" % (kind, r.rc))
        ok(unconfirmed(kind, ident, name) in r.out, "%s crash: no 'Could not confirm' line: %r" % (kind, r.out[-400:]))
        ok("Removed:" not in r.out, "%s crash: partial output was believed" % kind)
        ok(actions(r)[-1] == act_unconfirmed(kind, ident, name), "%s crash: actions %r" % (kind, actions(r)))
    return r


@test("fix", "X10", "an app that is still installed but no longer looks flagged is 'Still present', not 'Removed'")
def x10():
    r = go("x10", scen(apps=[ALPHA], uninstall_resign="Apple iPhone OS Application Signing"), "y\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "the removal was not tried: %r" % removed_ids(r))
    st = stub_state(r)
    ok(st["removed_apps"] == [] and "com.dev.alpha" in st["resigned"], "stub state %r" % st)
    has(r, still("app", *ALPHA))
    lacks(r, "Removed:")
    ok(actions(r)[-1] == act_still("app", *ALPHA), "actions: %r" % actions(r))
    return r


@test("fix", "X11", "APPLY=1 on a phone with nothing flagged says nothing about fixes and asks nothing")
def x11():
    r = go("x11", scen(), "")       # nothing to answer: a y would only reach the delete prompt and remove the report
    rc(r, 0)
    lacks(r, "Fixes:")
    lacks(r, "Remove the")
    lacks(r, HINT)
    ok(removal_calls(r) == [], "removal calls %r" % removal_calls(r))
    ok(NONE_TAKEN in r.report(), "report: %r" % actions(r))
    return r


@test("fix", "X12", "only the 25 listed apps and the 25 listed profiles are offered; the rest are counted, not offered")
def x12():
    apps = [("com.dev.app%02d" % i, "App%02d" % i) for i in range(1, 28)]
    r = go("x12a", scen(apps=apps), "n\n" * 25)
    rc(r, 0)
    ok(r.out.count('Remove the app "') == 25, "app prompts: %d" % r.out.count('Remove the app "'))
    for text in ('Remove the app "App25"', "...and 2 more apps not signed by the App Store (not listed here).",
                 "Only the items listed above are offered.", "2 flagged apps cannot be removed from here. Remove them yourself:"):
        ok(text in r.out, "expected %r" % text)
    for text in ('Remove the app "App26"', 'Remove the app "App27"', "com.dev.app26", "com.dev.app27"):
        ok(text not in r.out.split("Fixes:")[1], "did not expect %r among the offers" % text)
    ok(removal_calls(r) == [], "removal calls %r" % removal_calls(r))
    profs = [("com.dev.p%02d" % i, "Prof%02d" % i, "Org") for i in range(1, 27)]
    r = go("x12b", scen(profiles=profs), "n\n" * 25)
    rc(r, 0)
    ok(r.out.count('Remove the configuration profile "') == 25, "profile prompts: %d" % r.out.count('Remove the configuration profile "'))
    has(r, "...and 1 more configuration profile (not listed here).")
    has(r, "1 flagged configuration profile cannot be removed from here. Remove it yourself:")
    lacks(r, 'Remove the configuration profile "Prof26"')
    r = go("x12c", scen(apps=apps, profiles=profs), "", apply=None)
    has(r, "50 flagged items can be removed from here.")
    has(r, "2 flagged apps cannot be removed from here. Remove them yourself:")
    has(r, "1 flagged configuration profile cannot be removed from here. Remove it yourself:")
    return r


@test("fix", "X13", "hostile names are neutralised in the prompts, the outcome lines and the report; the ID used is the real one")
def x13():
    evil = "Ev\x1b[2Jil|na\nme"
    shown = "Ev?[2Jil/na?me"
    r = go("x13", scen(apps=[("com.dev.evil", evil)], profiles=[("com.dev.prof", evil, evil)]), "y\ny\n")
    rc(r, 0)
    ok("\x1b" not in r.raw, "escape byte reached the terminal")
    ok(removed_ids(r) == ["com.dev.prof", "com.dev.evil"], "removed %r" % removed_ids(r))
    has(r, prof_prompt("com.dev.prof", shown))
    has(r, app_prompt("com.dev.evil", shown))
    has(r, removed("profile", "com.dev.prof", shown))
    has(r, removed("app", "com.dev.evil", shown))
    acts = actions(r)
    ok(act_removed("profile", "com.dev.prof", shown) in acts and act_removed("app", "com.dev.evil", shown) in acts, "actions: %r" % acts)
    ok("\x1b" not in r.report() and "\x1b" not in r.zip_text(), "escape byte reached the report")
    return r


@test("fix", "X14", "profiles come first, then apps; each kind has its own warning; the profile one tells you to watch the phone")
def x14():
    r = go("x14", scen(apps=[ALPHA], profiles=[VPN]), "y\ny\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.example.vpn", "com.dev.alpha"], "removed %r" % removed_ids(r))
    ok(subsequence(r.pmd_cmds(), ["profile remove", "profile list", "apps uninstall", "apps list"]), "call order: %r" % r.pmd_cmds())
    in_order(r.out, ["Fixes:", "Only the items listed above are offered.", prof_prompt("com.example.vpn", "Work VPN"),
                     "If the phone asks for its passcode, enter it on the phone.", removed("profile", "com.example.vpn", "Work VPN"),
                     app_prompt(*ALPHA), removed("app", *ALPHA), "Summary:"])
    ok(r.out.count("If the phone asks for its passcode") == 1, "the passcode hint belongs to profiles only")
    acts = actions(r)
    ok(acts[1:] == [act_removed("profile", "com.example.vpn", "Work VPN"), act_removed("app", *ALPHA)], "actions: %r" % acts)
    st = stub_state(r)
    ok(st["removed_apps"] == ["com.dev.alpha"] and st["removed_profiles"] == ["com.example.vpn"], "stub state %r" % st)
    for call in r.pmd():
        if call[:2] != ["usbmux", "list"]:
            ok("--udid" in call and call[call.index("--udid") + 1] == UDID, "call without the phone's ID: %r" % call)
    return r


def only_in(ident, where):
    """A re-list of profiles that names IDENT in just one of the three places the phone may list it."""
    return json.dumps({"Status": "Acknowledged", "OrderedIdentifiers": [ident] if where == "order" else [],
                       "ProfileMetadata": {ident: {"PayloadDisplayName": "Work VPN"}} if where == "meta" else {},
                       "ProfileManifest": {ident: {"Description": "stub"}} if where == "manifest" else {}})


@test("fix", "X15", "presence is exact: a neighbour with a longer ID does not hide a removal; a profile named in any one list is still there")
def x15():
    near = ("com.dev.alpha.helper", "Alpha Sideload Helper")
    r = go("x15a", scen(apps=[ALPHA, near]), "y\nn\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.dev.alpha"], "removed %r" % removed_ids(r))
    has(r, removed("app", *ALPHA))
    lacks(r, "Still present")
    ok(actions(r)[-1] == act_removed("app", *ALPHA), "actions: %r" % actions(r))
    extra = ("com.example.vpn.extra", "Extra VPN", "Example Corp")
    r = go("x15b", scen(profiles=[VPN, extra]), "y\nn\n")
    rc(r, 0)
    ok(removed_ids(r) == ["com.example.vpn"], "removed %r" % removed_ids(r))
    has(r, removed("profile", "com.example.vpn", "Work VPN"))
    lacks(r, "Still present")
    last = r
    for where in ("order", "meta", "manifest"):
        r = go("x15_" + where, scen(profiles=[VPN], relist_raw=only_in("com.example.vpn", where)), "y\n")
        rc(r, 0)
        ok(still("profile", "com.example.vpn", "Work VPN") in r.out, "%s only: not reported as still present" % where)
        ok("Removed:" not in r.out, "%s only: reported as removed" % where)
        ok(actions(r)[-1] == act_still("profile", "com.example.vpn", "Work VPN"), "%s only: actions %r" % (where, actions(r)))
    return last
