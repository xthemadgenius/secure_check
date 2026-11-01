#!/bin/bash

# ============================================================================
# IPHONE SECURITY SCANNER v1.0
# Screens an iPhone connected to this Mac over USB (quick checks, then an
# optional deep scan with Amnesty International's MVT), writes one report and
# packages it into NAME.iPhone_Security_Check.zip
# Needs: pipx install pymobiledevice3 && pipx install mvt
# ============================================================================

# --- Robustness: cleanup on exit/interrupt ---
# (Not using set -e because we want checks to continue even if individual commands fail)
set -uo pipefail
umask 077   # the report, backup and temp files this script writes are private to you

APPLY="${APPLY:-0}"   # APPLY=1 turns on the "remove this app/profile?" prompts

# Track paths for cleanup
REPORT_DIR=""
REPORT_DIR_MADE=0
ZIP_PATH=""
TMP_DIR=""
PMD=""
MVT=""
PY=""

# The deep scan keeps the phone's backup in a private folder here, never inside the report ZIP
WORK_ROOT="$HOME/Library/Application Support/secure_check"
WORK_DIR=""
WORK_DIR_MADE=0
BACKUP_STARTED=0
WORK_NOTE_SHOWN=0
ENC_PENDING=0   # 1 while the phone is being asked to turn backup encryption on, until its answer is in
BACKUP_PW=""
HIDDEN_REPLY=""
PASSCODE_KNOWN=0

# PATH with the home folder shortened to ~ (shorter, and keeps the user name out of what gets shared)
tilde_path() {
    if [[ "$1" == "$HOME"/* ]]; then
        printf '%s' "~/${1#"$HOME"/}"
    else
        printf '%s' "$1"
    fi
}

# True only for the private folder this script made: a real folder (not a link) directly under WORK_ROOT
safe_work_dir() {
    local rest
    [[ "$WORK_DIR_MADE" -eq 1 && -n "$WORK_DIR" && -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] || return 1
    [[ "$WORK_DIR" == "$WORK_ROOT"/iphone_* ]] || return 1
    rest="${WORK_DIR#"$WORK_ROOT"/}"
    [[ "$rest" != */* ]]
}

# Remove the private folder again while nothing from the phone is in it
drop_work_dir() {
    if [[ "$BACKUP_STARTED" -eq 0 ]] && safe_work_dir; then
        rm -rf "$WORK_DIR"
    fi
}

# The decrypted copy holds all of the phone's data in the clear, so it never outlives the check that needed it
drop_decrypted() {
    if safe_work_dir; then
        rm -rf "$WORK_DIR/decrypted"
    fi
}

cleanup() {
    [[ -t 0 ]] && stty echo 2>/dev/null   # an interrupt at a password prompt must not leave the terminal silent
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    # Drop the report folder again if this script made it and stopped before anything was left in it
    [[ "$REPORT_DIR_MADE" -eq 1 && -n "$REPORT_DIR" ]] && rmdir "$REPORT_DIR" 2>/dev/null
    drop_decrypted
    # Stopped while the phone may have been changing a setting that stays: nothing else would tell you
    if [[ "$ENC_PENDING" -eq 1 ]]; then
        echo ""
        echo "The script stopped while it was turning on backup encryption on the phone."
        echo "The phone's backup setting may have changed: check \"Encrypt local backup\" in Finder."
        echo "If it is on, the password you just typed is its backup password."
    fi
    if [[ "$BACKUP_STARTED" -eq 1 && "$WORK_NOTE_SHOWN" -eq 0 ]] && safe_work_dir; then
        echo ""
        echo "The script stopped before it finished."
        echo "The backup so far is in a private folder on this Mac: $(tilde_path "$WORK_DIR")"
    fi
    drop_work_dir
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    echo "Usage: ./iphone_sec.sh"
    echo "       APPLY=1 ./iphone_sec.sh    also offer to remove flagged apps/profiles (each one asks first)"
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown argument."; usage; exit 1 ;;
    esac
fi

# --- macOS check ---
if [[ "$(uname)" != "Darwin" ]]; then
    echo "ERROR: This script only runs on macOS."
    exit 1
fi

# --- Check required tools (nothing is installed automatically) ---
if ! command -v zip &>/dev/null; then
    echo "ERROR: Required command 'zip' not found."
    exit 1
fi

find_tool() {
    local name="$1" found
    if found="$(command -v "$name" 2>/dev/null)" && [[ -x "$found" ]]; then
        printf '%s' "$found"
    elif [[ -x "$HOME/.local/bin/$name" ]]; then
        printf '%s' "$HOME/.local/bin/$name"
    fi
}

PMD="$(find_tool pymobiledevice3)"
MVT="$(find_tool mvt-ios)"
MISSING_TOOLS=0
if [[ -z "$PMD" ]]; then
    echo "ERROR: Required tool 'pymobiledevice3' not found."
    MISSING_TOOLS=1
fi
if [[ -z "$MVT" ]]; then
    echo "ERROR: Required tool 'mvt-ios' not found."
    MISSING_TOOLS=1
fi
if [[ "$MISSING_TOOLS" -eq 1 ]]; then
    echo ""
    echo "Install what is missing, then run this script again (nothing is installed automatically):"
    if ! command -v pipx &>/dev/null; then
        if command -v brew &>/dev/null; then
            echo "    brew install pipx"
        else
            echo "    brew install pipx        (Homebrew itself: https://brew.sh)"
        fi
    fi
    [[ -z "$PMD" ]] && echo "    pipx install pymobiledevice3"
    [[ -z "$MVT" ]] && echo "    pipx install mvt"
    echo "    pipx ensurepath          (then open a new Terminal window)"
    exit 1
fi

# The helper that parses the phone's answers runs on the Python that pymobiledevice3 itself
# uses (read from its launcher's first line), else on python3 from PATH.
find_python() {
    local line cand="" first
    line="$(head -n 1 "$PMD" 2>/dev/null)"
    if [[ "$line" == "#!"* ]]; then
        line="${line:2}"
        line="${line# }"
        first="${line%% *}"
        if [[ -x "$line" && "${line##*/}" == python* ]]; then
            cand="$line"
        elif [[ -x "$first" && "${first##*/}" == python* ]]; then
            cand="$first"
        fi
    fi
    [[ -z "$cand" ]] && cand="$(command -v python3 2>/dev/null)"
    if [[ -n "$cand" ]] && "$cand" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        printf '%s' "$cand"
    fi
}

PY="$(find_python)"
if [[ -z "$PY" ]]; then
    echo "ERROR: Python 3.8 or newer is required and was not found."
    echo "       Install it with: brew install python"
    exit 1
fi

# --- Color codes (plain text when the output is not a terminal) ---
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    GRAY='\033[0;90m'
    NC='\033[0m'
    clear
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; PURPLE=''; CYAN=''; GRAY=''; NC=''
fi

# --- Prompts: line based, so they also work on piped input; end of input counts as "no" ---
ask_yn() {
    local reply=""
    printf '%s' "$1"
    if IFS= read -r reply; then
        [[ -t 0 ]] || echo ""   # a terminal shows the Enter key as a new line; piped input does not
    else
        echo ""
    fi
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# A prompt that shows nothing while typing. The answer is left in HIDDEN_REPLY (empty at end of
# input); it is never passed through $(...) so it is not copied around.
ask_hidden() {
    printf '%s' "$1"
    IFS= read -rs HIDDEN_REPLY || HIDDEN_REPLY=""
    echo ""
}

# Print a line in a colour. TEXT is printed literally (never interpreted), so it is safe
# for text that came from the phone.
say() {
    printf '%b%s%b\n' "$1" "$2" "$NC"
}

# The size of a file or folder as du prints it (like 44K), or nothing if it cannot be read.
# macOS pads short sizes with a leading space; read drops it.
size_of() {
    local out="" size=""
    out="$(du -sh "$1" 2>/dev/null)" || return 0
    read -r size _ <<< "$out"
    printf '%s' "$size"
}

# --- Helper: everything the phone (or a tool) sends back is parsed and sanitised here ---
# Stdlib-only Python. Reads the tool's output on stdin and prints lines like KIND|field|field.
# Text from the phone has control characters replaced by '?' and '|' by '/', and is length
# capped, so it can neither garble the terminal nor break the line format.
IFS= read -r -d '' PYHELPER <<'PYEOF' || true
import json
import os
import plistlib
import re
import sys
import unicodedata

UDID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40}")
UNSAFE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
APP_STORE_SIGNER = "Apple iPhone OS Application Signing"
# Only an ID this plain is ever put on a removal command line; any other is left for its owner to remove by hand
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
# MVT's alert levels, and the tag each one gets in the report (INFORMATIONAL ones are only counted)
LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_TAGS = {"CRITICAL": "DETECTED", "HIGH": "DETECTED", "MEDIUM": "REVIEW", "LOW": "INFO"}
LIST_CAP = 25
# One line of MVT's command.log; a line that does not match is the continuation of the one before
LOG_LINE_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} - (\S+) - ([A-Z]+) - (.*)")
PRODUCED_RE = re.compile(r"MVT produced ([0-9]+) ([A-Z]+) alerts\.")
LOADED_RE = re.compile(r"Loaded a total of ([0-9]+) unique indicators")


def clean(value, cap=80):
    text = "" if value is None else str(value)
    out = []
    for ch in text:
        if ch == "|":
            out.append("/")
        elif unicodedata.category(ch) in UNSAFE_CATEGORIES:
            out.append("?")
        else:
            out.append(ch)
    text = "".join(out)
    return text if len(text) <= cap else text[:cap - 3] + "..."


def emit(*fields):
    print("|".join(fields))


def fixable(ident):
    # "1" when IDENT (the raw ID, not the cleaned text) is plain enough to be passed to a removal command
    return "1" if SAFE_ID_RE.fullmatch(ident) else "0"


def read_json():
    """(data, None), or (None, why) when the tool printed nothing or something that is not JSON."""
    raw = sys.stdin.read()
    if not raw.strip():
        return None, "the answer was empty"
    try:
        return json.loads(raw), None
    except ValueError:
        return None, "the answer was not valid JSON"


def cmd_devices():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        emit("ERR", "the answer was not valid JSON")
        return
    if not isinstance(data, list) or not all(isinstance(d, dict) for d in data):
        emit("ERR", "the answer was not a list of devices")
        return
    seen, ignored = set(), 0
    for dev in data:
        udid = dev.get("UniqueDeviceID") or dev.get("Identifier") or ""
        if not isinstance(udid, str) or not UDID_RE.fullmatch(udid):
            ignored += 1
            continue
        if udid in seen:
            continue
        seen.add(udid)
        emit("DEV", udid, clean(dev.get("DeviceName")) or "(unnamed)",
             clean(dev.get("ProductType")) or "unknown model", clean(dev.get("ProductVersion")) or "?")
    if ignored:
        emit("IGN", str(ignored))


def cmd_reason():
    text = sys.stdin.read()
    # A password the tool printed back is hidden first (before anything is trimmed, matched or cut short), in each way it
    # may have been printed: as typed, or escaped the way JSON or Python text shows it
    secret = os.environ.get("SECRET_TEXT", "")
    if secret:
        spellings = {secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], repr(secret)[1:-1]}
        for spelling in sorted(spellings - {""}, key=len, reverse=True):
            text = text.replace(spelling, "(password)")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    pick = ""
    for ln in reversed(lines):
        m = re.search(r"\b(?:ERROR|CRITICAL|WARNING)\b\s+(.*)$", ln)
        if m:
            pick = m.group(1)
            break
    if not pick and lines:
        pick = lines[-1]
    # The phone's ID is not printed or reported in full, so it is masked before the text is cut short
    emit("REASON", clean(UDID_RE.sub("(phone ID)", pick), 160) or "no details were printed")


def cmd_info():
    data, why = read_json()
    if why:
        emit("ERR", why)
    elif not isinstance(data, dict):
        emit("ERR", "the answer was not a JSON object")
    else:
        # Whitelist: the same answer also holds the serial number, IMEI and phone number
        name, model, ios, build = (clean(data.get(key)) for key in
                                   ("DeviceName", "ProductType", "ProductVersion", "BuildVersion"))
        if name or ios:
            emit("PHONE", name, model, ios, build)
        else:
            emit("ERR", "the answer had neither a device name nor an iOS version")


def cmd_profiles(probe=""):
    # With PROBE (a profile ID) it also says whether the phone lists exactly that ID: SEEN|1 or SEEN|0
    data, why = read_json()
    if why:
        emit("ERR", why)
        return
    if not isinstance(data, dict):
        emit("ERR", "the answer was not a JSON object")
        return
    if data.get("Status") != "Acknowledged":
        emit("ERR", "the phone did not acknowledge the request")
        return
    order, meta, manifest = data.get("OrderedIdentifiers"), data.get("ProfileMetadata"), data.get("ProfileManifest")
    if order is not None and not (isinstance(order, list) and all(isinstance(i, str) for i in order)):
        emit("ERR", "the profile list had an unexpected format")
        return
    if any(x is not None and not isinstance(x, dict) for x in (meta, manifest)):
        emit("ERR", "the profile details had an unexpected format")
        return
    if order is None and meta is None:
        # Never say "none installed" unless the phone said so in a form we understand
        emit("ERR", "the answer did not contain a list of profiles")
        return
    # Every profile that any of the lists mentions is shown, so none can hide in one of them
    ids, seen = [], set()
    for ident in (order or []) + sorted(meta or {}) + sorted(manifest or {}):
        if ident not in seen:
            seen.add(ident)
            ids.append(ident)
    if probe:
        emit("SEEN", "1" if probe in ids else "0")
    if not ids:
        emit("NONE")
        return
    for ident in ids:
        entry = (meta or {}).get(ident)
        entry = entry if isinstance(entry, dict) else {}
        emit("PROF", clean(ident), clean(entry.get("PayloadDisplayName")) or clean(ident),
             clean(entry.get("PayloadOrganization")) or "an unknown organisation", fixable(ident))


def cmd_apps(probe=""):
    # With PROBE (a bundle ID) it also says whether the phone lists exactly that app, whoever signed it: SEEN|1 or SEEN|0
    data, why = read_json()
    if why:
        emit("ERR", why)
        return
    if not isinstance(data, dict) or not data or not all(isinstance(v, dict) for v in data.values()):
        emit("ERR", "the answer was not a list of apps")
        return
    if not any(isinstance(v.get("ApplicationType"), str) for v in data.values()):
        emit("ERR", "the apps did not say whether they are system apps or yours")
        return
    if probe:
        emit("SEEN", "1" if probe in data else "0")
    flagged, total, store, unsigned = [], 0, 0, 0
    for bundle, entry in data.items():
        if entry.get("ApplicationType") != "User":
            continue
        total += 1
        signer = entry.get("SignerIdentity")
        if not isinstance(signer, str) or not signer.strip():
            unsigned += 1
        elif signer == APP_STORE_SIGNER:
            store += 1
        else:
            name = entry.get("CFBundleDisplayName") or entry.get("CFBundleName") or bundle
            flagged.append((clean(name), clean(bundle), clean(signer), fixable(bundle)))
    for name, bundle, signer, fix in sorted(flagged, key=lambda f: (f[0].casefold(), f[1])):
        emit("APP", bundle, name, signer, fix)
    emit("CNT", str(total), str(store), str(unsigned))


def cmd_willencrypt():
    # The phone's answer to "will your backups be encrypted?": ENC|1, ENC|0 or ERR|why. Nothing but a plain true/false counts.
    raw = sys.stdin.read().strip()
    if not raw:
        emit("ERR", "the answer was empty")
    elif raw in ("true", "false"):
        emit("ENC", "1" if raw == "true" else "0")
    else:
        emit("ERR", "the answer was not true or false")


def cmd_backupstate(path):
    # What a backup says about itself: STATE|encrypted|passcode-was-set, each 1, 0 or ? (not a real yes/no), or ERR|why
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        emit("ERR", "the backup's Manifest.plist could not be read")
        return
    if not isinstance(data, dict):
        emit("ERR", "the backup's Manifest.plist was not in the expected format")
        return

    def flag(key):
        value = data.get(key)
        return ("1" if value else "0") if isinstance(value, bool) else "?"

    emit("STATE", flag("IsEncrypted"), flag("WasPasscodeSet"))


def mask(value, cap):
    # Text that came from the phone's data or from a tool: the phone's ID masked, then made safe to print
    text = "" if value is None else str(value)
    return clean(UDID_RE.sub("(phone ID)", text), cap)


def first_line(value):
    lines = ("" if value is None else str(value)).strip().splitlines()
    return lines[0].strip() if lines else ""


def plural(n, one, many):
    return one if n == 1 else many


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def load_alerts(path):
    """("absent", []), ("unreadable", []) or ("ok", [alert dicts]) for MVT's alerts.json (it only exists when there are alerts)."""
    if not os.path.lexists(path):
        return "absent", []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return "unreadable", []
    if not isinstance(data, list) or not all(isinstance(a, dict) for a in data):
        return "unreadable", []
    return "ok", data


def cmd_mvt(results_dir, console_file, exit_status):
    # Judges one MVT check-backup run from the files it left. Prints F|TAG|WEIGHT|TEXT for every finding, then END;
    # END missing means this code stopped part way and the caller must say so.
    found = []

    def add(tag, text, weight=1):
        emit("F", tag, str(weight), text)
        found.append(tag)

    state, alerts = load_alerts(os.path.join(results_dir, "alerts.json"))
    if state == "unreadable":
        add("UNKNOWN", "MVT's alerts file could not be read, so its findings are not known.")
    by_level = {level: [] for level in LEVELS}
    odd = []
    for alert in alerts:
        level = alert.get("level")
        if isinstance(level, str) and level in by_level:
            by_level[level].append(alert)
        else:
            odd.append(alert)

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        items = by_level[level]
        for alert in items[:LIST_CAP]:
            add(ALERT_TAGS[level], 'MVT %s alert in the "%s" check: %s' % (
                level, mask(alert.get("module"), 40) or "unknown", mask(alert.get("message"), 200) or "(no details)"))
        if len(items) > LIST_CAP:
            more = len(items) - LIST_CAP
            add(ALERT_TAGS[level], "...and %d more MVT %s alert%s (see alerts.json in the private folder)." % (
                more, level, plural(more, "", "s")), more)
    for alert in odd[:LIST_CAP]:
        add("UNKNOWN", 'MVT reported an alert with an unrecognised level ("%s"), so it was not sorted: %s' % (
            mask(alert.get("level"), 40) or "missing", mask(alert.get("message"), 200) or "(no details)"))
    if len(odd) > LIST_CAP:
        more = len(odd) - LIST_CAP
        add("UNKNOWN", "...and %d more MVT alert%s with an unrecognised level (see alerts.json in the private folder)." % (
            more, plural(more, "", "s")), more)

    # MVT prints its own count of alerts per level; both counts come from the same list, so they must agree
    console = {}
    for ln in (read_text(console_file) or "").splitlines():
        m = PRODUCED_RE.search(ln)
        if m and m.group(2) in LEVELS:
            console[m.group(2)] = int(m.group(1))
    n_info = max(len(by_level["INFORMATIONAL"]), console.get("INFORMATIONAL", 0))
    if n_info:
        add("INFO", "MVT also recorded %d informational alert%s." % (n_info, plural(n_info, "", "s")))
    if not console:
        add("UNKNOWN", "MVT's summary of alerts could not be found in its output, so the alert counts were not cross-checked.")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        said, listed = console.get(level), len(by_level[level])
        if said is None:
            continue
        if said > listed and level in ("CRITICAL", "HIGH", "MEDIUM"):
            short = said - listed
            add(ALERT_TAGS[level], "MVT's own summary counts %d more %s alert%s than its alerts file lists (see the private folder)." % (
                short, level, plural(short, "", "s")), short)
        if said != listed and state != "unreadable":
            add("UNKNOWN", "MVT's summary says %d %s alert%s but its alerts file lists %d, so the findings may be incomplete." % (
                said, level, plural(said, "", "s"), listed))

    try:
        code = int(exit_status)
    except ValueError:
        code = None
    if code != 0:
        add("UNKNOWN", "MVT did not finish normally (exit status %s), so the backup was not fully checked." % (
            "unknown" if code is None else code))
    if not os.path.isfile(os.path.join(results_dir, "info.json")):
        add("UNKNOWN", "MVT did not finish (it left no completion marker), so the backup was not fully checked.")

    loaded = None
    log_text = read_text(os.path.join(results_dir, "command.log"))
    if log_text is None:
        add("UNKNOWN", "MVT's log could not be read, so it is not known whether every check ran.")
    else:
        # MVT logs every alert too (under the level's own name), so a line that repeats an alert is not a separate event
        echoed = {first_line(a.get("message")) for a in alerts}
        echoed.discard("")
        errors, incomplete, outdated = [], None, None
        for ln in log_text.splitlines():
            m = LOG_LINE_RE.fullmatch(ln)
            if not m:
                continue
            level, text = m.group(2), m.group(3).strip()
            if text in echoed:
                continue
            if level in ("ERROR", "CRITICAL"):
                if text not in errors:
                    errors.append(text)
                continue
            # The indicator count is logged before any check runs, so the first one is MVT's; later text could be data from the phone
            lm = LOADED_RE.match(text) if level == "INFO" and loaded is None else None
            if lm:
                loaded = int(lm.group(1))
            elif incomplete is None and level in ("INFO", "WARNING") and "missing from the backup folder" in text:
                incomplete = text
            elif outdated is None and level == "WARNING" and "outdated iOS version" in text:
                outdated = text
        for text in errors[:LIST_CAP]:
            add("UNKNOWN", "MVT logged an error, so part of the check did not run: %s" % mask(text, 160))
        if len(errors) > LIST_CAP:
            more = len(errors) - LIST_CAP
            add("UNKNOWN", "...and %d more MVT error%s (see command.log in the private folder)." % (
                more, plural(more, "", "s")), more)
        if not loaded:
            add("UNKNOWN", "MVT did not report loading any indicators, so nothing was checked against them.")
        if incomplete:
            add("UNKNOWN", "The backup may be incomplete, so part of it was not checked. MVT said: %s" % mask(incomplete, 160))
        if outdated:
            add("REVIEW", "MVT reports: %s. Update it under Settings > General > Software Update." % mask(outdated, 160))

    # This one is a conclusion, so it is sent apart as C: the caller shows it only after reading the whole answer
    if "UNKNOWN" not in found and "DETECTED" not in found and not any(a.get("matched_indicator") for a in alerts):
        emit("C", "INFO", "1", "No known indicators matched in the backup (checked against %d indicator entries). "
                               "This does not rule out spyware that is not in the public lists." % loaded)
    emit("END")


COMMANDS = {"devices": cmd_devices, "reason": cmd_reason, "info": cmd_info, "profiles": cmd_profiles, "apps": cmd_apps,
            "willencrypt": cmd_willencrypt, "backupstate": cmd_backupstate, "mvt": cmd_mvt}


def main():
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", errors="replace")   # app names often hold emoji
    fn = COMMANDS.get(sys.argv[1] if len(sys.argv) > 1 else "")
    if fn is None:
        sys.stderr.write("unknown helper command\n")
        sys.exit(2)
    fn(*sys.argv[2:])


main()
PYEOF

helper() {
    "$PY" -I -c "$PYHELPER" "$@"
}

# Run pymobiledevice3 with stdin closed so it can never swallow a prompt answer.
# stdout -> $TMP_DIR/out, stderr -> $TMP_DIR/err; the exit status is the tool's.
pmd() {
    "$PMD" "$@" </dev/null >"$TMP_DIR/out" 2>"$TMP_DIR/err"
}

# The useful part of a tool's error output, safe to print. $2, if given, is a password to hide wherever the tool printed it
# back; it reaches the helper through its environment, never on a command line.
reason_of() {
    local out kind text
    out="$(SECRET_TEXT="${2-}" "$PY" -I -c "$PYHELPER" reason < "$1" 2>/dev/null)" || out=""
    IFS='|' read -r kind text <<< "$out"
    if [[ "$kind" == "REASON" && -n "$text" ]]; then
        printf '%s' "$text"
    else
        printf '%s' "no details available"
    fi
}

# --- Banner ---
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}               IPHONE SECURITY SCANNER v1.0${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo -e "${YELLOW}This tool screens an iPhone plugged into this Mac with a USB cable:${NC}"
echo "  1. Quick checks - nothing is copied off the phone:"
echo "       configuration profiles, and apps that did not come from the App Store"
echo "  2. Optional deep scan - a full backup is checked against public"
echo "       spyware indicators (Amnesty International's MVT)"
echo "  3. A report you can share. The backup itself is never included."
echo ""
echo -e "${RED}Nothing is changed on the phone unless you run with APPLY=1 and confirm each item.${NC}"
echo -e "${RED}A computer cannot clean an iPhone like a Mac: there is no real-time protection,${NC}"
echo -e "${RED}and only apps and profiles can be removed. \"Nothing found\" means nothing KNOWN was found.${NC}"
echo ""
echo -e "${GRAY}Using:${NC}"
printf '  %-16s %s\n' "pymobiledevice3" "$PMD"
printf '  %-16s %s\n' "mvt-ios" "$MVT"
printf '  %-16s %s\n' "python" "$PY"
echo ""

# --- Get user name ---
echo -e "${CYAN}------------------------------------------------------------${NC}"
printf '%s' "Enter your name for the report (no spaces): "
IFS= read -r USER_NAME || true
echo ""

if [[ -z "$USER_NAME" ]]; then
    echo -e "${RED}Error: Name cannot be empty.${NC}"
    exit 1
fi
if [[ "$USER_NAME" =~ [[:space:]] ]]; then
    echo -e "${RED}Error: Name cannot contain spaces.${NC}"
    exit 1
fi
if [[ ! "$USER_NAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo -e "${RED}Error: Name can only contain letters, numbers, dots, dashes, underscores.${NC}"
    exit 1
fi

# --- Authorisation ---
echo -e "${YELLOW}Only continue if this is YOUR iPhone, or you have the owner's permission.${NC}"
if ! ask_yn "I confirm this is my iPhone or I have the owner's permission (y/n): "; then
    echo -e "${RED}Cancelled. No phone was contacted.${NC}"
    exit 1
fi
echo ""

# --- Define output paths ---
ZIP_NAME="${USER_NAME}.iPhone_Security_Check.zip"
ZIP_PATH="$HOME/Desktop/$ZIP_NAME"
REPORT_DIR="$HOME/Desktop/${USER_NAME}.iPhone_Security_Check"
REPORT_FILE="$REPORT_DIR/iphone_security_report.txt"

# A symlink here could send the report somewhere else, and something that is not a folder (or a
# file) cannot be used or replaced, so none of these are touched. Checked before the phone is contacted.
check_output_path() {
    local target="$1" shown="$2" kind="$3" plain=1
    if [[ -L "$target" ]]; then
        plain=0
    elif [[ -e "$target" ]]; then
        [[ "$kind" == "folder" && ! -d "$target" ]] && plain=0
        [[ "$kind" == "file" && ! -f "$target" ]] && plain=0
    fi
    if [[ "$plain" -eq 0 ]]; then
        echo -e "${RED}ERROR: ${shown} already exists and is not a normal ${kind}.${NC}"
        echo "       Move or rename it, then run this script again."
        exit 1
    fi
}
REPORT_SHOWN="~/Desktop/${USER_NAME}.iPhone_Security_Check"
check_output_path "$REPORT_DIR" "$REPORT_SHOWN" folder
check_output_path "$ZIP_PATH" "~/Desktop/${ZIP_NAME}" file
check_output_path "$REPORT_FILE" "${REPORT_SHOWN}/iphone_security_report.txt" file

echo -e "Folder: ${CYAN}~/Desktop/${USER_NAME}.iPhone_Security_Check/${NC}"
echo -e "   ZIP: ${CYAN}~/Desktop/${ZIP_NAME}${NC}"
if [[ -e "$ZIP_PATH" || -e "$REPORT_FILE" ]]; then
    say "$YELLOW" "Note: an earlier report with this name will be replaced."
fi
echo ""

# --- Temp folder for tool output (removed on exit) ---
TMP_BASE="${TMPDIR:-/tmp}"
TMP_DIR="$(mktemp -d "${TMP_BASE%/}/iphone_sec.XXXXXX")" || {
    echo "ERROR: Could not create a temporary folder."
    exit 1
}

# ============================================================================
# STEP 1: FIND THE PHONE  (usbmux list only reads the USB device list, it never pairs)
# ============================================================================
UDID=""
PHONE_NAME=""
PHONE_MODEL=""
PHONE_IOS=""
tries=0
while [[ -z "$UDID" ]]; do
    tries=$((tries + 1))
    echo -e "${CYAN}Looking for an iPhone on USB...${NC}"
    if ! pmd usbmux list --usb; then
        say "$RED" "ERROR: Could not look for connected phones: $(reason_of "$TMP_DIR/err")"
        exit 1
    fi
    DEV_OUT="$(helper devices < "$TMP_DIR/out")" || {
        say "$RED" "ERROR: Internal error while reading the list of connected phones."
        exit 1
    }

    DEV_LIST=""
    DEV_COUNT=0
    IGNORED=0
    PARSE_ERR=""
    while IFS='|' read -r kind f1 f2 f3 f4; do
        case "$kind" in
            DEV) DEV_LIST="${DEV_LIST}${f1}|${f2}|${f3}|${f4}"$'\n'; DEV_COUNT=$((DEV_COUNT + 1)) ;;
            IGN) IGNORED="$f1" ;;
            ERR) PARSE_ERR="$f1" ;;
        esac
    done <<< "$DEV_OUT"

    if [[ -n "$PARSE_ERR" ]]; then
        say "$RED" "ERROR: Could not read the list of connected phones ($PARSE_ERR)."
        exit 1
    fi
    if [[ "$IGNORED" -gt 0 ]]; then
        say "$YELLOW" "Ignored $IGNORED device(s) with an unexpected ID."
    fi

    if [[ "$DEV_COUNT" -eq 0 ]]; then
        say "$RED" "No iPhone found."
        echo "  - Plug the iPhone into this Mac with a cable (try another cable or port)."
        echo "  - Unlock the iPhone. If it asks \"Trust This Computer?\", tap Trust."
        if [[ "$tries" -ge 3 ]]; then
            say "$RED" "Giving up after $tries tries."
            exit 1
        fi
        printf '%s' "Press Enter to look again, or type q to quit: "
        reply=""
        if ! IFS= read -r reply || [[ "$reply" == "q" || "$reply" == "Q" ]]; then
            echo ""
            say "$RED" "Cancelled. No phone was contacted."
            exit 1
        fi
        continue
    fi

    if [[ "$DEV_COUNT" -eq 1 ]]; then
        IFS='|' read -r UDID PHONE_NAME PHONE_MODEL PHONE_IOS <<< "$DEV_LIST"
        printf '%bFound:%b %s (%s, iOS %s)\n' "$GREEN" "$NC" "$PHONE_NAME" "$PHONE_MODEL" "$PHONE_IOS"
        break
    fi

    echo "Several phones are connected:"
    n=0
    while IFS='|' read -r u nm md iv; do
        [[ -z "$u" ]] && continue
        n=$((n + 1))
        printf '  %d) %s (%s, iOS %s, ID ...%s)\n' "$n" "$nm" "$md" "$iv" "${u: -4}"
    done <<< "$DEV_LIST"
    choice=""
    for attempt in 1 2 3; do
        printf 'Which one should be checked? [1-%d]: ' "$DEV_COUNT"
        reply=""
        if ! IFS= read -r reply; then
            echo ""
            break
        fi
        if [[ "$reply" =~ ^[0-9]{1,3}$ ]] && (( 10#$reply >= 1 && 10#$reply <= DEV_COUNT )); then
            choice=$((10#$reply))
            break
        fi
        echo "Please type a number from 1 to $DEV_COUNT."
    done
    if [[ -z "$choice" ]]; then
        say "$RED" "No valid choice made. Nothing was checked."
        exit 1
    fi
    n=0
    while IFS='|' read -r u nm md iv; do
        [[ -z "$u" ]] && continue
        n=$((n + 1))
        if [[ "$n" -eq "$choice" ]]; then
            UDID="$u"; PHONE_NAME="$nm"; PHONE_MODEL="$md"; PHONE_IOS="$iv"
        fi
    done <<< "$DEV_LIST"
    printf '%bSelected:%b %s (%s, iOS %s)\n' "$GREEN" "$NC" "$PHONE_NAME" "$PHONE_MODEL" "$PHONE_IOS"
done

# Belt and braces: the ID is about to be used on command lines
if [[ ! "$UDID" =~ ^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40})$ ]]; then
    say "$RED" "ERROR: The phone reported an unexpected ID. Nothing was checked."
    exit 1
fi

# Tell the user what the phone will ask BEFORE the first command that can pair with it
echo ""
echo -e "${YELLOW}Before the first check, on the iPhone:${NC}"
echo "  1. Unlock it and keep the screen on."
echo "  2. If it asks \"Trust This Computer?\", tap Trust and enter the phone's passcode."
echo "     (Without this the phone refuses to answer anything.)"
printf '%s' "Press Enter once the iPhone is unlocked and has trusted this Mac: "
IFS= read -r _ || echo ""
echo ""

# ============================================================================
# STEP 2: QUICK CHECKS  (read-only: nothing is copied off the phone)
# ============================================================================
FINDINGS="$TMP_DIR/findings.txt"
: > "$FINDINGS"
N_DETECTED=0
N_REVIEW=0
N_INFO=0
N_UNKNOWN=0
MAX_LISTED=25   # longest list of flagged apps/profiles shown; the rest are counted
FIX_ITEMS=""    # one "P|id|name" or "A|id|name" line per listed item that can be removed from here
N_FIX_PROFS=0
N_FIX_APPS=0

# Record one finding: shown now and kept for the report. TEXT is printed literally.
# The optional third argument is how many items the line stands for (default 1).
finding() {
    local tag="$1" text="$2" weight="${3:-1}" colour="$NC"
    case "$tag" in
        DETECTED) colour="$RED";    N_DETECTED=$((N_DETECTED + weight)) ;;
        REVIEW)   colour="$YELLOW"; N_REVIEW=$((N_REVIEW + weight)) ;;
        INFO)     colour="$CYAN";   N_INFO=$((N_INFO + weight)) ;;
        UNKNOWN)  colour="$PURPLE"; N_UNKNOWN=$((N_UNKNOWN + weight)) ;;
    esac
    printf '%b[%s]%b %s\n' "$colour" "$tag" "$NC" "$text"
    printf '[%s] %s\n' "$tag" "$text" >> "$FINDINGS"
}

plural() {
    if [[ "$1" -eq 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi
}

echo -e "${CYAN}Running the quick checks...${NC}"

# Phone details. This is also the first command that needs the phone to trust this Mac.
LOCK_PROBLEM=""
PHONE_BUILD=""
if ! pmd lockdown info --udid "$UDID"; then
    LOCK_PROBLEM="The iPhone did not answer: $(reason_of "$TMP_DIR/err")"
else
    INFO_OUT="$(helper info < "$TMP_DIR/out" 2>/dev/null)" || INFO_OUT=""
    IFS='|' read -r kind f1 f2 f3 f4 <<< "$INFO_OUT"
    if [[ "$kind" == "PHONE" ]]; then
        [[ -n "$f1" ]] && PHONE_NAME="$f1"
        [[ -n "$f2" ]] && PHONE_MODEL="$f2"
        [[ -n "$f3" ]] && PHONE_IOS="$f3"
        PHONE_BUILD="$f4"
    else
        LOCK_PROBLEM="The iPhone's answer could not be read${f1:+ ($f1)}."
    fi
fi
if [[ -n "$LOCK_PROBLEM" ]]; then
    say "$RED" "ERROR: $LOCK_PROBLEM"
    echo "  - Unlock the iPhone and keep the screen on."
    echo "  - If it asks \"Trust This Computer?\", tap Trust and enter the phone's passcode."
    echo "  - Then run this script again."
    exit 1
fi
printf '  %bPhone:%b %s - %s - iOS %s%s\n' "$GRAY" "$NC" "$PHONE_NAME" "$PHONE_MODEL" "$PHONE_IOS" "${PHONE_BUILD:+ ($PHONE_BUILD)}"
echo ""

# Configuration profiles: they can route the phone's traffic or put it under someone's management
if pmd profile list --udid "$UDID"; then
    PROF_OUT="$(helper profiles < "$TMP_DIR/out" 2>/dev/null)" || PROF_OUT=""
else
    PROF_OUT="ERR|$(reason_of "$TMP_DIR/err")"
fi
PROF_STATE=""
PROF_WHY=""
PROF_TOTAL=0
PROF_SHOWN=0
while IFS='|' read -r kind f1 f2 f3 f4; do
    case "$kind" in
        PROF)
            PROF_STATE="LIST"
            PROF_TOTAL=$((PROF_TOTAL + 1))
            if [[ "$PROF_SHOWN" -lt "$MAX_LISTED" ]]; then
                PROF_SHOWN=$((PROF_SHOWN + 1))
                finding REVIEW "Configuration profile \"$f2\" from $f3 ($f1) - check that you recognise it."
                if [[ "$f4" == "1" ]]; then
                    FIX_ITEMS="${FIX_ITEMS}P|$f1|$f2"$'\n'
                    N_FIX_PROFS=$((N_FIX_PROFS + 1))
                fi
            fi ;;
        NONE) PROF_STATE="NONE" ;;
        ERR)  PROF_STATE="ERR"; PROF_WHY="$f1" ;;
    esac
done <<< "$PROF_OUT"
case "$PROF_STATE" in
    NONE) finding INFO "No configuration profiles are installed." ;;
    LIST)
        if [[ "$PROF_TOTAL" -gt "$PROF_SHOWN" ]]; then
            more=$((PROF_TOTAL - PROF_SHOWN))
            finding REVIEW "...and $more more configuration $(plural "$more" profile profiles) (not listed here)." "$more"
        fi ;;
    *) finding UNKNOWN "Configuration profiles could not be checked (${PROF_WHY:-the answer could not be processed})." ;;
esac

# Apps you installed: anything not signed by the App Store was sideloaded or comes from a company/developer
if pmd apps list --type Any --udid "$UDID"; then
    APPS_OUT="$(helper apps < "$TMP_DIR/out" 2>/dev/null)" || APPS_OUT=""
else
    APPS_OUT="ERR|$(reason_of "$TMP_DIR/err")"
fi
APP_STATE=""
APP_WHY=""
APP_TOTAL=0
APP_SHOWN=0
USER_APPS=0
STORE_APPS=0
UNSIGNED_APPS=0
while IFS='|' read -r kind f1 f2 f3 f4; do
    case "$kind" in
        APP)
            APP_TOTAL=$((APP_TOTAL + 1))
            if [[ "$APP_SHOWN" -lt "$MAX_LISTED" ]]; then
                APP_SHOWN=$((APP_SHOWN + 1))
                finding REVIEW "App \"$f2\" ($f1) is signed by \"$f3\", not by the App Store - check that you recognise it."
                if [[ "$f4" == "1" ]]; then
                    FIX_ITEMS="${FIX_ITEMS}A|$f1|$f2"$'\n'
                    N_FIX_APPS=$((N_FIX_APPS + 1))
                fi
            fi ;;
        CNT)
            if [[ "$f1" =~ ^[0-9]+$ && "$f2" =~ ^[0-9]+$ && "$f3" =~ ^[0-9]+$ ]]; then
                USER_APPS=$((10#$f1)); STORE_APPS=$((10#$f2)); UNSIGNED_APPS=$((10#$f3))
                APP_STATE="OK"
            fi ;;
        ERR) APP_STATE="ERR"; APP_WHY="$f1" ;;
    esac
done <<< "$APPS_OUT"
if [[ "$APP_STATE" != "OK" ]]; then
    finding UNKNOWN "Apps could not be checked (${APP_WHY:-the answer could not be processed})."
else
    if [[ "$APP_TOTAL" -gt "$APP_SHOWN" ]]; then
        more=$((APP_TOTAL - APP_SHOWN))
        finding REVIEW "...and $more more $(plural "$more" app apps) not signed by the App Store (not listed here)." "$more"
    fi
    if [[ "$USER_APPS" -eq 0 ]]; then
        finding INFO "There are no apps installed by you (only Apple's own apps)."
    else
        if [[ "$UNSIGNED_APPS" -eq "$USER_APPS" ]]; then
            finding UNKNOWN "The phone did not say who signed any of the $USER_APPS $(plural "$USER_APPS" app apps) you installed, so $(plural "$USER_APPS" it they) could not be checked."
        elif [[ "$UNSIGNED_APPS" -gt 0 ]]; then
            finding UNKNOWN "$UNSIGNED_APPS of the $USER_APPS apps you installed did not say who signed $(plural "$UNSIGNED_APPS" it them), so $(plural "$UNSIGNED_APPS" it those) could not be checked."
        fi
        if [[ "$STORE_APPS" -eq "$USER_APPS" && "$USER_APPS" -eq 1 ]]; then
            finding INFO "App Store signature present on the only app you installed."
        elif [[ "$STORE_APPS" -eq "$USER_APPS" ]]; then
            finding INFO "App Store signature present on all $USER_APPS apps you installed."
        elif [[ "$STORE_APPS" -gt 0 ]]; then
            finding INFO "App Store signature present on $STORE_APPS of the $USER_APPS apps you installed."
        fi
    fi
fi

# ============================================================================
# STEP 3: DEEP SCAN  (optional: a full backup, checked against public spyware indicators)
# ============================================================================
ACTIONS="$TMP_DIR/actions.txt"
: > "$ACTIONS"

record_action() {
    printf '%s\n' "$1" >> "$ACTIONS"
}

# Make this run's private folder under WORK_ROOT (never through a link, never over a file).
# Sets WORK_DIR; on failure WORK_WHY says why. Not called through $(...), so WORK_DIR survives.
WORK_WHY=""
make_work_dir() {
    local made=""
    WORK_WHY=""
    if [[ -L "$WORK_ROOT" || ( -e "$WORK_ROOT" && ! -d "$WORK_ROOT" ) ]]; then
        WORK_WHY="$(tilde_path "$WORK_ROOT") is a link or not a folder"
        return 1
    fi
    if ! mkdir -p "$WORK_ROOT" 2>/dev/null; then
        WORK_WHY="$(tilde_path "$WORK_ROOT") could not be created"
        return 1
    fi
    if ! made="$(mktemp -d "$WORK_ROOT/iphone_$(date +%Y%m%d_%H%M%S).XXXXXX" 2>/dev/null)" || [[ ! -d "$made" ]]; then
        WORK_WHY="a folder could not be made in $(tilde_path "$WORK_ROOT")"
        return 1
    fi
    WORK_DIR="$made"
    WORK_DIR_MADE=1
    return 0
}

# Ask the phone whether its backups are encrypted. Sets ENC_NOW to 1 or 0, or to "" with ENC_WHY saying why not.
ENC_NOW=""
ENC_WHY=""
will_encrypt() {
    local out="" kind="" f1=""
    ENC_NOW=""
    ENC_WHY=""
    if ! pmd lockdown get --udid "$UDID" com.apple.mobile.backup WillEncrypt; then
        ENC_WHY="$(reason_of "$TMP_DIR/err")"
        return 0
    fi
    out="$(helper willencrypt < "$TMP_DIR/out" 2>/dev/null)" || out=""
    IFS='|' read -r kind f1 <<< "$out"
    case "$kind" in
        ENC)
            if [[ "$f1" == "1" || "$f1" == "0" ]]; then ENC_NOW="$f1"; else ENC_WHY="its answer could not be read"; fi ;;
        ERR) ENC_WHY="$f1" ;;
        *)   ENC_WHY="its answer could not be read" ;;
    esac
    return 0
}

deep_scan() {
    local ioc_dir="${MVT_DATA_FOLDER:-$HOME/Library/Application Support/mvt}/indicators"
    local ioc_failed=0 ioc_why="" have_iocs=0 f="" why="" tries=0 pw1="" fail_why=""
    local state_out="" kind="" f1="" f2="" attempt=1 opened=0 backup_ok=0 enc_status=0
    local mvt_target="" mvt_status=0 mvt_out="" got_end=0 bad_line=0 tag="" weight="" text="" conclusion=""

    echo ""
    echo -e "${YELLOW}Deep scan (optional):${NC}"
    echo "  A full backup of the iPhone is made into a private folder on this Mac (it is not"
    echo "  part of the report ZIP) and checked against public spyware indicator lists"
    echo "  (Amnesty International's MVT)."
    echo "  - It can take a long time and needs free space about the size of the phone's data."
    echo "  - Keep the iPhone unlocked and plugged in, and watch it for prompts."
    echo "  - The indicator lists are downloaded from the internet. Nothing from the phone is sent."
    echo "  - A backup holds more when it is encrypted. That sets a backup password on the phone,"
    echo "    which stays until you turn it off. You will be asked first."
    if ! ask_yn "Run the deep scan? (y/n): "; then
        finding INFO "The deep scan was not run, so the phone's data was not checked against spyware indicators."
        return 0
    fi

    # The indicator lists. download-iocs exits 0 even when the download failed, so its text is checked too.
    echo ""
    echo -e "${CYAN}Downloading the public spyware indicator lists...${NC}"
    if ! "$MVT" --disable-update-check download-iocs </dev/null >"$TMP_DIR/mvt.log" 2>&1; then
        ioc_failed=1
    elif grep -Eq '^(ERROR|CRITICAL)[[:space:]]' "$TMP_DIR/mvt.log"; then
        ioc_failed=1
    fi
    for f in "$ioc_dir"/*.stix2; do
        [[ -f "$f" ]] && have_iocs=1
    done
    if [[ "$ioc_failed" -eq 1 ]]; then
        ioc_why="$(reason_of "$TMP_DIR/mvt.log")"
    else
        ioc_why="no indicator files were found"
    fi
    if [[ "$have_iocs" -eq 0 ]]; then
        finding UNKNOWN "The deep scan could not run: the spyware indicator lists could not be downloaded ($ioc_why). Nothing was changed on the phone."
        return 0
    fi
    if [[ "$ioc_failed" -eq 1 ]]; then
        finding INFO "The indicator lists could not be updated, so the copy already on this Mac is used (it may be out of date)."
    fi

    will_encrypt
    if [[ -z "$ENC_NOW" ]]; then
        finding UNKNOWN "The deep scan could not run: the phone did not say whether its backups are encrypted ($ENC_WHY). Nothing was changed on the phone."
        return 0
    fi

    BACKUP_PW=""
    if [[ "$ENC_NOW" == "0" ]]; then
        echo ""
        echo -e "${YELLOW}Backup encryption:${NC}"
        echo "  The phone's backups are not encrypted. An encrypted backup also holds saved passwords,"
        echo "  Wi-Fi settings, website history, Health data and call history, so more can be checked."
        echo "  Turning it on sets a backup password on the phone. It stays until you turn it off"
        echo "  (in Finder, untick \"Encrypt local backup\")."
        echo "  You need this password to use the backup. Write it down."
        echo "  Other programs on this Mac can briefly see the password while the command that sets it runs."
        if ask_yn "Turn on backup encryption? (y/n): "; then
            while [[ -z "$BACKUP_PW" && "$tries" -lt 3 ]]; do
                tries=$((tries + 1))
                ask_hidden "New backup password: "
                pw1="$HIDDEN_REPLY"
                if [[ -z "$pw1" ]]; then
                    echo "The password cannot be empty."
                    continue
                fi
                ask_hidden "Type it again: "
                if [[ "$HIDDEN_REPLY" != "$pw1" ]]; then
                    echo "The two passwords did not match. Try again."
                    continue
                fi
                BACKUP_PW="$pw1"
            done
            pw1=""
            HIDDEN_REPLY=""
            if [[ -z "$BACKUP_PW" ]]; then
                finding UNKNOWN "The deep scan could not run: no backup password was set. Nothing was changed on the phone."
                return 0
            fi
            if ! make_work_dir; then
                BACKUP_PW=""
                finding UNKNOWN "The deep scan could not run: the private folder for the backup could not be made ($WORK_WHY). Nothing was changed on the phone."
                return 0
            fi
            # The password is on this one command line, so other programs on this Mac can see it while it runs
            ENC_PENDING=1
            pmd backup2 encryption --udid "$UDID" -b "$WORK_DIR" -- on "$BACKUP_PW"
            enc_status=$?
            [[ "$enc_status" -eq 0 ]] && will_encrypt
            ENC_PENDING=0
            if [[ "$enc_status" -ne 0 ]]; then
                fail_why="$(reason_of "$TMP_DIR/err" "$BACKUP_PW")"
                BACKUP_PW=""
                record_action "Tried to turn on backup encryption on the phone; it failed, so the phone's setting may or may not have changed."
                drop_work_dir
                finding UNKNOWN "The deep scan could not run: turning backup encryption on failed ($fail_why). Check the phone's backup setting in Finder: it may have changed. No backup was made."
                return 0
            fi
            if [[ "$ENC_NOW" != "1" ]]; then
                BACKUP_PW=""
                record_action "Tried to turn on backup encryption on the phone; the phone did not confirm it, so its setting may or may not have changed. Check it in Finder."
                drop_work_dir
                finding UNKNOWN "The deep scan could not run: the phone did not confirm that backup encryption is on."
                return 0
            fi
            echo -e "${GREEN}Backup encryption is now on.${NC}"
            record_action "Turned on backup encryption on the phone (a backup password you chose; it stays until you turn it off)."
        fi
    else
        echo ""
        echo "The phone's backups are already encrypted, so the backup password is needed."
        echo "If you do not remember it: Settings > General > Transfer or Reset iPhone > Reset > Reset All Settings."
        echo "That keeps your data and passwords, resets settings such as display brightness, Home Screen layout"
        echo "and wallpaper, and removes the backup password (Apple support article 108313)."
        ask_hidden "Backup password (press Enter to stop): "
        BACKUP_PW="$HIDDEN_REPLY"
        HIDDEN_REPLY=""
        if [[ -z "$BACKUP_PW" ]]; then
            finding UNKNOWN "The deep scan could not run: no backup password was given. Nothing was changed on the phone."
            return 0
        fi
    fi

    if [[ "$WORK_DIR_MADE" -eq 0 ]] && ! make_work_dir; then
        BACKUP_PW=""
        finding UNKNOWN "The deep scan could not run: the private folder for the backup could not be made ($WORK_WHY). Nothing was changed on the phone."
        return 0
    fi

    echo ""
    echo -e "${CYAN}Making the backup. This can take a long time; keep the iPhone unlocked and plugged in...${NC}"
    BACKUP_STARTED=1
    if "$PMD" backup2 backup --udid "$UDID" "$WORK_DIR/backup" </dev/null; then
        [[ -s "$WORK_DIR/backup/$UDID/Manifest.db" && -s "$WORK_DIR/backup/$UDID/Manifest.plist" ]] && backup_ok=1
    fi
    if [[ "$backup_ok" -eq 0 ]]; then
        BACKUP_PW=""
        record_action "Started a backup of the phone into a private folder on this Mac; it did not finish."
        finding UNKNOWN "The backup did not finish (see the messages above), so the deep scan could not check the phone. The partial backup is in the private folder: $(tilde_path "$WORK_DIR")"
        return 0
    fi
    record_action "Made a backup of the phone into a private folder on this Mac (not part of the ZIP)."

    # What the backup says about itself decides whether it has to be opened with the password first
    state_out="$(helper backupstate "$WORK_DIR/backup/$UDID/Manifest.plist" 2>/dev/null)" || state_out=""
    IFS='|' read -r kind f1 f2 <<< "$state_out"
    case "$kind" in
        STATE) why=""; [[ "$f1" == "?" ]] && why="it did not say whether it is encrypted" ;;
        ERR)   why="$f1" ;;
        *)     why="its answer could not be read" ;;
    esac
    if [[ -n "$why" ]]; then
        BACKUP_PW=""
        finding UNKNOWN "The deep scan could not check the backup: its state could not be read ($why)."
        return 0
    fi
    case "$f2" in
        1) PASSCODE_KNOWN=1; finding INFO "The backup says a passcode is set on the iPhone (from the backup)." ;;
        0) PASSCODE_KNOWN=1; finding REVIEW "The backup says no passcode is set on the iPhone (from the backup). Set one under Settings > Face ID & Passcode." ;;
        *) finding UNKNOWN "The backup did not say whether a passcode is set (from the backup)." ;;
    esac

    mvt_target="$WORK_DIR/backup/$UDID"
    if [[ "$f1" == "1" ]]; then
        # Up to 3 passwords in all. The password goes to MVT through its environment, never on a command line.
        while [[ "$attempt" -le 3 ]]; do
            if [[ -z "$BACKUP_PW" ]]; then
                ask_hidden "Backup password (press Enter to stop): "
                BACKUP_PW="$HIDDEN_REPLY"
                HIDDEN_REPLY=""
                [[ -z "$BACKUP_PW" ]] && break
            fi
            if MVT_IOS_BACKUP_PASSWORD="$BACKUP_PW" "$MVT" --disable-update-check decrypt-backup -d "$WORK_DIR/decrypted" "$WORK_DIR/backup/$UDID" </dev/null >"$TMP_DIR/mvt.log" 2>&1 \
                && [[ -s "$WORK_DIR/decrypted/Manifest.db" ]]; then
                opened=1
                break
            fi
            say "$YELLOW" "That password did not open the backup."
            why="$(reason_of "$TMP_DIR/mvt.log" "$BACKUP_PW")"
            say "$GRAY" "  MVT said: $why"
            drop_decrypted
            BACKUP_PW=""
            attempt=$((attempt + 1))
        done
        BACKUP_PW=""
        if [[ "$opened" -eq 0 ]]; then
            finding UNKNOWN "The deep scan could not check the backup: it could not be opened with the password(s) given."
            return 0
        fi
        mvt_target="$WORK_DIR/decrypted"
    else
        BACKUP_PW=""
        finding INFO "The backup was not encrypted, so it may be missing data that only encrypted backups hold (saved passwords, Wi-Fi settings, website history, Health data, call history), and that data was not checked."
    fi

    echo ""
    echo -e "${CYAN}Checking the backup against the indicator lists (this can take several minutes)...${NC}"
    mkdir -p "$WORK_DIR/mvt_results"
    "$MVT" --disable-update-check --disable-indicator-update-check check-backup -o "$WORK_DIR/mvt_results" "$mvt_target" </dev/null >"$WORK_DIR/mvt_console.txt" 2>&1
    mvt_status=$?
    drop_decrypted

    # An answer that stops part way (no END line) is shown as far as it got, and then said to be incomplete
    mvt_out="$(helper mvt "$WORK_DIR/mvt_results" "$WORK_DIR/mvt_console.txt" "$mvt_status" 2>/dev/null)" || true
    while IFS='|' read -r kind tag weight text; do
        case "$kind" in
            F)
                case "$tag" in
                    DETECTED|REVIEW|INFO|UNKNOWN) ;;
                    *) bad_line=1; continue ;;
                esac
                [[ "$weight" =~ ^[0-9]+$ ]] || weight=1
                finding "$tag" "$text" "$((10#$weight))" ;;
            C) conclusion="$text" ;;
            END) got_end=1 ;;
        esac
    done <<< "$mvt_out"
    if [[ "$got_end" -eq 0 || "$bad_line" -eq 1 ]]; then
        finding UNKNOWN "MVT finished, but its results could not be read, so the backup was not fully checked."
    elif [[ -n "$conclusion" ]]; then
        finding INFO "$conclusion"
    fi
    return 0
}

deep_scan

# ============================================================================
# FIXES  (only with APPLY=1, and only for an item you answer y to)
# ============================================================================
HAND_APP="press and hold the app's icon, then tap Remove App."
HAND_PROFILE="Settings > General > VPN & Device Management, tap the profile, then Remove Profile."

# How to remove an item yourself. $1 is the kind (P or A), $2 what to say first.
hand_hint() {
    if [[ "$1" == "P" ]]; then
        echo "  $2 $HAND_PROFILE"
    else
        echo "  $2 $HAND_APP"
    fi
}

# After a removal, ask the phone for its list again. Prints 1 (still there), 0 (gone) or ? (the answer could
# not be read). Only this answer decides what is reported, never the removal command's own exit status.
still_installed() {
    local kind="$1" id="$2" out="" tag="" val="" seen="?"
    if [[ "$kind" == "P" ]]; then
        pmd profile list --udid "$UDID" || { echo "?"; return; }
        out="$(helper profiles "$id" < "$TMP_DIR/out" 2>/dev/null)" || out=""
    else
        pmd apps list --type Any --udid "$UDID" || { echo "?"; return; }
        out="$(helper apps "$id" < "$TMP_DIR/out" 2>/dev/null)" || out=""
    fi
    while IFS='|' read -r tag val; do
        if [[ "$tag" == "SEEN" && "$val" =~ ^[01]$ ]]; then seen="$val"; fi
    done <<< "$out"
    echo "$seen"
}

# Remove one item that was said y to, then report only what the phone's own list shows afterwards
remove_item() {
    local kind="$1" id="$2" name="$3" what why="" note=""
    if [[ "$kind" == "P" ]]; then
        what="configuration profile"
        echo "  If the phone asks for its passcode, enter it on the phone."
        pmd profile remove --udid "$UDID" "$id" || why="$(reason_of "$TMP_DIR/err")"
    else
        what="app"
        pmd apps uninstall --udid "$UDID" "$id" || why="$(reason_of "$TMP_DIR/err")"
    fi
    [[ -n "$why" ]] && note=" (the removal command said: $why)"
    case "$(still_installed "$kind" "$id")" in
        0)
            say "$GREEN" "Removed: $what \"$name\" ($id)."
            record_action "Removed $what \"$name\" ($id): confirmed gone from the phone's list." ;;
        1)
            say "$RED" "Still present: $what \"$name\" ($id) is still on the phone$note."
            record_action "Tried to remove $what \"$name\" ($id): it is still on the phone."
            hand_hint "$kind" "Remove it yourself:" ;;
        *)
            say "$PURPLE" "Could not confirm: $what \"$name\" ($id) - the phone's list could not be read afterwards$note."
            record_action "Tried to remove $what \"$name\" ($id): could not confirm whether it is gone."
            hand_hint "$kind" "Check the phone; if it is still there, remove it yourself:" ;;
    esac
}

# Items that are not offered (an ID that is not plain, or beyond the lists shown) are counted for you to remove by hand
N_FIX=$((N_FIX_PROFS + N_FIX_APPS))
N_HAND_PROFS=$((PROF_TOTAL - N_FIX_PROFS))
N_HAND_APPS=$((APP_TOTAL - N_FIX_APPS))
if [[ "$N_FIX" -gt 0 || "$N_HAND_PROFS" -gt 0 || "$N_HAND_APPS" -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}Fixes:${NC}"
    if [[ "$N_DETECTED" -gt 0 ]]; then
        echo "  Fixes are switched off because something known to be linked to spyware was found: removing apps or profiles can destroy the evidence an expert needs. Talk to an expert first."
        # Nothing is offered, and nothing is listed to remove by hand either
        N_FIX=0
        N_HAND_PROFS=0
        N_HAND_APPS=0
    fi
    if [[ "$N_HAND_PROFS" -gt 0 ]]; then
        echo "  $N_HAND_PROFS flagged configuration $(plural "$N_HAND_PROFS" profile profiles) cannot be removed from here. Remove $(plural "$N_HAND_PROFS" it them) yourself: $HAND_PROFILE"
    fi
    if [[ "$N_HAND_APPS" -gt 0 ]]; then
        echo "  $N_HAND_APPS flagged $(plural "$N_HAND_APPS" app apps) cannot be removed from here. Remove $(plural "$N_HAND_APPS" it them) yourself: $HAND_APP"
    fi
    if [[ "$N_FIX" -gt 0 && "$APPLY" != "1" ]]; then
        echo "  $N_FIX flagged $(plural "$N_FIX" item items) can be removed from here."
        echo "  To be asked about removing each one, run this script again as:  APPLY=1 ./iphone_sec.sh"
    elif [[ "$N_FIX" -gt 0 ]]; then
        echo "  Only the items listed above are offered. Nothing is removed unless you answer y."
        # The list comes in on fd 3: ask_yn reads its answer from the keyboard
        while IFS='|' read -r -u 3 kind f1 f2; do
            case "$kind" in
                P) what="configuration profile"; effect="Settings it applied stop working." ;;
                A) what="app"; effect="Its data on the phone is deleted." ;;
                *) continue ;;
            esac
            if ask_yn "Remove the $what \"$f2\" ($f1) from the phone? $effect (y/n): "; then
                remove_item "$kind" "$f1" "$f2"
            else
                echo "Kept: $what \"$f2\" ($f1) was not removed."
            fi
        done 3<<< "$FIX_ITEMS"
        if [[ -s "$ACTIONS" ]]; then
            echo "  The summary below shows the phone as it was when scanned, before these changes."
        fi
    fi
fi

# ============================================================================
# SUMMARY AND REPORT
# ============================================================================
# The sentence under the counts only ever describes what was checked, never the phone as a whole.
verdict() {
    if [[ "$N_DETECTED" -gt 0 ]]; then
        echo "Something known to be linked to spyware was found: do not wipe or remove anything yet, and talk to an expert."
    elif [[ "$N_REVIEW" -gt 0 || "$N_UNKNOWN" -gt 0 ]]; then
        echo "Some items need a look: check each [REVIEW] item, and do not treat an [UNKNOWN] item as passed."
    else
        echo "No known problem was found by the checks that ran."
    fi
}

# $1/$2 are the colour on/off codes (empty for the report file)
print_summary() {
    printf '%bSummary:%b %d DETECTED, %d REVIEW, %d INFO, %d UNKNOWN\n' "$1" "$2" "$N_DETECTED" "$N_REVIEW" "$N_INFO" "$N_UNKNOWN"
    verdict
    if [[ "$N_DETECTED" -gt 0 ]]; then
        echo ""
        printf '%bWhat to do first:%b\n' "$1" "$2"
        echo "  Do not wipe, reset or delete anything on the phone yet: that can destroy evidence an expert needs."
        echo "  Amnesty International's Security Lab helps human rights defenders and civil society, as MVT does: https://securitylab.amnesty.org/get-help/?c=mvt"
        echo "  Contact them from another device, not from this iPhone, and do not email the backup to anyone: it holds all of the phone's data."
    fi
}

# Shown on screen and written to the report, so the two can never disagree
print_limits() {
    echo "  \"Nothing found\" means nothing KNOWN was found. New or targeted spyware may not be in any public indicator list."
    echo "  iCloud / Apple ID account compromise, malicious iCloud backups, phishing and SIM swap are not visible from a USB connection."
    echo "  Android phones are not covered. A computer cannot clean an iPhone like a Mac: there is no real-time protection, and only apps and profiles can be removed."
    echo "  Jailbreak status cannot be reliably detected over USB."
}

# Things only the phone's owner can check; the lines under item 5 and the last item depend on what was found
print_checklist() {
    echo "  1. Passcode: Settings > Face ID & Passcode. Use 6 or more digits, or a password."
    echo "     Set \"Require Passcode\" to Immediately."
    echo "  2. iOS update: Settings > General > Software Update. Install the newest iOS and turn on Automatic Updates."
    echo "     Updates fix the security holes that spyware uses."
    echo "  3. Apple Account: Settings > tap your name, then scroll down to the list of devices."
    echo "     Remove any device you do not recognise, and change the password if you find one."
    echo "  4. Find My: Settings > tap your name > Find My > Find My iPhone. It should be On."
    echo "     It is how you locate or lock the phone if it is lost or stolen."
    echo "  5. VPN & Device Management: Settings > General > VPN & Device Management."
    echo "     Remove anything listed there that you, your employer or your school did not install."
    if [[ "$PROF_TOTAL" -gt 0 ]]; then
        echo "     This scan found $PROF_TOTAL $(plural "$PROF_TOTAL" "configuration profile" "configuration profiles")."
    fi
    if [[ "$APP_TOTAL" -gt 0 ]]; then
        echo "     This scan found $APP_TOTAL $(plural "$APP_TOTAL" app apps) not signed by the App Store."
    fi
    echo "  6. App permissions: Settings > Privacy & Security. Open Location Services, Microphone and Camera"
    echo "     and switch off access for apps that do not need it. \"Safety Check\" on the same screen reviews who can see your data."
    echo "  7. Messages: Settings > Messages > Text Message Forwarding: switch off any device you do not recognise."
    echo "     Settings > Phone > Call Forwarding should be Off unless you turned it on yourself."
    echo "  8. Lockdown Mode (for people at higher risk): Settings > Privacy & Security > Lockdown Mode."
    echo "     It blocks many attack routes at the cost of some features. Worth considering for journalists, activists and other likely targets."
    if [[ "$N_UNKNOWN" -gt 0 ]]; then
        echo "  9. Run this scan again:"
        echo "     $N_UNKNOWN $(plural "$N_UNKNOWN" check checks) could not finish (marked [UNKNOWN] above). Unlock the iPhone, keep the cable plugged in, and run the script again."
        echo "     Do not treat an [UNKNOWN] item as passed."
    fi
}

echo ""
print_summary "$CYAN" "$NC"
echo ""
# The backup of a deep scan says whether a passcode is set; without it this stays a check for you to do
if [[ "$PASSCODE_KNOWN" -eq 0 ]]; then
    echo -e "${YELLOW}Not checked by this script:${NC}"
    echo "  Passcode: not checked here (a computer cannot see whether one is set)."
    echo "  Use 6 or more digits, or a password, under Settings > Face ID & Passcode."
    echo ""
fi
echo -e "${YELLOW}What this scan cannot see:${NC}"
print_limits

REPORT_NAME="iphone_security_report.txt"
# Written in the private temp folder and moved into place once complete: a failed write never costs you an
# earlier report, and the report folder never holds a half-written file
REPORT_TMP="$TMP_DIR/$REPORT_NAME"

# The last command in the group is a plain echo, so its status tells whether the file could be written
write_report() {
    {
        echo "iPhone Security Report"
        echo "Prepared for: $USER_NAME"
        echo "Date: $(date)"
        echo "Phone: $PHONE_NAME - $PHONE_MODEL - iOS $PHONE_IOS${PHONE_BUILD:+ ($PHONE_BUILD)}"
        echo ""
        print_summary "" ""
        echo ""
        echo "FINDINGS"
        cat "$FINDINGS"
        echo ""
        echo "ACTIONS TAKEN"
        if [[ -s "$ACTIONS" ]]; then
            echo "The findings and counts above show the phone as it was when scanned, before these changes:"
            cat "$ACTIONS"
        else
            echo "None. Nothing was changed on the phone."
        fi
        if [[ "$BACKUP_STARTED" -eq 1 ]] && safe_work_dir; then
            echo ""
            echo "Private folder (backup and raw MVT results, not part of this ZIP): $(tilde_path "$WORK_DIR")"
        fi
        echo ""
        echo "WHAT THIS SCAN CANNOT SEE"
        print_limits
        echo ""
        echo "CHECK THESE YOURSELF (a computer cannot see these on an iPhone)"
        print_checklist
        echo ""
    } > "$REPORT_TMP"
}

if ! write_report; then
    echo -e "${RED}ERROR: Could not write the report.${NC}"
    exit 1
fi
if [[ ! -d "$REPORT_DIR" ]]; then
    mkdir -p "$REPORT_DIR" || {
        echo -e "${RED}ERROR: Could not create ${REPORT_SHOWN}${NC}"
        exit 1
    }
    REPORT_DIR_MADE=1
fi
if ! mv -f "$REPORT_TMP" "$REPORT_FILE"; then
    echo -e "${RED}ERROR: Could not write the report.${NC}"
    exit 1
fi

# Remove an existing ZIP of the same name first: zip would add to it instead of replacing it
rm -f "$ZIP_PATH"

# Create the ZIP containing only the report (flat, no directory nesting)
(cd "$REPORT_DIR" && zip -j "$ZIP_PATH" "$REPORT_NAME") > /dev/null 2>&1
ZIP_STATUS=$?

# Verify ZIP was created
if [[ "$ZIP_STATUS" -ne 0 || ! -f "$ZIP_PATH" ]]; then
    rm -f "$ZIP_PATH"
    echo -e "${RED}ERROR: Failed to create ZIP file.${NC}"
    echo "The report itself is at ${REPORT_SHOWN}/${REPORT_NAME}"
    exit 1
fi

ZIP_SIZE="$(size_of "$ZIP_PATH")"

# ============================================================================
# FINAL OUTPUT
# ============================================================================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}                    SCAN COMPLETE${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${CYAN}Folder:${NC} ~/Desktop/${USER_NAME}.iPhone_Security_Check/"
echo -e "${CYAN}   ZIP:${NC} ~/Desktop/${ZIP_NAME} (${ZIP_SIZE:-size unknown})"
echo ""
echo -e "${CYAN}Files included (1):${NC}"
echo "   1. ${REPORT_NAME}"
echo ""
echo -e "${CYAN}ZIP contents:${NC}"
unzip -l "$ZIP_PATH" 2>/dev/null | tail -n +4 | head -7
echo ""

# Ask about folder cleanup (the ZIP already holds the report). Only the report this script wrote is
# removed; the folder goes too only if that leaves it empty.
if ask_yn "Delete the folder and keep only the ZIP? (y/n): "; then
    rm -f "$REPORT_FILE"
    if rmdir "$REPORT_DIR" 2>/dev/null; then
        echo -e "${GREEN}Folder deleted. ZIP remains at ~/Desktop/${ZIP_NAME}${NC}"
    else
        echo -e "${YELLOW}Report removed from the folder, but the folder stays because it holds other files.${NC}"
        echo -e "${GREEN}ZIP remains at ~/Desktop/${ZIP_NAME}${NC}"
    fi
else
    echo -e "${GREEN}Both folder and ZIP kept on Desktop.${NC}"
fi
REPORT_DIR="" # nothing left for the cleanup trap to do

# The private folder holds all of the phone's data (the backup and MVT's raw results), so it stays unless you say y.
# It is removed only while it is still the very folder this script made.
if [[ "$BACKUP_STARTED" -eq 1 ]] && safe_work_dir; then
    PRIV_SIZE="$(size_of "$WORK_DIR")"
    echo ""
    echo -e "${CYAN}Private folder:${NC} $(tilde_path "$WORK_DIR") (${PRIV_SIZE:-size unknown})"
    echo "It holds the iPhone's data (the backup and MVT's raw results) and is not part of the ZIP."
    WORK_NOTE_SHOWN=1
    if [[ "$N_DETECTED" -gt 0 ]]; then
        PRIV_PROMPT="Delete the private folder anyway? An expert may need it as evidence. (y/n): "
    else
        PRIV_PROMPT="Delete the private folder (the backup and MVT's raw results)? (y/n): "
    fi
    if ask_yn "$PRIV_PROMPT"; then
        if ! safe_work_dir; then
            echo -e "${YELLOW}The private folder was not removed because it is not the folder this script made: $(tilde_path "$WORK_DIR")${NC}"
        elif rm -rf -- "$WORK_DIR" 2>/dev/null && [[ ! -e "$WORK_DIR" ]]; then
            echo -e "${GREEN}Private folder deleted.${NC}"
        else
            echo -e "${YELLOW}The private folder could not be fully removed: $(tilde_path "$WORK_DIR")${NC}"
        fi
    else
        echo -e "${GREEN}The private folder was kept: $(tilde_path "$WORK_DIR")${NC}"
    fi
fi

echo ""
echo -e "${YELLOW}Next steps:${NC}"
if [[ "$N_DETECTED" -gt 0 ]]; then
    echo "   FIRST: Something known to be linked to spyware was found. Read \"What to do first\" above, and do not wipe or remove anything yet."
fi
echo "   1. Open the report and work through CHECK THESE YOURSELF (it needs the iPhone in your hand)"
echo "   2. An [UNKNOWN] item means a check could not run, so it did NOT pass: run this scan again"
echo "   3. Send ${ZIP_NAME} to whoever asked for it (it holds only the report, never a backup)"
echo ""
echo -e "${PURPLE}Scan completed at $(date).${NC}"
echo ""
exit 0
