#!/usr/bin/env bash
# mac_iphone_security_audit.sh
# Defensive macOS host audit + iPhone-connected sanity checks (non-destructive by default).
# Runs on macOS. Creates a timestamped log on your Desktop.
#
# Usage:
#   chmod +x mac_iphone_security_audit.sh
#   ./mac_iphone_security_audit.sh
#
# Optional:
#   APPLY=1 ./mac_iphone_security_audit.sh        # enables interactive “apply” actions (kill/quarantine/pf rules) with confirmations

set -euo pipefail

APPLY="${APPLY:-0}"
TS="$(date +"%Y%m%d_%H%M%S")"
LOG="$HOME/Desktop/mac_iphone_security_audit_$TS.log"
QUAR_DIR="$HOME/Desktop/quarantine_$TS"

# ---------- helpers ----------
say() { printf "%s\n" "$*" | tee -a "$LOG" ; }
hr()  { say "----------------------------------------------------------------"; }
run() {
  local cmd="$*"
  say "\n$ $cmd"
  # shellcheck disable=SC2086
  eval $cmd 2>&1 | tee -a "$LOG"
}
confirm() {
  local prompt="$1"
  read -r -p "$prompt [y/N]: " ans
  [[ "${ans:-}" =~ ^[Yy]$ ]]
}
need_cmd() { command -v "$1" >/dev/null 2>&1; }

# Determine primary interface (best-effort)
DEFAULT_IF="$(route get default 2>/dev/null | awk '/interface:/{print $2; exit}' || true)"
DEFAULT_IF="${DEFAULT_IF:-en0}"

# Sudo keep-alive (asks once)
sudo -v
# Keep sudo alive while script runs
( while true; do sudo -n true; sleep 30; done ) >/dev/null 2>&1 &
SUDO_KEEPALIVE_PID=$!
trap 'kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true' EXIT

say "macOS + iPhone-connected security audit"
say "Log: $LOG"
say "Apply-mode (interactive): $APPLY"
hr

# ---------- 0) iPhone connected checks (best-effort, no extra deps) ----------
say "0) iPhone / USB device checks (best-effort)"
run "system_profiler SPUSBDataType | sed -n '1,220p'"

# Try to extract any iPhone/iPad block to make it easy to spot
say "\nQuick filter: iPhone/iPad/Apple Mobile Device in USB tree"
run "system_profiler SPUSBDataType | awk 'BEGIN{IGNORECASE=1} /iPhone|iPad|Apple Mobile Device/{p=1} p{print} /^\\s*$/{p=0}'"

say "\nFinder/iTunes backup folder (on Mac). This is about Mac-side backups, not directly the phone’s live state."
run "ls -la \"$HOME/Library/Application Support/MobileSync\" 2>/dev/null || true"
run "ls -la \"$HOME/Library/Application Support/MobileSync/Backup\" 2>/dev/null || true"
say "Tip: In Finder (select iPhone) enable 'Encrypt local backup' to protect backups stored on this Mac."
hr

# ---------- 1) Network + process visibility ----------
say "1) Network connections + listeners + shell/script processes"
run "sudo lsof -i -P"
# macOS netstat: LISTEN is shown for TCP when filtered
run "netstat -anv -p tcp | grep -i LISTEN || true"
run "ps aux | egrep -i '(cron|launchd|bash|sh|zsh|python|perl|ruby)' | grep -v egrep || true"
hr

# ---------- 2) Optional: kill suspicious process ----------
say "2) Optional: terminate suspicious processes (interactive, confirm each)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Do you want to kill a process by PID?"; then
    read -r -p "Enter PID: " PID
    run "sudo kill -9 \"$PID\""
  fi

  if confirm "Do you want to pkill by matching a process name/pattern?"; then
    read -r -p "Enter pattern (exactly what you’d pass to pkill -f): " PAT
    # Quote safely for eval
    run "sudo pkill -f \"${PAT//\"/\\\"}\""
  fi

  if confirm "Do you want to kill processes listening on a specific port?"; then
    read -r -p "Enter port (e.g., 1337): " PORT
    run "sudo lsof -ti :\"$PORT\" | xargs -r sudo kill -9"
  fi
else
  say "Apply-mode off: skipping kill actions. Re-run with APPLY=1 to enable."
fi
hr

# ---------- 3) Launch agents/daemons checks ----------
say "3) LaunchAgents / LaunchDaemons inventory"
run "ls -la \"$HOME/Library/LaunchAgents\" 2>/dev/null || true"
run "ls -la /Library/LaunchAgents 2>/dev/null || true"
run "ls -la /Library/LaunchDaemons 2>/dev/null || true"
run "ls -la /System/Library/LaunchAgents 2>/dev/null || true"
run "ls -la /System/Library/LaunchDaemons 2>/dev/null || true"

say "\nOptional: unload + remove a suspicious plist (interactive)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Unload/remove a LaunchAgent plist from ~/Library/LaunchAgents ?"; then
    mkdir -p "$QUAR_DIR"
    read -r -p "Enter plist filename (e.g., suspicious.plist): " PLIST
    PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST"
    run "launchctl unload \"$PLIST_PATH\" || true"
    run "mv \"$PLIST_PATH\" \"$QUAR_DIR/\""
    say "Moved to quarantine: $QUAR_DIR"
  fi
else
  say "Apply-mode off: not unloading/removing plists."
fi
hr

# ---------- 4) Cron checks ----------
say "4) Cron checks"
run "crontab -l || true"
run "sudo crontab -l || true"
hr

# ---------- 5) Kernel extensions (kext) / system extensions ----------
say "5) Kernel extensions / loaded extensions (varies by macOS version)"
if need_cmd kmutil; then
  run "kmutil showloaded --list-only || true"
else
  run "kextstat | grep -v com.apple || true"
fi

say "\nOptional: unload suspicious kext bundle id (interactive, older systems)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Attempt kext unload by bundle id? (Often blocked on modern macOS)"; then
    read -r -p "Enter bundle id (e.g., com.suspicious.kext): " BID
    if need_cmd kmutil; then
      run "sudo kmutil unload -b \"$BID\" || true"
    else
      run "sudo kextunload -b \"$BID\" || true"
    fi
  fi
else
  say "Apply-mode off: not unloading extensions."
fi
hr

# ---------- 6) Recently modified binaries ----------
say "6) Recently modified binaries in common system paths (last 7 days)"
run "sudo find /usr/local/bin /usr/bin /bin /sbin -type f -mtime -7 -print 2>/dev/null || true"
hr

# ---------- 7) Hidden files + recent scripts ----------
say "7) Hidden-ish areas + recent scripts (last 3 days in home dir)"
run "ls -la \"$HOME/Library/.\" 2>/dev/null || true"
run "ls -la \"$HOME/Library/Application Support\" 2>/dev/null || true"
run "find \"$HOME\" -type f \\( -name \"*.sh\" -o -name \"*.py\" -o -name \"*.pl\" \\) -mtime -3 -print 2>/dev/null || true"

say "\nOptional: quarantine a suspicious file (move + chmod 000)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Quarantine a file by path?"; then
    mkdir -p "$QUAR_DIR"
    read -r -p "Enter full path to file: " FPATH
    run "sudo mv \"$FPATH\" \"$QUAR_DIR/\""
    base="$(basename "$FPATH")"
    run "sudo chmod 000 \"$QUAR_DIR/$base\""
    say "Quarantined in: $QUAR_DIR"
  fi
else
  say "Apply-mode off: not quarantining files."
fi
hr

# ---------- 8) Firewall (PF + Application Firewall) ----------
say "8) Firewall checks (PF + macOS Application Firewall)"

# PF status
run "sudo pfctl -s info || true"
run "sudo pfctl -sr || true"

# Application Firewall status
run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate || true"
run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode || true"
run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps || true"

say "\nOptional: add a PF rule to block a TCP port (SAFER: writes a small anchor, doesn’t overwrite full ruleset)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Add PF block rule for a TCP port?"; then
    read -r -p "Enter port to block (e.g., 4444): " PFPORT
    ANCHOR_NAME="com.local.blockport"
    RULE_FILE="/etc/pf.anchors/$ANCHOR_NAME"
    # Create anchor rule
    run "echo \"block in proto tcp from any to any port $PFPORT\" | sudo tee \"$RULE_FILE\" >/dev/null"
    # Ensure pf.conf loads the anchor (idempotent-ish)
    if ! sudo grep -q "$ANCHOR_NAME" /etc/pf.conf; then
      run "echo \"anchor \\\"$ANCHOR_NAME\\\"\" | sudo tee -a /etc/pf.conf >/dev/null"
      run "echo \"load anchor \\\"$ANCHOR_NAME\\\" from \\\"$RULE_FILE\\\"\" | sudo tee -a /etc/pf.conf >/dev/null"
    fi
    run "sudo pfctl -f /etc/pf.conf"
    run "sudo pfctl -e || true"
    say "PF rule added via anchor: $RULE_FILE"
  fi

  if confirm "Enable macOS Application Firewall (global on)?"; then
    run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
  fi

  if confirm "Block a specific app with Application Firewall?"; then
    read -r -p "Enter full app path (e.g., /Applications/Bad.app): " APPPATH
    run "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp \"$APPPATH\""
  fi
else
  say "Apply-mode off: not modifying firewall rules."
fi
hr

# ---------- 9) Profiles + browser extensions + sudoers ----------
say "9) Profiles, browser extensions, sudoers"
# NOTE: `profiles` here reports macOS configuration profiles (MDM), not iPhone profiles.
run "sudo profiles -L || true"
run "sudo profiles show || true"

run "ls -la \"$HOME/Library/Safari/Extensions\" 2>/dev/null || true"
run "ls -la \"$HOME/Library/Application Support/Google/Chrome/Default/Extensions\" 2>/dev/null || true"

run "sudo cat /etc/sudoers | sed -n '1,220p'"
run "sudo ls -la /etc/sudoers.d 2>/dev/null || true"
run "sudo sh -c 'for f in /etc/sudoers.d/*; do [ -e \"\$f\" ] && echo \"--- \$f ---\" && cat \"\$f\"; done' || true"
hr

# ---------- 10) Memory map / code injection quick glance (PID-based) ----------
say "10) vmmap quick check (PID-based, interactive)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Run vmmap on a PID and grep common regions?"; then
    read -r -p "Enter PID: " VPID
    run "sudo vmmap \"$VPID\" | egrep -i '(malloc|stack|dyld)' || true"
  fi
else
  say "Apply-mode off: skipping vmmap PID check."
fi
hr

# ---------- 11) Signing identities + system integrity ----------
say "11) Signing identities (non-Apple) + SIP status + Gatekeeper sample assess"
run "security find-identity -v | grep -v \"Apple\" || true"
run "csrutil status || true"
run "sudo spctl --status || true"
# Assessing every app can be noisy; sample Applications root
run "sudo spctl --assess --verbose /Applications/* 2>/dev/null || true"
hr

# ---------- 12) Real-time monitoring helpers (print commands, don’t auto-run) ----------
say "12) Real-time monitoring commands (run these manually in a separate terminal if needed)"
say "   sudo opensnoop -n <process_name>"
say "   sudo fs_usage -w | egrep '(exec|rename|unlink)'"
hr

# ---------- 13) Optional packet capture ----------
say "13) Optional tcpdump capture (interactive)"
if [[ "$APPLY" == "1" ]]; then
  if confirm "Capture 100 packets to a pcap on Desktop?"; then
    PCAP="$HOME/Desktop/capture_$TS.pcap"
    say "Using interface: $DEFAULT_IF"
    run "sudo tcpdump -i \"$DEFAULT_IF\" -c 100 -w \"$PCAP\""
    say "Saved: $PCAP"
    say "Analyze with: tcpdump -r \"$PCAP\" -n"
  fi
else
  say "Apply-mode off: not capturing packets."
fi
hr

say "Done. Log saved to: $LOG"
if [[ "$APPLY" == "1" ]]; then
  say "Quarantine directory (if used): $QUAR_DIR"
fi