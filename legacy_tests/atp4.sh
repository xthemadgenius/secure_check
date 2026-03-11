#!/bin/bash

# ============================================================================
# MAC SECURITY SCANNER v4.1
# Generates 6 security report files with real-time streaming output,
# then packages them into NAME.Security_Check.zip
# ============================================================================

# --- Robustness: cleanup on exit/interrupt ---
# (Not using set -e because we want scans to continue even if individual commands fail)
set -uo pipefail

# Track background PIDs for cleanup
SUDO_REFRESH_PID=""
REPORT_DIR=""
ZIP_PATH=""

cleanup() {
    # Kill sudo refresh background process if running
    if [[ -n "$SUDO_REFRESH_PID" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then
        kill "$SUDO_REFRESH_PID" 2>/dev/null
        wait "$SUDO_REFRESH_PID" 2>/dev/null || true
    fi
    # Invalidate sudo credentials
    sudo -k 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- macOS check ---
if [[ "$(uname)" != "Darwin" ]]; then
    echo "ERROR: This script only runs on macOS."
    exit 1
fi

# --- Check required tools ---
for cmd in zip lsof xattr plutil; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command '$cmd' not found."
        exit 1
    fi
done

# --- Color codes ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

clear

# --- Banner ---
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}               MAC SECURITY SCANNER v4.1${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo -e "${YELLOW}This tool performs 6 security scans on your Mac to detect:${NC}"
echo "  1. Suspicious hidden files and malware"
echo "  2. Persistence mechanisms (LaunchAgents/Daemons/Crontab/Login Items)"
echo "  3. Temp directory anomalies"
echo "  4. Active network connections to potential C2 servers"
echo "  5. Hidden/suspicious processes"
echo "  6. Extended attributes that may hide malicious code"
echo ""
echo -e "${RED}NOTE: Some scans require administrator privileges.${NC}"
echo -e "${RED}      You will be prompted for your password once.${NC}"
echo ""

# --- Get user name ---
echo -e "${CYAN}------------------------------------------------------------${NC}"
read -p "Enter your name for the report (no spaces): " USER_NAME
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

# --- Define output paths ---
ZIP_NAME="${USER_NAME}.Security_Check.zip"
ZIP_PATH="$HOME/Desktop/$ZIP_NAME"
REPORT_DIR="$HOME/Desktop/${USER_NAME}.Security_Check"

# Create VISIBLE folder on Desktop
mkdir -p "$REPORT_DIR"

# File names (exactly 6)
FILE_HIDDEN="suspicious_hidden_analysis.txt"
FILE_LAUNCH="launch_agents_report.txt"
FILE_TEMP="temp_hidden_files.txt"
FILE_NETWORK="network_connections.txt"
FILE_PROCESS="hidden_processes.txt"
FILE_XATTR="extended_attributes.txt"

# --- Confirm ---
echo -e "${YELLOW}------------------------------------------------------------${NC}"
echo -e "Folder: ${CYAN}~/Desktop/${USER_NAME}.Security_Check/${NC}"
echo -e "   ZIP: ${CYAN}~/Desktop/${ZIP_NAME}${NC}"
echo ""
read -p "Ready to begin scanning? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Scan cancelled.${NC}"
    rmdir "$REPORT_DIR" 2>/dev/null || true
    REPORT_DIR=""
    exit 0
fi
echo ""

# --- Request sudo upfront ---
echo -e "${YELLOW}Password required for full system scan.${NC}"
echo -e "${GRAY}(Only used to read system files and network info. Nothing is modified.)${NC}"
sudo -v
# Keep sudo alive in background
(while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done) &
SUDO_REFRESH_PID=$!
echo -e "${GREEN}Password accepted.${NC}"
echo ""

# --- Progress tracking ---
TOTAL_SCANS=6
CURRENT_SCAN=0

show_progress() {
    CURRENT_SCAN=$((CURRENT_SCAN + 1))
    local pct=$((CURRENT_SCAN * 100 / TOTAL_SCANS))
    local filled=$((CURRENT_SCAN * 40 / TOTAL_SCANS))
    local empty=$((40 - filled))
    echo ""
    echo -ne "${BLUE}[${pct}%] ${GREEN}["
    printf "%0.s#" $(seq 1 $filled)
    if [[ $empty -gt 0 ]]; then
        printf "%0.s-" $(seq 1 $empty)
    fi
    echo -e "]${NC}  Scan ${CURRENT_SCAN}/${TOTAL_SCANS}"
    echo ""
}

# Helper: stream lines to both file and terminal with a prefix icon
# Usage: stream_to_file_and_terminal <file> <icon> <color>
stream_live() {
    local file="$1"
    local icon="$2"
    local color="$3"
    while IFS= read -r line; do
        echo "$line" >> "$file"
        echo -e "  ${color}${icon}${NC} $line"
    done
}

# ============================================================================
# SCAN 1: SUSPICIOUS HIDDEN FILES
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 1: Hidden Files${NC} - searching for hidden files, executables, user dir anomalies"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_HIDDEN"

{
    echo "SUSPICIOUS HIDDEN FILES REPORT - $(date)"
    echo "=========================================="
    echo ""
} > "$OUTFILE"

# Recently modified hidden files (targeted paths where threats actually hide)
echo "Recently modified hidden files (last 7 days):" >> "$OUTFILE"
echo "------------------------------------------" >> "$OUTFILE"
sudo find /Users /tmp /var/tmp /private/tmp /Library/LaunchAgents /Library/LaunchDaemons \
    -name ".*" -type f -mtime -7 -ls 2>/dev/null \
    | grep -v "/Library/Application Support" \
    | stream_live "$OUTFILE" "FILE" "$CYAN" || true

echo "" >> "$OUTFILE"

# Executable hidden files (targeted paths)
echo -e "\n${GRAY}   (scanning executable hidden files...)${NC}"
echo "Executable hidden files:" >> "$OUTFILE"
echo "-----------------------" >> "$OUTFILE"
sudo find /Users /tmp /var/tmp /private/tmp \
    -name ".*" -type f -perm /111 -ls 2>/dev/null \
    | grep -v "/Library/Application Support" \
    | stream_live "$OUTFILE" "EXEC" "$YELLOW" || true

echo "" >> "$OUTFILE"

# Hidden files in user directories
echo -e "\n${GRAY}   (scanning user directories...)${NC}"
echo "Hidden files in user directories:" >> "$OUTFILE"
echo "--------------------------------" >> "$OUTFILE"
sudo find /Users -name ".*" -type f -ls 2>/dev/null \
    | grep -v "/Library" \
    | stream_live "$OUTFILE" "USER" "$PURPLE" || true

echo "" >> "$OUTFILE"

# SHA-256 hashes of suspicious executables
echo "SHA-256 hashes of suspicious executable hidden files:" >> "$OUTFILE"
echo "----------------------------------------------------" >> "$OUTFILE"
sudo find /Users -name ".*" -type f -perm /111 2>/dev/null \
    | grep -v "/Library" \
    | while IFS= read -r f; do
        hash_line=$(shasum -a 256 "$f" 2>/dev/null) || true
        if [[ -n "$hash_line" ]]; then
            echo "$hash_line" >> "$OUTFILE"
            echo -e "  ${RED}HASH${NC} $hash_line"
        fi
    done

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
ITEM_COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
echo -e "  ${GREEN}Done -> ${FILE_HIDDEN} (${ITEM_COUNT} lines)${NC}"

# ============================================================================
# SCAN 2: LAUNCH AGENTS / DAEMONS + CRONTAB + LOGIN ITEMS
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 2: Launch Agents & Persistence${NC} - LaunchAgents, Daemons, crontab, login items"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_LAUNCH"

{
    echo "LAUNCH AGENTS & PERSISTENCE SCAN REPORT - $(date)"
    echo "========================================"
    echo ""
    echo "User Launch Agents (~/Library/LaunchAgents/):"
    echo "----------------------------------------------"
} > "$OUTFILE"

if [[ -d "$HOME/Library/LaunchAgents" ]]; then
    ls -la "$HOME/Library/LaunchAgents/" 2>/dev/null \
        | stream_live "$OUTFILE" "USR " "$CYAN" || true
else
    echo "(directory does not exist)" >> "$OUTFILE"
fi

{
    echo ""
    echo "System Launch Agents (/Library/LaunchAgents/):"
    echo "-----------------------------------------------"
} >> "$OUTFILE"
sudo ls -la /Library/LaunchAgents/ 2>/dev/null \
    | stream_live "$OUTFILE" "SYS " "$YELLOW" || true

{
    echo ""
    echo "System Launch Daemons (/Library/LaunchDaemons/):"
    echo "-------------------------------------------------"
} >> "$OUTFILE"
sudo ls -la /Library/LaunchDaemons/ 2>/dev/null \
    | stream_live "$OUTFILE" "DMN " "$PURPLE" || true

{
    echo ""
    echo "User Launch Daemons (~/Library/LaunchDaemons/):"
    echo "------------------------------------------------"
} >> "$OUTFILE"
if [[ -d "$HOME/Library/LaunchDaemons" ]]; then
    ls -la "$HOME/Library/LaunchDaemons/" 2>/dev/null \
        | stream_live "$OUTFILE" "UDMN" "$PURPLE" || true
else
    echo "(directory does not exist)" >> "$OUTFILE"
fi

# Plist contents of non-Apple agents
{
    echo ""
    echo "========================================"
    echo "PLIST CONTENTS OF NON-APPLE AGENTS:"
    echo "========================================"
} >> "$OUTFILE"

echo -e "\n${GRAY}   (dumping non-Apple plist contents...)${NC}"
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
    if [[ -d "$dir" ]]; then
        find "$dir" -name "*.plist" 2>/dev/null | while IFS= read -r plist; do
            basename_plist=$(basename "$plist")
            if [[ "$basename_plist" != com.apple.* ]]; then
                echo "" >> "$OUTFILE"
                echo "--- $plist ---" >> "$OUTFILE"
                echo -e "  ${RED}PLIST${NC} $plist"
                plutil -p "$plist" 2>/dev/null >> "$OUTFILE" || echo "(could not parse)" >> "$OUTFILE"
            fi
        done
    fi
done

# Crontab entries
{
    echo ""
    echo "========================================"
    echo "CRONTAB ENTRIES:"
    echo "========================================"
    echo "Current user crontab:"
} >> "$OUTFILE"
cron_out=$(crontab -l 2>/dev/null) || cron_out="(no crontab)"
echo "$cron_out" >> "$OUTFILE"
if [[ "$cron_out" != "(no crontab)" ]]; then
    echo -e "  ${YELLOW}CRON${NC} User crontab has entries"
fi

echo "" >> "$OUTFILE"
echo "Root crontab:" >> "$OUTFILE"
root_cron=$(sudo crontab -l 2>/dev/null) || root_cron="(no crontab)"
echo "$root_cron" >> "$OUTFILE"
if [[ "$root_cron" != "(no crontab)" ]]; then
    echo -e "  ${RED}CRON${NC} Root crontab has entries"
fi

# Login items
{
    echo ""
    echo "========================================"
    echo "LOGIN ITEMS:"
    echo "========================================"
} >> "$OUTFILE"
login_items=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null) || login_items="(could not retrieve login items)"
echo "$login_items" >> "$OUTFILE"
if [[ "$login_items" != "(could not retrieve login items)" && -n "$login_items" ]]; then
    echo -e "  ${YELLOW}LOGIN${NC} $login_items"
fi

{
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Plists with random/obfuscated names"
    echo "- Files mimicking Apple (com.apple.xxx) that are NOT in /System"
    echo "- Recently modified agents/daemons"
    echo "- Crontab entries running scripts from /tmp or hidden paths"
    echo "- Unknown login items"
} >> "$OUTFILE"

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
ITEM_COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
echo -e "  ${GREEN}Done -> ${FILE_LAUNCH} (${ITEM_COUNT} lines)${NC}"

# ============================================================================
# SCAN 3: TEMP DIRECTORY HIDDEN FILES
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 3: Temp Directories${NC} - scanning /tmp, /var/tmp, /private/tmp for hidden files"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_TEMP"

{
    echo "TEMP DIRECTORY HIDDEN FILES SCAN - $(date)"
    echo "============================================="
    echo ""
    echo "Files modified in last 7 days:"
    echo "-------------------------------"
} > "$OUTFILE"

sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null \
    | stream_live "$OUTFILE" "TMP " "$CYAN" || true

echo "" >> "$OUTFILE"

# Accurate count (re-run find, count only)
TEMP_COUNT=$(sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 2>/dev/null | wc -l | tr -d ' ')

{
    echo "============================================="
    echo "SUMMARY:"
    echo "Total suspicious temp files: $TEMP_COUNT"
    echo ""
    echo "SHA-256 hashes of hidden temp files:"
    echo "------------------------------------"
} >> "$OUTFILE"

sudo find /tmp /var/tmp /private/tmp -name ".*" -type f -mtime -7 2>/dev/null \
    | while IFS= read -r f; do
        hash_line=$(shasum -a 256 "$f" 2>/dev/null) || true
        if [[ -n "$hash_line" ]]; then
            echo "$hash_line" >> "$OUTFILE"
            echo -e "  ${RED}HASH${NC} $hash_line"
        fi
    done

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
echo -e "  ${GREEN}Done -> ${FILE_TEMP} (${TEMP_COUNT} hidden files found)${NC}"

# ============================================================================
# SCAN 4: NETWORK CONNECTIONS (single capture, then filter)
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 4: Network Connections${NC} - capturing active connections and listening ports"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_NETWORK"

# Capture lsof output ONCE to avoid state changes between queries
LSOF_SNAPSHOT=$(sudo lsof -i -n 2>/dev/null || true)

{
    echo "NETWORK CONNECTIONS SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "ESTABLISHED Connections (Active):"
    echo "--------------------------------"
} > "$OUTFILE"

echo "$LSOF_SNAPSHOT" | grep "ESTABLISHED" \
    | stream_live "$OUTFILE" "CONN" "$GREEN" || echo "(none found)" >> "$OUTFILE"

{
    echo ""
    echo "LISTENING Ports (Services):"
    echo "---------------------------"
} >> "$OUTFILE"

echo "$LSOF_SNAPSHOT" | grep "LISTEN" \
    | stream_live "$OUTFILE" "LSTN" "$YELLOW" || echo "(none found)" >> "$OUTFILE"

# DNS resolution
{
    echo ""
    echo "DNS Resolution of Connected IPs:"
    echo "---------------------------------"
} >> "$OUTFILE"

echo -e "\n${GRAY}   (resolving IP addresses...)${NC}"
echo "$LSOF_SNAPSHOT" | grep "ESTABLISHED" \
    | awk '{print $9}' | sed 's/.*->//' | cut -d: -f1 \
    | sort -u | while IFS= read -r ip; do
        if [[ -n "$ip" && "$ip" != "*" ]]; then
            resolved=$(host "$ip" 2>/dev/null | head -1 || echo "no reverse DNS")
            echo "  $ip -> $resolved" >> "$OUTFILE"
            echo -e "  ${PURPLE}DNS ${NC} $ip -> $resolved"
        fi
    done

{
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Connections to foreign/unknown IP addresses"
    echo "- Unusual ports (4444, 1337, 31337, 8443, 9001, etc.)"
    echo "- Processes with random or obfuscated names"
    echo "- Connections from processes in /tmp or hidden directories"
} >> "$OUTFILE"

unset LSOF_SNAPSHOT

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
ITEM_COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
echo -e "  ${GREEN}Done -> ${FILE_NETWORK} (${ITEM_COUNT} lines)${NC}"

# ============================================================================
# SCAN 5: HIDDEN / SUSPICIOUS PROCESSES
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 5: Process Scan${NC} - listing non-system processes and checking for anomalies"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_PROCESS"

{
    echo "HIDDEN PROCESSES SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "Non-root, non-system processes:"
    echo "-------------------------------"
} > "$OUTFILE"

# Capture process list, exclude system processes AND this script
PS_OUTPUT=$(ps aux | grep -v "^_" | grep -v "^root" | grep -v "^USER" \
    | grep -v "launchd" | grep -v "kernel_task" \
    | grep -v "grep" | grep -v "atp4\.sh" || true)

# Stream each process line with CPU highlighting
echo "$PS_OUTPUT" | while IFS= read -r line; do
    if [[ -z "$line" ]]; then continue; fi
    echo "$line" >> "$OUTFILE"
    cpu=$(echo "$line" | awk '{print $3}')
    # Integer comparison (strip decimal) to avoid bc dependency
    cpu_int=${cpu%%.*}
    if [[ "$cpu_int" -gt 50 ]] 2>/dev/null; then
        echo -e "  ${RED}HIGH CPU (${cpu}%)${NC} $line"
    else
        echo -e "  ${CYAN}PROC${NC} $line"
    fi
done

PROC_COUNT=$(echo "$PS_OUTPUT" | grep -c '[^[:space:]]' || echo "0")

{
    echo ""
    echo "========================================"
    echo "PROCESS COUNT: $PROC_COUNT"
    echo ""
    echo "HIGH CPU PROCESSES (>50%):"
    echo "--------------------------"
} >> "$OUTFILE"
echo "$PS_OUTPUT" | awk '{if ($3+0 > 50) print "  WARNING: "$0}' >> "$OUTFILE" || true

{
    echo ""
    echo "PROCESSES RUNNING FROM /tmp OR /var/tmp:"
    echo "-----------------------------------------"
} >> "$OUTFILE"
echo "$PS_OUTPUT" | grep -E "/tmp|/var/tmp" >> "$OUTFILE" || echo "(none found)" >> "$OUTFILE"

{
    echo ""
    echo "SUSPICIOUS INDICATORS:"
    echo "- Processes with %CPU > 50% (potential mining/activity)"
    echo "- Processes running from /tmp or /var/tmp"
    echo "- Processes with no parent (PPID 1)"
    echo "- Processes with random or single-character names"
} >> "$OUTFILE"

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
echo -e "  ${GREEN}Done -> ${FILE_PROCESS} (${PROC_COUNT} processes)${NC}"

# ============================================================================
# SCAN 6: EXTENDED ATTRIBUTES
# ============================================================================
show_progress
echo -e "${CYAN}> Scan 6: Extended Attributes${NC} - checking applications for hidden metadata"
echo -e "${GRAY}--- Live findings (streaming) ------------------------------------------${NC}"

OUTFILE="$REPORT_DIR/$FILE_XATTR"

{
    echo "EXTENDED ATTRIBUTES SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "Applications with extended attributes:"
    echo "-------------------------------------"
} > "$OUTFILE"

find /Applications -name "*.app" -maxdepth 2 -print0 2>/dev/null | while IFS= read -r -d '' app; do
    attrs=$(xattr "$app" 2>/dev/null || true)
    if [[ -n "$attrs" ]]; then
        echo "Checking: $app" >> "$OUTFILE"
        echo -e "  ${YELLOW}APP ${NC} $app"
        while IFS= read -r attr; do
            if [[ -n "$attr" ]]; then
                value=$(xattr -p "$attr" "$app" 2>/dev/null | head -c 100 || true)
                echo "   $attr = $value" >> "$OUTFILE"
                # Highlight suspicious attributes
                if [[ "$attr" == *"test"* ]] || [[ "$attr" == *"quarantine"* ]]; then
                    echo -e "    ${RED}WARN${NC} $attr = $value"
                else
                    echo -e "    ${GRAY}ATTR${NC} $attr"
                fi
            fi
        done <<< "$attrs"
        echo "" >> "$OUTFILE"
    fi
done

{
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Attributes named 'test' or custom non-Apple attributes"
    echo "- Hidden scripts in metadata"
    echo "- Executable flags in attributes"
    echo "- com.apple.quarantine is normal for downloaded apps"
    echo "  but suspicious if combined with other unusual attributes"
} >> "$OUTFILE"

echo -e "${GRAY}------------------------------------------------------------------------${NC}"
ITEM_COUNT=$(wc -l < "$OUTFILE" | tr -d ' ')
echo -e "  ${GREEN}Done -> ${FILE_XATTR} (${ITEM_COUNT} lines)${NC}"

# ============================================================================
# CREATE ZIP (automatic)
# ============================================================================
echo ""
echo -e "${CYAN}Packaging reports into ZIP...${NC}"

# Verify all 6 files exist
EXPECTED_FILES=("$FILE_HIDDEN" "$FILE_LAUNCH" "$FILE_TEMP" "$FILE_NETWORK" "$FILE_PROCESS" "$FILE_XATTR")
for f in "${EXPECTED_FILES[@]}"; do
    if [[ ! -f "$REPORT_DIR/$f" ]]; then
        echo -e "${RED}ERROR: Missing report file: $f${NC}"
        exit 1
    fi
done

# Remove existing ZIP if present
if [[ -f "$ZIP_PATH" ]]; then
    rm -f "$ZIP_PATH"
fi

# Create ZIP containing exactly the 6 files (flat, no directory nesting)
(cd "$REPORT_DIR" && zip -j "$ZIP_PATH" \
    "$FILE_HIDDEN" \
    "$FILE_LAUNCH" \
    "$FILE_TEMP" \
    "$FILE_NETWORK" \
    "$FILE_PROCESS" \
    "$FILE_XATTR" \
) > /dev/null 2>&1

# Verify ZIP was created
if [[ ! -f "$ZIP_PATH" ]]; then
    echo -e "${RED}ERROR: Failed to create ZIP file.${NC}"
    exit 1
fi

ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)

# ============================================================================
# FINAL OUTPUT
# ============================================================================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}                    SCAN COMPLETE${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${CYAN}Folder:${NC} ~/Desktop/${USER_NAME}.Security_Check/"
echo -e "${CYAN}   ZIP:${NC} ~/Desktop/${ZIP_NAME} (${ZIP_SIZE})"
echo ""
echo -e "${CYAN}Files included (6):${NC}"
echo "   1. ${FILE_HIDDEN}"
echo "   2. ${FILE_LAUNCH}"
echo "   3. ${FILE_TEMP}"
echo "   4. ${FILE_NETWORK}"
echo "   5. ${FILE_PROCESS}"
echo "   6. ${FILE_XATTR}"
echo ""
echo -e "${CYAN}ZIP contents:${NC}"
unzip -l "$ZIP_PATH" 2>/dev/null | tail -n +4 | head -7
echo ""

# Ask about folder cleanup (ZIP already exists regardless)
read -p "Delete the folder and keep only the ZIP? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$REPORT_DIR"
    REPORT_DIR="" # prevent cleanup trap from erroring
    echo -e "${GREEN}Folder deleted. ZIP remains at ~/Desktop/${ZIP_NAME}${NC}"
else
    echo -e "${GREEN}Both folder and ZIP kept on Desktop.${NC}"
    REPORT_DIR="" # prevent cleanup trap from touching it
fi

echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "   1. Review reports for suspicious indicators"
echo "   2. Send ${ZIP_NAME} to security team for analysis"
echo "   3. If compromise found, isolate the machine"
echo ""
echo -e "${PURPLE}Scan completed at $(date).${NC}"
echo ""
