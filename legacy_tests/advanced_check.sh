#!/bin/bash

# Color codes for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Clear screen for better presentation
clear

# Banner
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                   🔍 MAC SECURITY SCANNER v2.0${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}This tool will perform 6 security scans on your Mac to detect:${NC}"
echo "  • Suspicious hidden files and malware"
echo "  • Persistence mechanisms (LaunchAgents/Daemons)"
echo "  • Active network connections to potential C2 servers"
echo "  • Hidden processes running on your system"
echo "  • Temp directory anomalies"
echo "  • Extended attributes that may hide malicious code"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Some scans require administrator privileges${NC}"
echo -e "${RED}   You will be prompted for your password when needed${NC}"
echo ""

# Get user's name for zip file
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -p "📝 Enter your name for the report (no spaces): " USER_NAME
echo ""

# Validate name
if [[ -z "$USER_NAME" || "$USER_NAME" =~ [[:space:]] ]]; then
    echo -e "${RED}❌ Error: Name cannot be empty or contain spaces${NC}"
    exit 1
fi

# Create timestamp and directories
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="$HOME/Desktop/${USER_NAME}.Security_Check_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

echo -e "${GREEN}✅ Reports will be saved to:${NC} $REPORT_DIR"
echo ""

# Initialize progress tracking
TOTAL_STEPS=6
CURRENT_STEP=0

# Function to show progress bar
show_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    PERCENT=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    COMPLETED=$((CURRENT_STEP * 50 / TOTAL_STEPS))
    REMAINING=$((50 - COMPLETED))
    
    echo ""
    echo -e "${BLUE}[ Progress: ${PERCENT}% ]${NC}"
    echo -ne "${GREEN}["
    printf "%0.s#" $(seq 1 $COMPLETED)
    printf "%0.s-" $(seq 1 $REMAINING)
    echo -e "${GREEN}]${NC}"
    echo ""
}

# Function to prompt for password with explanation
request_password() {
    local reason="$1"
    echo -e "${YELLOW}🔐 Password Required${NC}"
    echo -e "${CYAN}Reason:${NC} $reason"
    echo -e "${CYAN}Note:${NC} This is only to access system information. No data is modified."
    echo -e "${PURPLE}────────────────────────────────────────────────────────${NC}"
    sudo -v 2>/dev/null
    while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &
    echo -e "${GREEN}✅ Password accepted - continuing...${NC}"
    echo ""
}

# Function to show scan start
start_scan() {
    local scan_name="$1"
    echo -e "${CYAN}▶ Starting scan ${CURRENT_STEP}/6: ${scan_name}${NC}"
}

# Function to show scan complete
complete_scan() {
    local scan_name="$1"
    local file_name="$2"
    echo -e "${GREEN}  ✅ ${scan_name} complete → ${file_name}${NC}"
}

# Ask if user wants to proceed
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -p "⏳ Ready to begin scanning. Proceed? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ Scan cancelled by user${NC}"
    exit 0
fi
echo ""

# Request password upfront with explanation
request_password "Full system scan requires admin access to read all files and network connections"

# Show initial progress
show_progress

# 1. SUSPICIOUS HIDDEN FILES REPORT
start_scan "Hidden Files Scan"
{
    echo "SUSPICIOUS HIDDEN FILES REPORT - $(date)"
    echo "=========================================="
    echo ""
    echo "Recently modified hidden files (last 7 days):"
    echo "------------------------------------------"
    sudo find / -name ".*" -type f -mtime -7 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library"
    
    echo ""
    echo "Executable hidden files:"
    echo "-----------------------"
    sudo find / -name ".*" -type f -perm +111 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library"
    
    echo ""
    echo "Hidden files in user directories:"
    echo "--------------------------------"
    sudo find /Users -name ".*" -type f -ls 2>/dev/null | grep -v "/Library"
    
} > "$REPORT_DIR/suspicious_hidden_analysis.txt" 2>/dev/null
complete_scan "Hidden Files Scan" "suspicious_hidden_analysis.txt"
show_progress

# 2. LAUNCH AGENTS REPORT
start_scan "Launch Agents Scan"
{
    echo "LAUNCH AGENTS SCAN REPORT - $(date)"
    echo "========================================"
    echo ""
    echo "User Launch Agents (~/Library/LaunchAgents/):"
    ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "System Launch Agents (/Library/LaunchAgents/):"
    sudo ls -la /Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "System Launch Daemons (/Library/LaunchDaemons/):"
    sudo ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "Check for:"
    echo "- Plists with random names"
    echo "- Files mimicking Apple (com.apple.xxx)"
    echo "- Recently modified (2024-2026)"
} > "$REPORT_DIR/launch_agents_report.txt" 2>/dev/null
complete_scan "Launch Agents Scan" "launch_agents_report.txt"
show_progress

# 3. TEMP DIRECTORY HIDDEN FILES REPORT
start_scan "Temp Directory Scan"
{
    echo "TEMP DIRECTORY HIDDEN FILES SCAN - $(date)"
    echo "============================================="
    echo ""
    echo "Files modified in last 7 days:"
    echo "-------------------------------"
    sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null
    echo ""
    echo "============================================="
    echo "SUMMARY:"
    echo "Total suspicious temp files: $(sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null | wc -l)"
} > "$REPORT_DIR/temp_hidden_files.txt" 2>/dev/null
complete_scan "Temp Directory Scan" "temp_hidden_files.txt"
show_progress

# 4. NETWORK CONNECTIONS REPORT
start_scan "Network Connections Scan"
{
    echo "NETWORK CONNECTIONS SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "ESTABLISHED Connections (Active):"
    echo "--------------------------------"
    sudo lsof -i 2>/dev/null | grep "ESTABLISHED"
    echo ""
    echo "LISTENING Ports (Services):"
    echo "---------------------------"
    sudo lsof -i 2>/dev/null | grep "LISTEN"
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Connections to foreign countries"
    echo "- Unknown IP addresses"
    echo "- Unusual ports (4444, 1337, 31337, etc.)"
    echo "- Processes with random names"
} > "$REPORT_DIR/network_connections.txt" 2>/dev/null
complete_scan "Network Scan" "network_connections.txt"
show_progress

# 5. HIDDEN PROCESSES REPORT
start_scan "Process Scan"
{
    echo "HIDDEN PROCESSES SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "Non-root, non-system processes:"
    echo "-------------------------------"
    ps aux | grep -v "^_" | grep -v "root" | grep -v "USER" | grep -v "launchd" | grep -v "kernel_task"
    echo ""
    echo "========================================"
    echo "PROCESS COUNT: $(ps aux | grep -v "^_" | grep -v "root" | grep -v "USER" | wc -l)"
    echo ""
    echo "SUSPICIOUS INDICATORS:"
    echo "- Processes with %CPU > 50% (potential mining/activity)"
    echo "- Processes running from /tmp or /var/tmp"
    echo "- Processes with no parent (PPID 1)"
} > "$REPORT_DIR/hidden_processes.txt" 2>/dev/null
complete_scan "Process Scan" "hidden_processes.txt"
show_progress

# 6. EXTENDED ATTRIBUTES REPORT
start_scan "Extended Attributes Scan"
{
    echo "EXTENDED ATTRIBUTES SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "Applications with extended attributes:"
    echo "-------------------------------------"
    
    find /Applications -name "*.app" -maxdepth 2 -exec sh -c '
        echo "Checking: {}"
        xattr -l "{}" 2>/dev/null | sed "s/^/   /"
        echo ""
    ' \; 2>/dev/null
    
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Attributes named 'test', 'com.apple.quarantine' (if not from App Store)"
    echo "- Hidden scripts in metadata"
    echo "- Executable flags in attributes"
    echo ""
    echo "NOTE: The 'com.apple.quarantine' attribute is normal for downloaded apps"
    echo "      but suspicious if combined with other unusual attributes"
} > "$REPORT_DIR/extended_attributes.txt" 2>/dev/null
complete_scan "Extended Attributes Scan" "extended_attributes.txt"
show_progress

# Create summary file
{
    echo "🔍 SECURITY SCAN SUMMARY - $(date)"
    echo "========================================"
    echo "User: $USER_NAME"
    echo ""
    echo "Files generated:"
    echo "  1. suspicious_hidden_analysis.txt"
    echo "  2. launch_agents_report.txt"
    echo "  3. temp_hidden_files.txt"
    echo "  4. network_connections.txt"
    echo "  5. hidden_processes.txt"
    echo "  6. extended_attributes.txt"
    echo ""
    echo "To analyze these files, look for:"
    echo "  • Connections to suspicious IPs (especially 83.136.209.0/24)"
    echo "  • Processes with high CPU usage (>50%)"
    echo "  • Files in ~/Library/Translation/Hotfix/"
    echo "  • Recently modified hidden files"
    echo "  • Unknown launch agents/daemons"
    echo ""
    echo "Scan completed: $(date)"
    
} > "$REPORT_DIR/00_README.txt"

# Ask about ZIP creation
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -p "📦 Create ZIP file of all reports? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Creating ZIP archive...${NC}"
    ZIP_NAME="$HOME/Desktop/${USER_NAME}.Security_Check_${TIMESTAMP}.zip"
    
    cd "$HOME/Desktop"
    zip -r "$ZIP_NAME" "$(basename "$REPORT_DIR")" > /dev/null 2>&1
    
    # Ask about cleanup
    echo ""
    read -p "🧹 Delete temporary folder (keep only ZIP)? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$REPORT_DIR"
        echo -e "${GREEN}✅ Temporary folder deleted${NC}"
    fi
    
    FINAL_OUTPUT="$ZIP_NAME"
else
    FINAL_OUTPUT="$REPORT_DIR"
fi

# Final output
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                     ✅ SCAN COMPLETE!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}📂 Reports location:${NC}"
echo "   $FINAL_OUTPUT"
echo ""
echo -e "${CYAN}📋 Files included:${NC}"
echo "   • suspicious_hidden_analysis.txt"
echo "   • launch_agents_report.txt"
echo "   • temp_hidden_files.txt"
echo "   • network_connections.txt"
echo "   • hidden_processes.txt"
echo "   • extended_attributes.txt"
echo "   • 00_README.txt - Analysis guide"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "   1. Review the reports for suspicious indicators"
echo "   2. Send ZIP to security team for analysis"
echo "   3. If infection found, prepare for system wipe"
echo ""
echo -e "${PURPLE}Thank you for running the security scan.${NC}"
echo ""