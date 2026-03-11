#!/bin/bash

# Color codes for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Clear screen for better presentation
clear

# Banner
echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                   🔍 MAC SECURITY SCANNER v3.0${NC}"
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
TEMP_LOG="$REPORT_DIR/.temp_log"
mkdir -p "$REPORT_DIR"

echo -e "${GREEN}✅ Reports will be saved to:${NC} $REPORT_DIR"
echo ""

# Initialize progress tracking
TOTAL_STEPS=6
CURRENT_STEP=0

# Function to show live log tail
show_live_log() {
    local log_file="$1"
    local scan_name="$2"
    echo -e "${GRAY}─── Live finding preview (last 10 items) ──────────────────────${NC}"
    tail -f "$log_file" 2>/dev/null | while read line; do
        if [[ -n "$line" ]]; then
            echo -e "  ${CYAN}🔍${NC} $line"
        fi
    done &
    TAIL_PID=$!
    # Let it run for a moment to show some results
    sleep 2
    kill $TAIL_PID 2>/dev/null
    wait $TAIL_PID 2>/dev/null
    echo -e "${GRAY}────────────────────────────────────────────────────────────${NC}"
}

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
    local scan_desc="$2"
    echo -e "${CYAN}▶ Starting scan ${CURRENT_STEP}/6: ${scan_name}${NC}"
    echo -e "${GRAY}  ${scan_desc}${NC}"
    echo ""
}

# Function to show scan complete
complete_scan() {
    local scan_name="$1"
    local file_name="$2"
    local item_count="$3"
    echo -e "${GREEN}  ✅ ${scan_name} complete → ${file_name}${NC}"
    if [[ -n "$item_count" ]]; then
        echo -e "     ${GRAY}Items found: ${item_count}${NC}"
    fi
    echo ""
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
start_scan "Hidden Files Scan" "Searching for hidden files, executables, and user directory anomalies"
{
    echo "SUSPICIOUS HIDDEN FILES REPORT - $(date)" > "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "==========================================" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    
    echo "Recently modified hidden files (last 7 days):" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "------------------------------------------" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    sudo find / -name ".*" -type f -mtime -7 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    
    echo "Executable hidden files:" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "-----------------------" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    sudo find / -name ".*" -type f -perm +111 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    
    echo "Hidden files in user directories:" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    echo "--------------------------------" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    sudo find /Users -name ".*" -type f -ls 2>/dev/null | grep -v "/Library" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/suspicious_hidden_analysis.txt"
    
} 2>/dev/null &
SCAN_PID=$!

# Show live log while scanning
show_live_log "$TEMP_LOG" "Hidden Files Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(wc -l < "$REPORT_DIR/suspicious_hidden_analysis.txt" 2>/dev/null | tr -d ' ')
complete_scan "Hidden Files Scan" "suspicious_hidden_analysis.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# 2. LAUNCH AGENTS REPORT
start_scan "Launch Agents Scan" "Checking for persistence mechanisms (LaunchAgents and LaunchDaemons)"
{
    echo "LAUNCH AGENTS SCAN REPORT - $(date)" > "$REPORT_DIR/launch_agents_report.txt"
    echo "========================================" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "" >> "$REPORT_DIR/launch_agents_report.txt"
    
    echo "User Launch Agents (~/Library/LaunchAgents/):" >> "$REPORT_DIR/launch_agents_report.txt"
    ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "" >> "$REPORT_DIR/launch_agents_report.txt"
    
    echo "System Launch Agents (/Library/LaunchAgents/):" >> "$REPORT_DIR/launch_agents_report.txt"
    sudo ls -la /Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "" >> "$REPORT_DIR/launch_agents_report.txt"
    
    echo "System Launch Daemons (/Library/LaunchDaemons/):" >> "$REPORT_DIR/launch_agents_report.txt"
    sudo ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -E "202[4-6]" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "" >> "$REPORT_DIR/launch_agents_report.txt"
    
    echo "========================================" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "SUSPICIOUS INDICATORS:" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "Check for:" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "- Plists with random names" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "- Files mimicking Apple (com.apple.xxx)" >> "$REPORT_DIR/launch_agents_report.txt"
    echo "- Recently modified (2024-2026)" >> "$REPORT_DIR/launch_agents_report.txt"
    
} 2>/dev/null &
SCAN_PID=$!

show_live_log "$TEMP_LOG" "Launch Agents Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(wc -l < "$REPORT_DIR/launch_agents_report.txt" 2>/dev/null | tr -d ' ')
complete_scan "Launch Agents Scan" "launch_agents_report.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# 3. TEMP DIRECTORY HIDDEN FILES REPORT
start_scan "Temp Directory Scan" "Checking /tmp, /var/tmp, and /private/tmp for hidden files"
{
    echo "TEMP DIRECTORY HIDDEN FILES SCAN - $(date)" > "$REPORT_DIR/temp_hidden_files.txt"
    echo "=============================================" >> "$REPORT_DIR/temp_hidden_files.txt"
    echo "" >> "$REPORT_DIR/temp_hidden_files.txt"
    
    echo "Files modified in last 7 days:" >> "$REPORT_DIR/temp_hidden_files.txt"
    echo "-------------------------------" >> "$REPORT_DIR/temp_hidden_files.txt"
    sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null | tee -a "$TEMP_LOG" >> "$REPORT_DIR/temp_hidden_files.txt"
    echo "" >> "$REPORT_DIR/temp_hidden_files.txt"
    
    echo "=============================================" >> "$REPORT_DIR/temp_hidden_files.txt"
    echo "SUMMARY:" >> "$REPORT_DIR/temp_hidden_files.txt"
    echo "Total suspicious temp files: $(sudo find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null | wc -l)" >> "$REPORT_DIR/temp_hidden_files.txt"
    
} 2>/dev/null &
SCAN_PID=$!

show_live_log "$TEMP_LOG" "Temp Directory Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(wc -l < "$REPORT_DIR/temp_hidden_files.txt" 2>/dev/null | tr -d ' ')
complete_scan "Temp Directory Scan" "temp_hidden_files.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# 4. NETWORK CONNECTIONS REPORT
start_scan "Network Connections Scan" "Identifying active connections and listening ports"
{
    echo "NETWORK CONNECTIONS SCAN - $(date)" > "$REPORT_DIR/network_connections.txt"
    echo "========================================" >> "$REPORT_DIR/network_connections.txt"
    echo "" >> "$REPORT_DIR/network_connections.txt"
    
    echo "ESTABLISHED Connections (Active):" >> "$REPORT_DIR/network_connections.txt"
    echo "--------------------------------" >> "$REPORT_DIR/network_connections.txt"
    sudo lsof -i 2>/dev/null | grep "ESTABLISHED" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/network_connections.txt"
    echo "" >> "$REPORT_DIR/network_connections.txt"
    
    echo "LISTENING Ports (Services):" >> "$REPORT_DIR/network_connections.txt"
    echo "---------------------------" >> "$REPORT_DIR/network_connections.txt"
    sudo lsof -i 2>/dev/null | grep "LISTEN" | tee -a "$TEMP_LOG" >> "$REPORT_DIR/network_connections.txt"
    echo "" >> "$REPORT_DIR/network_connections.txt"
    
    echo "========================================" >> "$REPORT_DIR/network_connections.txt"
    echo "SUSPICIOUS INDICATORS:" >> "$REPORT_DIR/network_connections.txt"
    echo "- Connections to foreign countries" >> "$REPORT_DIR/network_connections.txt"
    echo "- Unknown IP addresses" >> "$REPORT_DIR/network_connections.txt"
    echo "- Unusual ports (4444, 1337, 31337, etc.)" >> "$REPORT_DIR/network_connections.txt"
    echo "- Processes with random names" >> "$REPORT_DIR/network_connections.txt"
    
} 2>/dev/null &
SCAN_PID=$!

show_live_log "$TEMP_LOG" "Network Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(wc -l < "$REPORT_DIR/network_connections.txt" 2>/dev/null | tr -d ' ')
complete_scan "Network Scan" "network_connections.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# 5. HIDDEN PROCESSES REPORT
start_scan "Process Scan" "Listing all running processes (excluding system processes)"
{
    echo "HIDDEN PROCESSES SCAN - $(date)" > "$REPORT_DIR/hidden_processes.txt"
    echo "========================================" >> "$REPORT_DIR/hidden_processes.txt"
    echo "" >> "$REPORT_DIR/hidden_processes.txt"
    
    echo "Non-root, non-system processes:" >> "$REPORT_DIR/hidden_processes.txt"
    echo "-------------------------------" >> "$REPORT_DIR/hidden_processes.txt"
    ps aux | grep -v "^_" | grep -v "root" | grep -v "USER" | grep -v "launchd" | grep -v "kernel_task" | head -20 | tee -a "$TEMP_LOG" | head -10 >> "$REPORT_DIR/hidden_processes.txt"
    echo "" >> "$REPORT_DIR/hidden_processes.txt"
    
    echo "========================================" >> "$REPORT_DIR/hidden_processes.txt"
    echo "PROCESS COUNT: $(ps aux | grep -v "^_" | grep -v "root" | grep -v "USER" | wc -l)" >> "$REPORT_DIR/hidden_processes.txt"
    echo "" >> "$REPORT_DIR/hidden_processes.txt"
    
    echo "SUSPICIOUS INDICATORS:" >> "$REPORT_DIR/hidden_processes.txt"
    echo "- Processes with %CPU > 50% (potential mining/activity)" >> "$REPORT_DIR/hidden_processes.txt"
    echo "- Processes running from /tmp or /var/tmp" >> "$REPORT_DIR/hidden_processes.txt"
    echo "- Processes with no parent (PPID 1)" >> "$REPORT_DIR/hidden_processes.txt"
    
} 2>/dev/null &
SCAN_PID=$!

show_live_log "$TEMP_LOG" "Process Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(ps aux | grep -v "^_" | grep -v "root" | grep -v "USER" | wc -l | tr -d ' ')
complete_scan "Process Scan" "hidden_processes.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# 6. EXTENDED ATTRIBUTES REPORT
start_scan "Extended Attributes Scan" "Checking applications for hidden metadata attributes"
{
    echo "EXTENDED ATTRIBUTES SCAN - $(date)" > "$REPORT_DIR/extended_attributes.txt"
    echo "========================================" >> "$REPORT_DIR/extended_attributes.txt"
    echo "" >> "$REPORT_DIR/extended_attributes.txt"
    
    echo "Applications with extended attributes:" >> "$REPORT_DIR/extended_attributes.txt"
    echo "-------------------------------------" >> "$REPORT_DIR/extended_attributes.txt"
    
    find /Applications -name "*.app" -maxdepth 2 -exec sh -c '
        echo "Checking: {}"
        xattr -l "{}" 2>/dev/null | sed "s/^/   /"
        echo ""
    ' \; 2>/dev/null | tee -a "$TEMP_LOG" >> "$REPORT_DIR/extended_attributes.txt"
    
    echo "========================================" >> "$REPORT_DIR/extended_attributes.txt"
    echo "SUSPICIOUS INDICATORS:" >> "$REPORT_DIR/extended_attributes.txt"
    echo "- Attributes named 'test', 'com.apple.quarantine' (if not from App Store)" >> "$REPORT_DIR/extended_attributes.txt"
    echo "- Hidden scripts in metadata" >> "$REPORT_DIR/extended_attributes.txt"
    echo "- Executable flags in attributes" >> "$REPORT_DIR/extended_attributes.txt"
    echo "" >> "$REPORT_DIR/extended_attributes.txt"
    echo "NOTE: The 'com.apple.quarantine' attribute is normal for downloaded apps" >> "$REPORT_DIR/extended_attributes.txt"
    echo "      but suspicious if combined with other unusual attributes" >> "$REPORT_DIR/extended_attributes.txt"
    
} 2>/dev/null &
SCAN_PID=$!

show_live_log "$TEMP_LOG" "Extended Attributes Scan"
wait $SCAN_PID 2>/dev/null
ITEM_COUNT=$(wc -l < "$REPORT_DIR/extended_attributes.txt" 2>/dev/null | tr -d ' ')
complete_scan "Extended Attributes Scan" "extended_attributes.txt" "$ITEM_COUNT"
show_progress
rm -f "$TEMP_LOG"

# Create summary file
{
    echo "🔍 SECURITY SCAN SUMMARY - $(date)" > "$REPORT_DIR/00_README.txt"
    echo "========================================" >> "$REPORT_DIR/00_README.txt"
    echo "User: $USER_NAME" >> "$REPORT_DIR/00_README.txt"
    echo "" >> "$REPORT_DIR/00_README.txt"
    echo "Files generated:" >> "$REPORT_DIR/00_README.txt"
    echo "  1. suspicious_hidden_analysis.txt" >> "$REPORT_DIR/00_README.txt"
    echo "  2. launch_agents_report.txt" >> "$REPORT_DIR/00_README.txt"
    echo "  3. temp_hidden_files.txt" >> "$REPORT_DIR/00_README.txt"
    echo "  4. network_connections.txt" >> "$REPORT_DIR/00_README.txt"
    echo "  5. hidden_processes.txt" >> "$REPORT_DIR/00_README.txt"
    echo "  6. extended_attributes.txt" >> "$REPORT_DIR/00_README.txt"
    echo "" >> "$REPORT_DIR/00_README.txt"
    echo "To analyze these files, look for:" >> "$REPORT_DIR/00_README.txt"
    echo "  • Connections to suspicious IPs (especially 83.136.209.0/24)" >> "$REPORT_DIR/00_README.txt"
    echo "  • Processes with high CPU usage (>50%)" >> "$REPORT_DIR/00_README.txt"
    echo "  • Files in ~/Library/Translation/Hotfix/" >> "$REPORT_DIR/00_README.txt"
    echo "  • Recently modified hidden files" >> "$REPORT_DIR/00_README.txt"
    echo "  • Unknown launch agents/daemons" >> "$REPORT_DIR/00_README.txt"
    echo "" >> "$REPORT_DIR/00_README.txt"
    echo "Scan completed: $(date)" >> "$REPORT_DIR/00_README.txt"
    
}

# Ask about ZIP creation
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -p "📦 Create ZIP file of all reports? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Creating ZIP archive...${NC}"
    ZIP_NAME="$HOME/Desktop/${USER_NAME}.Security_Check_${TIMESTAMP}.zip"
    
    cd "$HOME/Desktop"
    zip -r "$ZIP_NAME" "$(basename "$REPORT_DIR")" > /dev/null 2>&1
    
    # Show ZIP contents
    echo -e "${GRAY}ZIP contents:${NC}"
    unzip -l "$ZIP_NAME" | tail -n +4 | head -8 | while read line; do
        echo -e "  ${CYAN}📄${NC} $line"
    done
    
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
echo -e "${YELLOW}📊 Scan Statistics:${NC}"
echo "   • Hidden files scanned: $(find / -name ".*" -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "   • Processes analyzed: $(ps aux | wc -l | tr -d ' ')"
echo "   • Applications checked: $(find /Applications -name "*.app" -maxdepth 2 2>/dev/null | wc -l | tr -d ' ')"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "   1. Review the reports for suspicious indicators"
echo "   2. Send ZIP to security team for analysis"
echo "   3. If infection found, prepare for system wipe"
echo ""
echo -e "${PURPLE}Thank you for running the security scan.${NC}"
echo ""