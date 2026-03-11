#!/bin/bash

# Get user's name for zip file
echo "========================================="
echo "🔍 MAC SECURITY SCANNER"
echo "========================================="
echo ""
read -p "Enter your name for the report (no spaces): " USER_NAME

# Create timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="$HOME/Desktop/${USER_NAME}.Security_Check_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

echo ""
echo "📁 Creating reports in: $REPORT_DIR"
echo "⏳ Running scans (this may take a few minutes)..."
echo ""

# 1. SUSPICIOUS HIDDEN FILES REPORT
{
    echo "SUSPICIOUS HIDDEN FILES REPORT - $(date)"
    echo "=========================================="
    echo ""
    echo "Recently modified hidden files (last 7 days):"
    echo "------------------------------------------"
    find / -name ".*" -type f -mtime -7 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library"
    
    echo ""
    echo "Executable hidden files:"
    echo "-----------------------"
    find / -name ".*" -type f -perm +111 -ls 2>/dev/null | grep -v "^/System" | grep -v "^/Library"
    
    echo ""
    echo "Hidden files in user directories:"
    echo "--------------------------------"
    find /Users -name ".*" -type f -ls 2>/dev/null | grep -v "/Library"
    
} > "$REPORT_DIR/suspicious_hidden_analysis.txt"
echo "  ✅ Hidden files scan complete"

# 2. LAUNCH AGENTS REPORT
{
    echo "LAUNCH AGENTS SCAN REPORT - $(date)"
    echo "========================================"
    echo ""
    echo "User Launch Agents (~/Library/LaunchAgents/):"
    ls -la ~/Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "System Launch Agents (/Library/LaunchAgents/):"
    ls -la /Library/LaunchAgents/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "System Launch Daemons (/Library/LaunchDaemons/):"
    ls -la /Library/LaunchDaemons/ 2>/dev/null | grep -E "202[4-6]"
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "Check for:"
    echo "- Plists with random names"
    echo "- Files mimicking Apple (com.apple.xxx)"
    echo "- Recently modified (2024-2026)"
} > "$REPORT_DIR/launch_agents_report.txt"
echo "  ✅ Launch agents scan complete"

# 3. TEMP DIRECTORY HIDDEN FILES REPORT
{
    echo "TEMP DIRECTORY HIDDEN FILES SCAN - $(date)"
    echo "============================================="
    echo ""
    echo "Files modified in last 7 days:"
    echo "-------------------------------"
    find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null
    echo ""
    echo "============================================="
    echo "SUMMARY:"
    echo "Total suspicious temp files: $(find /tmp /var/tmp /private/tmp -name ".*" -mtime -7 -ls 2>/dev/null | wc -l)"
} > "$REPORT_DIR/temp_hidden_files.txt"
echo "  ✅ Temp files scan complete"

# 4. NETWORK CONNECTIONS REPORT
{
    echo "NETWORK CONNECTIONS SCAN - $(date)"
    echo "========================================"
    echo ""
    echo "ESTABLISHED Connections (Active):"
    echo "--------------------------------"
    lsof -i 2>/dev/null | grep "ESTABLISHED"
    echo ""
    echo "LISTENING Ports (Services):"
    echo "---------------------------"
    lsof -i 2>/dev/null | grep "LISTEN"
    echo ""
    echo "========================================"
    echo "SUSPICIOUS INDICATORS:"
    echo "- Connections to foreign countries"
    echo "- Unknown IP addresses"
    echo "- Unusual ports (4444, 1337, 31337, etc.)"
    echo "- Processes with random names"
} > "$REPORT_DIR/network_connections.txt"
echo "  ✅ Network scan complete"

# 5. HIDDEN PROCESSES REPORT
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
} > "$REPORT_DIR/hidden_processes.txt"
echo "  ✅ Processes scan complete"

# 6. EXTENDED ATTRIBUTES REPORT
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
} > "$REPORT_DIR/extended_attributes.txt"
echo "  ✅ Extended attributes scan complete"

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

# Create ZIP file on Desktop
ZIP_NAME="$HOME/Desktop/${USER_NAME}.Security_Check_${TIMESTAMP}.zip"

cd "$HOME/Desktop"
zip -r "$ZIP_NAME" "$(basename "$REPORT_DIR")" > /dev/null 2>&1

# Clean up
rm -rf "$REPORT_DIR"

echo ""
echo "========================================="
echo "✅ SCAN COMPLETE!"
echo "========================================="
echo ""
echo "📦 ZIP file created at:"
echo "   $ZIP_NAME"
echo ""
echo "📋 Files included:"
echo "   • suspicious_hidden_analysis.txt"
echo "   • launch_agents_report.txt"
echo "   • temp_hidden_files.txt"
echo "   • network_connections.txt"
echo "   • hidden_processes.txt"
echo "   • extended_attributes.txt"
echo "   • 00_README.txt - Instructions for analysis"
echo ""
echo "🔍 Send this ZIP file for security analysis."
echo ""