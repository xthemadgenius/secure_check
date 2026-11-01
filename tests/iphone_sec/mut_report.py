"""Mutants for the report / ZIP / ending / output-path code: (id, description, old text (exactly once), replacement, tests expected to fail)."""

CHECK_PREFIX = '    if [[ -L "$target" ]]; then\n        plain=0\n    elif'

MUTANTS = [
    # --- ZIP ---
    ("zipNotReplaced", "an older ZIP of the same name is added to instead of replaced",
     'zip would add to it instead of replacing it\nrm -f "$ZIP_PATH"\n', 'zip would add to it instead of replacing it\n', ["R01"]),
    ("zipStatusIgnored", "a zip that fails after leaving a file is accepted",
     'if [[ "$ZIP_STATUS" -ne 0 || ! -f "$ZIP_PATH" ]]; then', 'if [[ ! -f "$ZIP_PATH" ]]; then', ["R08"]),
    ("zipFileIgnored", "a zip that says it worked but made nothing is accepted",
     'if [[ "$ZIP_STATUS" -ne 0 || ! -f "$ZIP_PATH" ]]; then', 'if [[ "$ZIP_STATUS" -ne 0 ]]; then', ["R08"]),
    ("partialZipKept", "a broken ZIP is left on the Desktop after a failure",
     'if [[ "$ZIP_STATUS" -ne 0 || ! -f "$ZIP_PATH" ]]; then\n    rm -f "$ZIP_PATH"\n',
     'if [[ "$ZIP_STATUS" -ne 0 || ! -f "$ZIP_PATH" ]]; then\n    :\n', ["R08"]),
    ("umaskOpen", "files are created readable by everyone", 'umask 077   # the report', 'umask 022   # the report', ["R01"]),

    # --- counts and verdict ---
    ("weightIgnored", "'...and N more' counts as one item",
     'REVIEW)   colour="$YELLOW"; N_REVIEW=$((N_REVIEW + weight)) ;;', 'REVIEW)   colour="$YELLOW"; N_REVIEW=$((N_REVIEW + 1)) ;;', ["R03"]),
    ("unknownNoVerdict", "UNKNOWN items do not change the verdict",
     'if [[ "$N_REVIEW" -gt 0 || "$N_UNKNOWN" -gt 0 ]]; then', 'if [[ "$N_REVIEW" -gt 0 ]]; then', ["R02", "R03"]),
    ("reviewNoVerdict", "REVIEW items do not change the verdict",
     'if [[ "$N_REVIEW" -gt 0 || "$N_UNKNOWN" -gt 0 ]]; then', 'if [[ "$N_UNKNOWN" -gt 0 ]]; then', ["R02", "R03"]),

    # --- checklist ---
    ("item4Dropped", "checklist item 4 is missing",
     '    echo "  4. Find My: Settings > tap your name > Find My > Find My iPhone. It should be On."\n'
     '    echo "     It is how you locate or lock the phone if it is lost or stolen."\n', '', ["R04"]),
    ("item3Misnumbered", "checklist item 3 is numbered 4", 'echo "  3. Apple Account:', 'echo "  4. Apple Account:', ["R04"]),
    ("profPluralBroken", "'1 configuration profiles' style plural in the VPN item",
     '$(plural "$PROF_TOTAL" "configuration profile" "configuration profiles")',
     '$(plural "$PROF_TOTAL" "configuration profile" "configuration profile")', ["R05"]),
    ("appPluralBroken", "'27 app not signed' style plural in the VPN item",
     'This scan found $APP_TOTAL $(plural "$APP_TOTAL" app apps) not signed', 'This scan found $APP_TOTAL $(plural "$APP_TOTAL" app app) not signed', ["R05"]),
    ("ninthNever", "the 'run this scan again' item never appears",
     '    if [[ "$N_UNKNOWN" -gt 0 ]]; then\n        echo "  9. Run this scan again:"',
     '    if false; then\n        echo "  9. Run this scan again:"', ["R05"]),
    ("ninthAlways", "the 'run this scan again' item always appears",
     '    if [[ "$N_UNKNOWN" -gt 0 ]]; then\n        echo "  9. Run this scan again:"',
     '    if true; then\n        echo "  9. Run this scan again:"', ["R04"]),
    ("profHintAlways", "the profile hint appears even with no profiles",
     '    if [[ "$PROF_TOTAL" -gt 0 ]]; then\n        echo "     This scan found $PROF_TOTAL',
     '    if true; then\n        echo "     This scan found $PROF_TOTAL', ["R04"]),
    ("appHintAlways", "the app hint appears even with no flagged apps",
     '    if [[ "$APP_TOTAL" -gt 0 ]]; then\n        echo "     This scan found $APP_TOTAL',
     '    if true; then\n        echo "     This scan found $APP_TOTAL', ["R04"]),
    ("profHintNever", "the profile hint never appears",
     '    if [[ "$PROF_TOTAL" -gt 0 ]]; then\n        echo "     This scan found $PROF_TOTAL',
     '    if false; then\n        echo "     This scan found $PROF_TOTAL', ["R05"]),
    ("appHintNever", "the app hint never appears",
     '    if [[ "$APP_TOTAL" -gt 0 ]]; then\n        echo "     This scan found $APP_TOTAL',
     '    if false; then\n        echo "     This scan found $APP_TOTAL', ["R05"]),

    # --- report content ---
    ("limitDropped", "one 'cannot see' line is missing", '    echo "  Jailbreak status cannot be reliably detected over USB."\n', '', ["R02"]),
    ("headerPhoneDropped", "the Phone line is missing from the report",
     '        echo "Phone: $PHONE_NAME - $PHONE_MODEL - iOS $PHONE_IOS${PHONE_BUILD:+ ($PHONE_BUILD)}"\n', '', ["R02"]),
    ("headerPreparedDropped", "the Prepared for line is missing from the report", '        echo "Prepared for: $USER_NAME"\n', '', ["R02"]),
    ("reportSummaryDropped", "the report has no summary", '        print_summary "" ""\n', '', ["R02"]),
    ("findingsDropped", "the report has no findings", '        cat "$FINDINGS"\n', '', ["R02", "R03"]),
    ("reportChecklistDropped", "the report has no checklist", '        print_checklist\n        echo ""\n    } > "$REPORT_TMP"', '        echo ""\n    } > "$REPORT_TMP"', ["R02", "R04"]),
    ("reportLimitsDropped", "the report lists no limits", '        echo "WHAT THIS SCAN CANNOT SEE"\n        print_limits\n', '        echo "WHAT THIS SCAN CANNOT SEE"\n', ["R02"]),
    ("screenLimitsDropped", "the screen shows no limits", 'echo -e "${YELLOW}What this scan cannot see:${NC}"\nprint_limits\n', 'echo -e "${YELLOW}What this scan cannot see:${NC}"\n', ["R02"]),

    # --- writing the report ---
    ("moveCheckOff", "a failed move of the report into place is ignored", 'if ! mv -f "$REPORT_TMP" "$REPORT_FILE"; then', 'if false; then', ["R10"]),
    ("writeCheckOff", "a failed write of the report is ignored", 'if ! write_report; then', 'if false; then', ["R10"]),
    ("madeFlagDropped", "the folder the script made is not remembered", '    REPORT_DIR_MADE=1\n', '    :\n', ["R10"]),
    ("cleanupNever", "the folder the script made is left behind", '    [[ "$REPORT_DIR_MADE" -eq 1 && -n "$REPORT_DIR" ]] && rmdir "$REPORT_DIR" 2>/dev/null\n', '', ["R10"]),
    ("cleanupAnyDir", "an existing empty folder is removed too",
     '[[ "$REPORT_DIR_MADE" -eq 1 && -n "$REPORT_DIR" ]] && rmdir', '[[ -n "$REPORT_DIR" ]] && rmdir', ["R11"]),

    # --- the note, the ending and the delete prompt ---
    ("noteAlways", "the 'will be replaced' note always shows", 'if [[ -e "$ZIP_PATH" || -e "$REPORT_FILE" ]]; then', 'if true; then', ["R02"]),
    ("noteNever", "the 'will be replaced' note never shows", 'if [[ -e "$ZIP_PATH" || -e "$REPORT_FILE" ]]; then', 'if false; then', ["R01"]),
    ("noteOnlyZip", "the note ignores an earlier report", 'if [[ -e "$ZIP_PATH" || -e "$REPORT_FILE" ]]; then', 'if [[ -e "$ZIP_PATH" ]]; then', ["R01"]),
    ("noteOnlyReport", "the note ignores an earlier ZIP", 'if [[ -e "$ZIP_PATH" || -e "$REPORT_FILE" ]]; then', 'if [[ -e "$REPORT_FILE" ]]; then', ["R01"]),
    ("deleteWholeFolder", "answering y removes the whole folder",
     '    rm -f "$REPORT_FILE"\n    if rmdir "$REPORT_DIR" 2>/dev/null; then', '    rm -rf "$REPORT_DIR"\n    if [[ ! -e "$REPORT_DIR" ]]; then', ["R07"]),
    ("deleteKeepsReport", "answering y leaves the report in place",
     '    rm -f "$REPORT_FILE"\n    if rmdir "$REPORT_DIR" 2>/dev/null; then', '    :\n    if rmdir "$REPORT_DIR" 2>/dev/null; then', ["R07"]),
    ("deleteByDefault", "the folder is deleted unless you say no",
     'if ask_yn "Delete the folder and keep only the ZIP? (y/n): "; then', 'if true; then', ["R07"]),
    ("nextStep2Dropped", "the 'did NOT pass' next step is missing",
     'echo "   2. An [UNKNOWN] item means a check could not run, so it did NOT pass: run this scan again"\n', '', ["R06"]),

    # --- output path checks ---
    ("linkCheckOff", "a symlink is accepted as an output path", CHECK_PREFIX, '    if false; then\n        plain=0\n    elif', ["R09"]),
    ("kindFolderOff", "a file where the folder should be is accepted",
     '        [[ "$kind" == "folder" && ! -d "$target" ]] && plain=0\n', '', ["R09"]),
    ("kindFileOff", "a folder where a file should be is accepted",
     '        [[ "$kind" == "file" && ! -f "$target" ]] && plain=0\n', '', ["R09"]),
    ("folderCallOff", "the report folder path is not checked",
     'check_output_path "$REPORT_DIR" "$REPORT_SHOWN" folder\n', '', ["R09"]),
    ("zipCallOff", "the ZIP path is not checked",
     'check_output_path "$ZIP_PATH" "~/Desktop/${ZIP_NAME}" file\n', '', ["R09"]),
    ("fileCallOff", "the report file path is not checked",
     'check_output_path "$REPORT_FILE" "${REPORT_SHOWN}/iphone_security_report.txt" file\n', '', ["R09"]),
]
