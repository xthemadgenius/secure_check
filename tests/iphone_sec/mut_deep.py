"""Mutants for the deep scan (STEP 3), the DETECTED handling and the private folder: (id, description, old text (exactly once), replacement, tests expected to fail).
`old` and `new` may both be lists, for a change at several places. An empty expected list means "any test may kill it"."""

DL = '"$MVT" --disable-update-check download-iocs </dev/null >"$TMP_DIR/mvt.log" 2>&1'
BACKUP_CALL = '"$PMD" backup2 backup --udid "$UDID" "$WORK_DIR/backup" </dev/null'
DECRYPT_ARGS = '"$WORK_DIR/decrypted" "$WORK_DIR/backup/$UDID" </dev/null >"$TMP_DIR/mvt.log"'
CHECK_CALL = 'check-backup -o "$WORK_DIR/mvt_results" "$mvt_target" </dev/null >"$WORK_DIR/mvt_console.txt" 2>&1'
PMD_CALL = '"$PMD" "$@" </dev/null >"$TMP_DIR/out" 2>"$TMP_DIR/err"'
DECLINE = ('        finding INFO "The deep scan was not run, so the phone\'s data was not checked against spyware indicators."\n'
           '        return 0\n')
ASK_RE = '[[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]'
IOC_IF = '    if ! "$MVT" --disable-update-check download-iocs </dev/null >"$TMP_DIR/mvt.log" 2>&1; then\n        ioc_failed=1\n    elif grep'
STALE = '        finding INFO "The indicator lists could not be updated, so the copy already on this Mac is used (it may be out of date)."\n'
REC_FAIL = ('                record_action "Tried to turn on backup encryption on the phone; it failed, so the phone\'s setting may or may not have '
            'changed."\n')
REC_NOCONF = ('                record_action "Tried to turn on backup encryption on the phone; the phone did not confirm it, so its setting may or '
              'may not have changed. Check it in Finder."\n')
FAIL_END = ('Check the phone\'s backup setting in Finder: it may have changed. No backup was made."\n'
            '                return 0\n')
NOCONF_END = ('                finding UNKNOWN "The deep scan could not run: the phone did not confirm that backup encryption is on."\n'
              '                return 0\n')
NOPW_SET = '            if [[ -z "$BACKUP_PW" ]]; then\n                finding UNKNOWN "The deep scan could not run: no backup password was set.'
NOPW_GIVEN = '        if [[ -z "$BACKUP_PW" ]]; then\n            finding UNKNOWN "The deep scan could not run: no backup password was given.'
MANIFESTS = '[[ -s "$WORK_DIR/backup/$UDID/Manifest.db" && -s "$WORK_DIR/backup/$UDID/Manifest.plist" ]] && backup_ok=1'
PASS_SET = '        1) PASSCODE_KNOWN=1; finding INFO '
PASS_NONE = '        0) PASSCODE_KNOWN=1; finding REVIEW '
PASS_UNK = '        *) finding UNKNOWN "The backup did not say whether a passcode is set (from the backup)." ;;'
STATE_IF = '    if [[ -n "$why" ]]; then\n        BACKUP_PW=""\n        finding UNKNOWN "The deep scan could not check the backup: its state'
LOOP_FAIL = '            drop_decrypted\n            BACKUP_PW=""\n            attempt=$((attempt + 1))\n'
FIX_ZERO = '        N_FIX=0\n        N_HAND_PROFS=0\n        N_HAND_APPS=0\n'
FIXES_OFF = '    if [[ "$N_DETECTED" -gt 0 ]]; then\n        echo "  Fixes are switched off'
VERDICT_IF = '    if [[ "$N_DETECTED" -gt 0 ]]; then\n        echo "Something known to be linked to spyware was found: do not wipe'
FIRST_STEPS = '    if [[ "$N_DETECTED" -gt 0 ]]; then\n        echo ""\n        printf \'%bWhat to do first:'
FIRST_LINE = 'if [[ "$N_DETECTED" -gt 0 ]]; then\n    echo "   FIRST: Something known'
PRIV_WORDING = '    if [[ "$N_DETECTED" -gt 0 ]]; then\n        PRIV_PROMPT="Delete the private folder anyway?'
PRIV_OUTER = 'if [[ "$BACKUP_STARTED" -eq 1 ]] && safe_work_dir; then\n    PRIV_SIZE='
PRIV_INNER = '        if ! safe_work_dir; then\n            echo -e "${YELLOW}The private folder was not removed because'
RM_ELIF = '        elif rm -rf -- "$WORK_DIR" 2>/dev/null && [[ ! -e "$WORK_DIR" ]]; then'
TAGS = 'ALERT_TAGS = {"CRITICAL": "DETECTED", "HIGH": "DETECTED", "MEDIUM": "REVIEW", "LOW": "INFO"}'
MATCHED = 'and not any(a.get("matched_indicator") for a in alerts):'
SPELLINGS = 'spellings = {secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], repr(secret)[1:-1]}'
SCRUB_ALL = ('sorted({secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1], repr(secret)[1:-1]} - {""}, '
             'key=len, reverse=True)')
SCRUB_LOOP = 'text = text.replace(spelling, "(password)")'
REASON_EMIT = '    emit("REASON", clean(UDID_RE.sub("(phone ID)", pick), 160) or "no details were printed")\n'
CONCLUSION_ELIF = '    elif [[ -n "$conclusion" ]]; then\n        finding INFO "$conclusion"\n    fi\n'

MUTANTS = [
    # --- no tool is ever handed the keyboard (D02d) ---
    ("stdinDownload", "download-iocs gets the keyboard", DL, DL.replace(" </dev/null", ""), ["D02d"]),
    ("stdinBackup", "the backup tool gets the keyboard", BACKUP_CALL, BACKUP_CALL.replace(" </dev/null", ""), ["D02d"]),
    ("stdinDecrypt", "decrypt-backup gets the keyboard", DECRYPT_ARGS, DECRYPT_ARGS.replace(" </dev/null", ""), ["D02d"]),
    ("stdinCheck", "check-backup gets the keyboard", CHECK_CALL, CHECK_CALL.replace(" </dev/null", ""), ["D02d"]),
    ("stdinPmd", "every pmd call gets the keyboard", PMD_CALL, PMD_CALL.replace(" </dev/null", ""), ["D02d"]),
    ("decryptedKept", "the decrypted copy stays until the script ends", '    mvt_status=$?\n    drop_decrypted\n', '    mvt_status=$?\n', ["D04c"]),

    # --- the deep-scan question and the yes/no prompt ---
    ("deepAlwaysAsked", "the deep scan runs without being asked", 'if ! ask_yn "Run the deep scan? (y/n): "; then', 'if false; then', ["D01"]),
    ("declineContinues", "a no still goes on with the scan", DECLINE, DECLINE.replace("return 0", ":"), ["D01"]),
    ("askAnyY", "anything starting with y is a yes", ASK_RE, '[[ "$reply" =~ ^[Yy] ]]', ["D01", "D22"]),
    ("askEnterYes", "Enter alone is a yes", ASK_RE, '[[ -z "$reply" || "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]', ["D22", "D01"]),
    ("askEofYes", "end of input is a yes", '    else\n        echo ""\n    fi\n    ' + ASK_RE, '    else\n        echo ""\n        reply=y\n    fi\n    ' + ASK_RE, ["D22", "D01"]),
    ("askNoNewline", "piped answers are not followed by a new line",
     '        [[ -t 0 ]] || echo ""   # a terminal shows the Enter key as a new line; piped input does not\n', '        :\n', []),

    # --- the indicator lists (D03, D03b) ---
    ("iocExitIgnored", "a failed download-iocs exit status is ignored", IOC_IF, DL.join(['    ', '\n    if false; then\n        ioc_failed=1\n    elif grep']), ["D03"]),
    ("iocTextIgnored", "an error printed by a download that exits 0 is ignored",
     '    elif grep -Eq \'^(ERROR|CRITICAL)[[:space:]]\' "$TMP_DIR/mvt.log"; then', '    elif false; then', ["D03"]),
    ("iocCheckSkipped", "no indicator files does not stop the scan", '    if [[ "$have_iocs" -eq 0 ]]; then', '    if false; then', ["D03", "D03b"]),
    ("iocStaleDropped", "an old copy of the lists is used without saying so", STALE, '        :\n', ["D03"]),
    ("iocGlobAll", "any file in the indicators folder counts", '    for f in "$ioc_dir"/*.stix2; do', '    for f in "$ioc_dir"/*; do', ["D03", "D03b"]),
    ("iocTestE", "a folder named like an indicator file counts", '        [[ -f "$f" ]] && have_iocs=1', '        [[ -e "$f" ]] && have_iocs=1', []),
    ("iocEnvIgnored", "MVT_DATA_FOLDER is not looked at", 'local ioc_dir="${MVT_DATA_FOLDER:-$HOME/Library/Application Support/mvt}/indicators"',
     'local ioc_dir="$HOME/Library/Application Support/mvt/indicators"', []),
    ("iocDefaultDir", "the default data folder is wrong", 'Application Support/mvt}/indicators"', 'Application Support/mvt_x}/indicators"', []),
    ("iocWhyConstant", "the download error is never shown", '        ioc_why="$(reason_of "$TMP_DIR/mvt.log")"', '        ioc_why="no indicator files were found"', ["D03"]),
    ("iocWhyAlways", "the empty-folder reason is replaced by the log", '        ioc_why="no indicator files were found"\n',
     '        ioc_why="$(reason_of "$TMP_DIR/mvt.log")"\n', ["D03"]),

    # --- backup encryption ---
    ("encAnswerIgnored", "an unreadable WillEncrypt answer does not stop the scan", '    if [[ -z "$ENC_NOW" ]]; then', '    if false; then', ["D15"]),
    ("encPromptSkipped", "encryption is turned on without asking", '        if ask_yn "Turn on backup encryption? (y/n): "; then', '        if true; then', ["D22"]),
    ("encNoDashDash", "a password starting with - is read as an option", '-b "$WORK_DIR" -- on "$BACKUP_PW"', '-b "$WORK_DIR" on "$BACKUP_PW"', ["D04"]),
    ("decryptPwOnArgv", "the password is also put on the decrypt command line", 'decrypt-backup -d "$WORK_DIR/decrypted"',
     'decrypt-backup -p "$BACKUP_PW" -d "$WORK_DIR/decrypted"', ["D04", "D06"]),
    ("pwExported", "the password is exported to every program", '                BACKUP_PW="$pw1"\n', '                BACKUP_PW="$pw1"; export BACKUP_PW\n', ["D04", "D06"]),
    ("encNoConfirm", "the phone's confirmation is assumed", '            [[ "$enc_status" -eq 0 ]] && will_encrypt\n',
     '            ENC_NOW=1\n', ["D23"]),
    ("encStatusIgnored", "a failed encryption call is taken as success", '            if [[ "$enc_status" -ne 0 ]]; then\n',
     '            if [[ "$enc_status" -eq 99 ]]; then\n', ["D19"]),
    ("encConfirmAfterFail", "the phone is asked about encryption even after the call failed", '[[ "$enc_status" -eq 0 ]] && will_encrypt',
     'will_encrypt', ["D19"]),
    # stopped in the middle of turning encryption on: the screen says the phone's setting may have changed, and says nothing once it is settled
    ("encPendingNeverSet", "the script does not know it is turning encryption on", '            ENC_PENDING=1\n', '', ["D18c"]),
    ("encPendingNeverCleared", "the script still thinks it is turning encryption on afterwards", '            ENC_PENDING=0\n', '', ["D18c"]),
    ("encPendingEndsBeforeConfirm", "the phone's confirmation is not covered by the note",
     '            [[ "$enc_status" -eq 0 ]] && will_encrypt\n            ENC_PENDING=0\n',
     '            ENC_PENDING=0\n            [[ "$enc_status" -eq 0 ]] && will_encrypt\n', ["D18c"]),
    ("encPendingNoNote", "the note is never shown", 'if [[ "$ENC_PENDING" -eq 1 ]]; then', 'if [[ "$ENC_PENDING" -eq 2 ]]; then', ["D18c"]),
    ("encFailNoRecord", "a failed attempt is not in ACTIONS TAKEN", REC_FAIL, '                :\n', ["D19"]),
    ("encFailKeepsFolder", "the empty private folder stays after a failed attempt", REC_FAIL + '                drop_work_dir\n', REC_FAIL + '                :\n', ["D19"]),
    ("encFailContinues", "the scan goes on after a failed attempt", FAIL_END, FAIL_END.replace("return 0", ":"), ["D19"]),
    ("encFailPwShown", "the password is not hidden in the failure reason", 'fail_why="$(reason_of "$TMP_DIR/err" "$BACKUP_PW")"',
     'fail_why="$(reason_of "$TMP_DIR/err")"', ["D19c"]),
    ("encNoConfNoRecord", "an unconfirmed attempt is not in ACTIONS TAKEN", REC_NOCONF, '                :\n', ["D23"]),
    ("encNoConfKeepsFolder", "the empty private folder stays after an unconfirmed attempt", REC_NOCONF + '                drop_work_dir\n', REC_NOCONF + '                :\n', ["D23"]),
    ("encNoConfContinues", "the scan goes on after an unconfirmed attempt", NOCONF_END, NOCONF_END.replace("return 0", ":"), ["D23"]),
    ("decryptPwShown", "the password is not hidden in MVT's reason", 'why="$(reason_of "$TMP_DIR/mvt.log" "$BACKUP_PW")"',
     'why="$(reason_of "$TMP_DIR/mvt.log")"', ["D07c"]),
    # a password the tool printed back is hidden by the helper, in every spelling, before the text is trimmed, matched or cut short
    ("reasonNoSecret", "the helper does not look for a password to hide", 'secret = os.environ.get("SECRET_TEXT", "")', 'secret = ""', ["D19c", "D07c"]),
    ("reasonSecretNotSent", "the password is not handed to the helper",
     'out="$(SECRET_TEXT="${2-}" "$PY" -I -c "$PYHELPER" reason < "$1" 2>/dev/null)"', 'out="$("$PY" -I -c "$PYHELPER" reason < "$1" 2>/dev/null)"', ["D19c", "D07c"]),
    ("reasonPwOnArgv", "the password is also put on the helper's command line",
     ['def cmd_reason():', 'reason < "$1" 2>/dev/null)" || out=""'], ['def cmd_reason(*_):', 'reason "${2-}" < "$1" 2>/dev/null)" || out=""'], ["D19c", "D07c"]),
    ("scrubRawOnly", "only the password as typed is hidden", SPELLINGS, 'spellings = {secret}', ["D19c", "D07c"]),
    ("scrubNoRepr", "the password in Python's quoting is not hidden", SPELLINGS,
     'spellings = {secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]}', ["D19c", "D07c"]),
    ("scrubNoJsonBoth", "the password in JSON's quoting is not hidden", SPELLINGS, 'spellings = {secret, repr(secret)[1:-1]}', ["D19c", "D07c"]),
    ("scrubNoJsonAscii", "the password in JSON's \\u00e4 quoting is not hidden", SPELLINGS,
     'spellings = {secret, json.dumps(secret, ensure_ascii=False)[1:-1], repr(secret)[1:-1]}', ["D19c", "D07c"]),
    ("scrubNoJsonUnicode", "the password in JSON's unescaped-letters quoting is not hidden", SPELLINGS,
     'spellings = {secret, json.dumps(secret)[1:-1], repr(secret)[1:-1]}', ["D19c", "D07c"]),
    ("stripBeforeScrub", "each line is trimmed before the password is looked for", 'text = sys.stdin.read()\n    # A password the tool printed back',
     'text = "\\n".join(ln.strip() for ln in sys.stdin.read().splitlines())\n    # A password the tool printed back', ["D19c", "D07c"]),
    ("scrubAfterLevel", "the password is hidden only after the message is picked out of the line", [SCRUB_LOOP, REASON_EMIT],
     ['pass', '    for spelling in ' + SCRUB_ALL + ':\n        pick = pick.replace(spelling, "(password)")\n' + REASON_EMIT], ["D19c", "D07c"]),
    ("scrubAfterCap", "the password is hidden only after the text is cut short", [SCRUB_LOOP, REASON_EMIT],
     ['pass', '    shown = clean(UDID_RE.sub("(phone ID)", pick), 160)\n    for spelling in ' + SCRUB_ALL + ':\n        shown = shown.replace(spelling, "(password)")\n'
              '    emit("REASON", shown or "no details were printed")\n'], ["D19c", "D07c"]),
    ("emptyPwAccepted", "an empty new password is accepted", '                if [[ -z "$pw1" ]]; then', '                if false; then', ["D21"]),
    ("mismatchAccepted", "two different passwords are accepted", '                if [[ "$HIDDEN_REPLY" != "$pw1" ]]; then', '                if false; then', ["D21"]),
    ("tries4", "four tries at a new password", '"$tries" -lt 3 ]]', '"$tries" -lt 4 ]]', ["D21"]),
    ("tries2", "two tries at a new password", '"$tries" -lt 3 ]]', '"$tries" -lt 2 ]]', ["D21"]),
    ("noPwSetSkipped", "no password set does not stop the scan", NOPW_SET, NOPW_SET.replace('if [[ -z "$BACKUP_PW" ]]; then', 'if false; then', 1), ["D21"]),
    ("noPwGivenSkipped", "no password given does not stop the scan", NOPW_GIVEN, NOPW_GIVEN.replace('if [[ -z "$BACKUP_PW" ]]; then', 'if false; then', 1), ["D08"]),
    ("encSwapped", "true and false are swapped", 'emit("ENC", "1" if raw == "true" else "0")', 'emit("ENC", "0" if raw == "true" else "1")', ["D15", "D04", "D22"]),
    ("encAnyAnswer", "any answer other than true counts as false", '    elif raw in ("true", "false"):', '    elif True:', ["D15"]),
    ("encCrashZero", "an unreadable answer counts as no encryption", '        *)   ENC_WHY="its answer could not be read" ;;',
     '        *)   ENC_WHY="its answer could not be read"; ENC_NOW=0 ;;', ["D40", "D15"]),
    ("encErrZero", "an error answer counts as no encryption", '        ERR) ENC_WHY="$f1" ;;', '        ERR) ENC_WHY="$f1"; ENC_NOW=0 ;;', ["D15"]),
    ("encOnMsgDropped", "'Backup encryption is now on' is not said", '            echo -e "${GREEN}Backup encryption is now on.${NC}"\n', '            :\n', ["D02"]),
    ("encOnRecordDropped", "turning encryption on is not in ACTIONS TAKEN",
     '            record_action "Turned on backup encryption on the phone (a backup password you chose; it stays until you turn it off)."\n', '            :\n', ["D04"]),
    ("resetHintDropped", "the forgotten-password help is not shown",
     '        echo "If you do not remember it: Settings > General > Transfer or Reset iPhone > Reset > Reset All Settings."\n', '        :\n', ["D02c"]),
    ("encWhyDropped", "the reason a WillEncrypt read failed is not shown", '        ENC_WHY="$(reason_of "$TMP_DIR/err")"\n', '        ENC_WHY="x"\n', ["D15"]),
    ("encNoUdid", "WillEncrypt is asked without the phone's ID", 'pmd lockdown get --udid "$UDID" com.apple.mobile.backup WillEncrypt',
     'pmd lockdown get com.apple.mobile.backup WillEncrypt', ["D02", "D06", "D22"]),
    ("encOnNoUdid", "encryption is turned on without the phone's ID", 'pmd backup2 encryption --udid "$UDID" -b', 'pmd backup2 encryption -b', []),
    ("backupNoUdid", "the backup is made without the phone's ID", '"$PMD" backup2 backup --udid "$UDID" "$WORK_DIR/backup"', '"$PMD" backup2 backup "$WORK_DIR/backup"', ["D02", "D06", "D22"]),

    # --- the backup ---
    ("manifestDbUnchecked", "an empty Manifest.db passes", MANIFESTS, '[[ -s "$WORK_DIR/backup/$UDID/Manifest.plist" ]] && backup_ok=1', ["D11"]),
    ("manifestPlistUnchecked", "an empty Manifest.plist passes", MANIFESTS, '[[ -s "$WORK_DIR/backup/$UDID/Manifest.db" ]] && backup_ok=1', ["D11"]),
    ("backupFilesUnchecked", "any backup passes", MANIFESTS, 'backup_ok=1', ["D11"]),
    ("backupExitIgnored", "a backup tool that reports failure passes",
     '    if ' + BACKUP_CALL + '; then\n', '    ' + BACKUP_CALL + '\n    if true; then\n', ["D11"]),
    ("backupNotMarked", "a started backup is not remembered", '    BACKUP_STARTED=1\n    if "$PMD"', '    BACKUP_STARTED=0\n    if "$PMD"', ["D18", "D17", "D13"]),
    ("partialFolderHidden", "the partial backup's folder is not shown", 'The partial backup is in the private folder: $(tilde_path "$WORK_DIR")"',
     'The partial backup is in the private folder."', ["D11"]),
    ("passcodeSwapped", "passcode set and not set are swapped", [PASS_SET, PASS_NONE], ['        0) PASSCODE_KNOWN=1; finding INFO ', '        1) PASSCODE_KNOWN=1; finding REVIEW '], ["D12"]),
    ("passcodeSetNotKnown", "a set passcode is not marked as checked", PASS_SET, '        1) finding INFO ', ["D12"]),
    ("passcodeNoneNotKnown", "no passcode is not marked as checked", PASS_NONE, '        0) finding REVIEW ', ["D12"]),
    ("passcodeUnknownKnown", "an unreadable passcode flag is marked as checked", PASS_UNK, PASS_UNK.replace("*) finding", "*) PASSCODE_KNOWN=1; finding"), ["D12"]),
    ("backupOutputHidden", "the backup tool's messages are hidden", BACKUP_CALL, BACKUP_CALL + ' >/dev/null 2>&1', ["D02", "D11"]),
    ("backupRecordDropped", "a finished backup is not in ACTIONS TAKEN",
     '    record_action "Made a backup of the phone into a private folder on this Mac (not part of the ZIP)."\n', '    :\n', []),
    ("backupFailRecordDropped", "an unfinished backup is not in ACTIONS TAKEN",
     '        record_action "Started a backup of the phone into a private folder on this Mac; it did not finish."\n', '        :\n', []),
    ("workDirFailContinues", "a private folder that cannot be made does not stop the scan",
     '            if ! make_work_dir; then\n                BACKUP_PW=""\n                finding UNKNOWN "The deep scan could not run: the private folder for the backup could not be made ($WORK_WHY). Nothing was changed on the phone."\n                return 0\n',
     '            if ! make_work_dir; then\n                BACKUP_PW=""\n                finding UNKNOWN "The deep scan could not run: the private folder for the backup could not be made ($WORK_WHY). Nothing was changed on the phone."\n                :\n',
     ["D39"]),

    # --- what the backup says about itself, opening it, MVT ---
    ("stateWhyIgnored", "a backup whose state cannot be read is checked anyway", STATE_IF, STATE_IF.replace('if [[ -n "$why" ]]; then', 'if false; then', 1), ["D41"]),
    ("stateFlagMissingOk", "a backup that does not say if it is encrypted is checked anyway",
     '        STATE) why=""; [[ "$f1" == "?" ]] && why="it did not say whether it is encrypted" ;;', '        STATE) why="" ;;', ["D41"]),
    ("stateErrIgnored", "a Manifest.plist that cannot be read is ignored", '        ERR)   why="$f1" ;;', '        ERR)   why="" ;;', ["D41"]),
    ("stateCrashIgnored", "an unreadable state answer is ignored", '        *)     why="its answer could not be read" ;;', '        *)     why="" ;;', ["D40"]),
    ("attempts4", "four passwords may be tried", 'while [[ "$attempt" -le 3 ]]; do', 'while [[ "$attempt" -le 4 ]]; do', ["D07"]),
    ("attempts2", "two passwords may be tried", 'while [[ "$attempt" -le 3 ]]; do', 'while [[ "$attempt" -le 2 ]]; do', ["D07"]),
    ("wrongPwReused", "a wrong password is tried again", LOOP_FAIL, LOOP_FAIL.replace('            BACKUP_PW=""\n', '', 1), ["D07"]),
    ("decryptedKeptOnFail", "a half-written decrypted copy stays after a failed try", LOOP_FAIL, LOOP_FAIL.replace('            drop_decrypted\n', '', 1), ["D07b"]),
    ("emptyPwKeepsGoing", "an empty password is still tried", '                [[ -z "$BACKUP_PW" ]] && break\n', '                :\n', ["D07"]),
    ("decryptManifestUnchecked", "a decrypt that left nothing counts as opened", '                && [[ -s "$WORK_DIR/decrypted/Manifest.db" ]]; then', '                ; then', ["D07b"]),
    ("mvtOnEncrypted", "MVT is pointed at the encrypted backup", '        mvt_target="$WORK_DIR/decrypted"\n', '        :\n', ["D04", "D06"]),
    ("encryptedUnhandled", "an encrypted backup is treated as plain", '    if [[ "$f1" == "1" ]]; then\n        # Up to 3 passwords', '    if false; then\n        # Up to 3 passwords', ["D04", "D06"]),
    ("mvtStatusZero", "MVT's exit status is not looked at", '    mvt_status=$?\n', '    mvt_status=0\n', ["D24"]),
    ("gotEndIgnored", "a helper that stops part way is not noticed", '    if [[ "$got_end" -eq 0 || "$bad_line" -eq 1 ]]; then', '    if [[ "$bad_line" -eq 1 ]]; then', ["D40"]),
    ("badLineIgnored", "a line the script cannot read is not noticed", '    if [[ "$got_end" -eq 0 || "$bad_line" -eq 1 ]]; then', '    if [[ "$got_end" -eq 0 ]]; then', ["D40"]),
    ("badTagSilent", "a finding with an unknown tag is dropped quietly", '                    *) bad_line=1; continue ;;', '                    *) continue ;;', ["D40"]),
    ("conclusionShownAlways", "'nothing matched' is shown even when the results could not be read", CONCLUSION_ELIF,
     '    fi\n    if [[ -n "$conclusion" ]]; then\n        finding INFO "$conclusion"\n    fi\n', ["D40"]),
    ("conclusionDropped", "'nothing matched' is never shown", 'finding INFO "$conclusion"', ':', ["D40", "D04", "D06", "D07c", "D31", "D35"]),
    ("weightGuardDropped", "a weight that is not a number is used as it is", '                [[ "$weight" =~ ^[0-9]+$ ]] || weight=1\n', '                :\n', ["D40", "D26"]),
    ("weightIgnored", "an alert count line counts as one", '                finding "$tag" "$text" "$((10#$weight))" ;;', '                finding "$tag" "$text" ;;', ["D26"]),
    ("rawInZip", "MVT's console output is put into the ZIP",
     '(cd "$REPORT_DIR" && zip -j "$ZIP_PATH" "$REPORT_NAME") > /dev/null 2>&1',
     '(cd "$REPORT_DIR" && zip -j "$ZIP_PATH" "$REPORT_NAME" ${WORK_DIR:+"$WORK_DIR/mvt_console.txt"}) > /dev/null 2>&1', ["D13", "D16"]),

    # --- DETECTED, the summary, the private folder ---
    ("fixesStayOn", "fixes stay on when something is DETECTED", FIXES_OFF, FIXES_OFF.replace('if [[ "$N_DETECTED" -gt 0 ]]; then', 'if false; then', 1), ["D05b"]),
    ("fixZeroNoFix", "N_FIX is not zeroed when something is DETECTED", FIX_ZERO, '        N_HAND_PROFS=0\n        N_HAND_APPS=0\n', ["D05b"]),
    ("fixZeroNoProfs", "N_HAND_PROFS is not zeroed when something is DETECTED", FIX_ZERO, '        N_FIX=0\n        N_HAND_APPS=0\n', ["D05d"]),
    ("fixZeroNoApps", "N_HAND_APPS is not zeroed when something is DETECTED", FIX_ZERO, '        N_FIX=0\n        N_HAND_PROFS=0\n', ["D05d"]),
    ("verdictBlind", "the verdict ignores DETECTED", VERDICT_IF, VERDICT_IF.replace('if [[ "$N_DETECTED" -gt 0 ]]; then', 'if false; then', 1), ["D05a"]),
    ("noFirstSteps", "'What to do first' is not shown", FIRST_STEPS, FIRST_STEPS.replace('if [[ "$N_DETECTED" -gt 0 ]]; then', 'if false; then', 1), ["D05a"]),
    ("noFirstLine", "the FIRST: line is not shown", FIRST_LINE, FIRST_LINE.replace('if [[ "$N_DETECTED" -gt 0 ]]; then', 'if false; then', 1), ["D05a"]),
    ("privAlwaysDelete", "the private folder is deleted without asking", '    if ask_yn "$PRIV_PROMPT"; then', '    if true; then', ["D17"]),
    ("privInverted", "a no deletes the private folder", '    if ask_yn "$PRIV_PROMPT"; then', '    if ! ask_yn "$PRIV_PROMPT"; then', ["D17"]),
    ("privPlainWording", "the evidence warning is not shown", PRIV_WORDING, PRIV_WORDING.replace('if [[ "$N_DETECTED" -gt 0 ]]; then', 'if false; then', 1), ["D17", "D05a"]),
    ("privOuterGuard", "the private folder is offered even if it is not the one made", PRIV_OUTER, PRIV_OUTER.replace(' && safe_work_dir', '', 1), ["D38b"]),
    ("privInnerGuard", "the private folder is removed even if it is not the one made", PRIV_INNER, PRIV_INNER.replace('if ! safe_work_dir; then', 'if false; then', 1), ["D38"]),
    ("safeNoLink", "a link in place of the private folder passes", '&& -d "$WORK_DIR" && ! -L "$WORK_DIR" ]] || return 1', '&& -d "$WORK_DIR" ]] || return 1', ["D38"]),
    ("workRootLinkOk", "a link as the private folder's parent is followed",
     '    if [[ -L "$WORK_ROOT" || ( -e "$WORK_ROOT" && ! -d "$WORK_ROOT" ) ]]; then', '    if [[ ( -e "$WORK_ROOT" && ! -d "$WORK_ROOT" ) ]]; then', ["D39"]),
    ("workRootFileOk", "a file as the private folder's parent is used",
     '    if [[ -L "$WORK_ROOT" || ( -e "$WORK_ROOT" && ! -d "$WORK_ROOT" ) ]]; then', '    if [[ -L "$WORK_ROOT" ]]; then', ["D39b"]),
    ("umaskOpen", "files are made readable by others", 'umask 077   # the report, backup', 'umask 022   # the report, backup', ["D04", "D06"]),
    ("interruptNoteOff", "an interrupt does not say where the partial backup is",
     '    if [[ "$BACKUP_STARTED" -eq 1 && "$WORK_NOTE_SHOWN" -eq 0 ]] && safe_work_dir; then', '    if false; then', ["D18"]),
    ("workNoteNotMarked", "the folder note is repeated after an interrupt at the last prompt", '    WORK_NOTE_SHOWN=1\n', '    :\n', ["D17", "D13"]),
    ("dropIgnoresBackup", "a partial backup is deleted when the script stops",
     '    if [[ "$BACKUP_STARTED" -eq 0 ]] && safe_work_dir; then\n        rm -rf "$WORK_DIR"', '    if safe_work_dir; then\n        rm -rf "$WORK_DIR"', ["D18"]),
    ("keptNotShown", "keeping the private folder is not acknowledged",
     '        echo -e "${GREEN}The private folder was kept: $(tilde_path "$WORK_DIR")${NC}"\n', '        :\n', ["D17"]),
    ("rmFailureHidden", "a folder that could not be removed is reported as deleted", RM_ELIF, '        elif { rm -rf -- "$WORK_DIR" 2>/dev/null; true; }; then', ["D17c"]),
    ("rmLiar", "a removal that left something behind is reported as deleted", RM_ELIF, '        elif rm -rf -- "$WORK_DIR" 2>/dev/null; then', ["D17c"]),
    ("sizeUntrimmed", "du's padding is kept in the size", '    read -r size _ <<< "$out"', '    size="${out%%[[:space:]]*}"', ["D17b"]),

    # --- the embedded helper: alert levels, counts, cleaning, MVT's log ---
    ("tagHighReview", "HIGH alerts are only REVIEW", TAGS, TAGS.replace('"HIGH": "DETECTED"', '"HIGH": "REVIEW"'), ["D25", "D35"]),
    ("tagCriticalReview", "CRITICAL alerts are only REVIEW", TAGS, TAGS.replace('"CRITICAL": "DETECTED"', '"CRITICAL": "REVIEW"'), ["D25", "D35"]),
    ("tagMediumDetected", "MEDIUM alerts are DETECTED", TAGS, TAGS.replace('"MEDIUM": "REVIEW"', '"MEDIUM": "DETECTED"'), ["D25", "D35"]),
    ("tagLowReview", "LOW alerts are REVIEW", TAGS, TAGS.replace('"LOW": "INFO"', '"LOW": "REVIEW"'), ["D25", "D35"]),
    ("cap24", "24 alerts are listed", 'LIST_CAP = 25', 'LIST_CAP = 24', ["D26"]),
    ("cap26", "26 alerts are listed", 'LIST_CAP = 25', 'LIST_CAP = 26', ["D26"]),
    ("cap50", "50 alerts are listed", 'LIST_CAP = 25', 'LIST_CAP = 50', ["D26"]),
    ("oddDropped", "an alert with an unknown level is dropped", '            odd.append(alert)\n', '            pass\n', ["D27"]),
    ("oddInformational", "an alert with an unknown level is informational", '            odd.append(alert)\n', '            by_level["INFORMATIONAL"].append(alert)\n', ["D27"]),
    ("countMismatchOff", "MVT's counts are not compared with its alerts file", '        if said != listed and state != "unreadable":', '        if False:', ["D28"]),
    ("missingHighReview", "missing HIGH alerts are only REVIEW", '            add(ALERT_TAGS[level], "MVT\'s own summary counts %d more', '            add("REVIEW", "MVT\'s own summary counts %d more', ["D28"]),
    ("missingHighOff", "alerts missing from the alerts file are not noticed", '        if said > listed and level in ("CRITICAL", "HIGH", "MEDIUM"):', '        if False:', ["D28"]),
    ("noConsoleOk", "an MVT summary that cannot be found is fine", '    if not console:\n        add("UNKNOWN", "MVT\'s summary of alerts', '    if False:\n        add("UNKNOWN", "MVT\'s summary of alerts', ["D29"]),
    ("alertsUnreadableOk", "an alerts file that cannot be read is fine",
     '    if state == "unreadable":\n        add("UNKNOWN", "MVT\'s alerts file could not be read', '    if False:\n        add("UNKNOWN", "MVT\'s alerts file could not be read', ["D29"]),
    ("cleanPipeKept", "| is kept in the phone's text", '        if ch == "|":', '        if False:', ["D30"]),
    ("cleanControlKept", "control characters are kept in the phone's text", '        elif unicodedata.category(ch) in UNSAFE_CATEGORIES:', '        elif False:', ["D30"]),
    ("cleanNoCap", "the phone's text is not cut short", '    return text if len(text) <= cap else text[:cap - 3] + "..."', '    return text', ["D30b"]),
    ("maskNoUdid", "the phone's ID is not masked in text from the backup", '    return clean(UDID_RE.sub("(phone ID)", text), cap)', '    return clean(text, cap)', ["D30"]),
    ("reasonNoUdid", "the phone's ID is not masked in a tool's error", 'emit("REASON", clean(UDID_RE.sub("(phone ID)", pick), 160) or "no details were printed")',
     'emit("REASON", clean(pick, 160) or "no details were printed")', ["D19"]),
    ("outdatedIgnored", "MVT's outdated-iOS warning is dropped", '        if outdated:\n            add("REVIEW", "MVT reports:', '        if False:\n            add("REVIEW", "MVT reports:', ["D31"]),
    ("outdatedInfo", "MVT's outdated-iOS warning is only INFO", '            add("REVIEW", "MVT reports: %s. Update it', '            add("INFO", "MVT reports: %s. Update it', ["D31"]),
    ("outdatedHidesClean", "a REVIEW item hides the 'nothing matched' line", 'and "DETECTED" not in found and not any(', 'and "DETECTED" not in found and "REVIEW" not in found and not any(', ["D31"]),
    ("zeroLoadedOk", "zero indicators loaded is fine", '        if not loaded:\n            add("UNKNOWN", "MVT did not report loading any indicators',
     '        if loaded is None:\n            add("UNKNOWN", "MVT did not report loading any indicators', ["D32"]),
    ("loadedNeverChecked", "indicators that never loaded are fine", '        if not loaded:\n            add("UNKNOWN", "MVT did not report loading any indicators',
     '        if False:\n            add("UNKNOWN", "MVT did not report loading any indicators', ["D32"]),
    ("noInfoJsonOk", "a run without its completion marker is fine", '    if not os.path.isfile(os.path.join(results_dir, "info.json")):', '    if False:', ["D33"]),
    ("noLogOk", "a log that cannot be read is fine", '        add("UNKNOWN", "MVT\'s log could not be read, so it is not known whether every check ran.")', '        pass', ["D33"]),
    ("errorLevelOnly", "a CRITICAL log line is not an error", '            if level in ("ERROR", "CRITICAL"):', '            if level in ("ERROR",):', ["D34"]),
    ("echoDedupeOff", "an alert's own log line counts as an error", '            if text in echoed:\n                continue\n', '            if False:\n                continue\n', ["D34"]),
    ("errorsRepeat", "the same logged error is listed again", '                if text not in errors:\n                    errors.append(text)', '                if True:\n                    errors.append(text)', ["D34"]),
    ("errorsUncapped", "every logged error is listed", '        for text in errors[:LIST_CAP]:', '        for text in errors:', ["D34"]),
    ("matchedLowIgnored", "a matched indicator on a LOW alert does not stop the clean line", MATCHED, 'and not False:', ["D35"]),
    ("exitCodeIgnored", "an MVT that exits non-zero is fine", '    if code != 0:\n        add("UNKNOWN", "MVT did not finish normally', '    if False:\n        add("UNKNOWN", "MVT did not finish normally', ["D24"]),
    ("infoCountAlertsOnly", "informational alerts are counted from the alerts file only",
     '    n_info = max(len(by_level["INFORMATIONAL"]), console.get("INFORMATIONAL", 0))', '    n_info = len(by_level["INFORMATIONAL"])', ["D25"]),
]
