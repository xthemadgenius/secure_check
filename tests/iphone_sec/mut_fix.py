"""Mutants for the APPLY=1 fix flow and the plain-ID rule: (id, description, old text (exactly once), replacement, tests expected to fail).
`old` and `new` may both be lists, for a change at several places."""

GATE = 'if [[ "$N_FIX" -gt 0 && "$APPLY" != "1" ]]; then'
HEADER = 'if [[ "$N_FIX" -gt 0 || "$N_HAND_PROFS" -gt 0 || "$N_HAND_APPS" -gt 0 ]]; then'
ASK = r'if ask_yn "Remove the $what \"$f2\" ($f1) from the phone? $effect (y/n): "; then'
KEPT = r'echo "Kept: $what \"$f2\" ($f1) was not removed."'
SAFE = 'SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")'
FIXABLE = 'return "1" if SAFE_ID_RE.fullmatch(ident) else "0"'
APP_FLAG = 'flagged.append((clean(name), clean(bundle), clean(signer), fixable(bundle)))'
PROF_FLAG = 'clean(entry.get("PayloadOrganization")) or "an unknown organisation", fixable(ident))'
PROF_ADD = '                if [[ "$f4" == "1" ]]; then\n                    FIX_ITEMS="${FIX_ITEMS}P|$f1|$f2"$\'\\n\'\n'
APP_ADD = '                if [[ "$f4" == "1" ]]; then\n                    FIX_ITEMS="${FIX_ITEMS}A|$f1|$f2"$\'\\n\'\n'
APP_BLOCK = APP_ADD + '                    N_FIX_APPS=$((N_FIX_APPS + 1))\n                fi\n'
PROF_BLOCK = PROF_ADD + '                    N_FIX_PROFS=$((N_FIX_PROFS + 1))\n                fi\n'
APP_RELIST = 'pmd apps list --type Any --udid "$UDID" || { echo "?"; return; }'
PROF_RELIST = 'pmd profile list --udid "$UDID" || { echo "?"; return; }'
APP_PROBE = 'out="$(helper apps "$id" < "$TMP_DIR/out" 2>/dev/null)" || out=""'
PROF_PROBE = 'out="$(helper profiles "$id" < "$TMP_DIR/out" 2>/dev/null)" || out=""'
APP_RM = 'pmd apps uninstall --udid "$UDID" "$id" || why="$(reason_of "$TMP_DIR/err")"'
PROF_RM = 'pmd profile remove --udid "$UDID" "$id" || why="$(reason_of "$TMP_DIR/err")"'
CASE = 'case "$(still_installed "$kind" "$id")" in'
SEEN_PROFS = 'emit("SEEN", "1" if probe in ids else "0")'
SEEN_APPS = 'emit("SEEN", "1" if probe in data else "0")'
PASSCODE = '        echo "  If the phone asks for its passcode, enter it on the phone."\n'
ONSCREEN = '            echo "  The summary below shows the phone as it was when scanned, before these changes."\n'
IN_REPORT = '            echo "The findings and counts above show the phone as it was when scanned, before these changes:"\n'
HAND_APPS_LINE = '    if [[ "$N_HAND_APPS" -gt 0 ]]; then\n        echo "  $N_HAND_APPS flagged'
HAND_PROFS_LINE = '    if [[ "$N_HAND_PROFS" -gt 0 ]]; then\n        echo "  $N_HAND_PROFS flagged'
DRY_HINT = '        echo "  To be asked about removing each one, run this script again as:  APPLY=1 ./iphone_sec.sh"\n'
DRY_COUNT = '        echo "  $N_FIX flagged $(plural "$N_FIX" item items) can be removed from here."\n'
SCREEN_IF = '        if [[ -s "$ACTIONS" ]]; then\n            echo "  The summary below shows'
REPORT_IF = '        if [[ -s "$ACTIONS" ]]; then\n            echo "The findings and counts'

MUTANTS = [
    # --- APPLY=1 is the only switch ---
    ("applyDefaultOn", "APPLY defaults to on", 'APPLY="${APPLY:-0}"', 'APPLY="${APPLY:-1}"', ["X01"]),
    ("applyAnyValue", "any APPLY value other than 0 turns removal on", GATE, 'if [[ "$N_FIX" -gt 0 && "$APPLY" == "0" ]]; then', ["X01"]),
    ("applyNever", "APPLY=1 never gets as far as the prompts", GATE, 'if [[ "$N_FIX" -gt 0 ]]; then', ["X02"]),
    ("applyAlways", "removal is offered even without APPLY=1", GATE, 'if false; then', ["X01"]),

    # --- the question and its answers ---
    ("promptSkipped", "items are removed without asking", ASK, 'if true; then', ["X06", "X02"]),
    ("promptInverted", "a y keeps the item and a n removes it", ASK, ASK.replace("if ask_yn", "if ! ask_yn"), ["X02", "X06"]),
    ("removeOnNo", "the item is removed after a no as well", KEPT, 'remove_item "$kind" "$f1" "$f2"', ["X02", "X06"]),
    ("keptNotShown", "a no is not acknowledged", KEPT, ':', ["X02", "X06"]),
    ("keptRecorded", "a no is written into ACTIONS TAKEN", KEPT, KEPT + '; record_action "Kept $what ($f1)."', ["X06", "X02"]),
    ("loopOnFd0", "the item list is read from the keyboard's stream, so it eats the answers",
     ["while IFS='|' read -r -u 3 kind f1 f2; do", 'done 3<<< "$FIX_ITEMS"'],
     ["while IFS='|' read -r kind f1 f2; do", 'done <<< "$FIX_ITEMS"'], ["X02", "X06"]),
    ("loopReadsKeyboard", "the item list is read from the keyboard",
     "while IFS='|' read -r -u 3 kind f1 f2; do", "while IFS='|' read -r kind f1 f2; do", ["X02"]),
    ("blankItemAsks", "the empty last line of the list is asked about with the last item's words",
     '                *) continue ;;', '                *) ;;', ["X12", "X02"]),
    ("nameAndIdSwapped", "the name is passed where the ID belongs", 'remove_item "$kind" "$f1" "$f2"', 'remove_item "$kind" "$f2" "$f1"', ["X02"]),
    ("profileEffectWrong", "the profile prompt carries the app warning",
     'P) what="configuration profile"; effect="Settings it applied stop working." ;;',
     'P) what="configuration profile"; effect="Its data on the phone is deleted." ;;', ["X14", "X13"]),
    ("appEffectWrong", "the app prompt carries the profile warning",
     'A) what="app"; effect="Its data on the phone is deleted." ;;', 'A) what="app"; effect="Settings it applied stop working." ;;', ["X02", "X06"]),

    # --- which IDs are ever put on a command line ---
    ("idLeadingPunct", "an ID may start with a dash, dot or underscore", SAFE, 'SAFE_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,80}")', ["X04"]),
    ("idTooLong", "an ID may be 90 characters", SAFE, 'SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,89}")', ["X04"]),
    ("idTooShort", "an 80-character ID is refused", SAFE, 'SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,78}")', ["X04"]),
    ("idWordChars", "an ID may hold any letter, including non-ASCII", SAFE, 'SAFE_ID_RE = re.compile(r"[A-Za-z0-9][\\w.-]{0,79}")', ["X04"]),
    ("idPrefixOnly", "only the start of an ID has to be plain", FIXABLE, 'return "1" if SAFE_ID_RE.match(ident) else "0"', ["X04"]),
    ("idTrailingNewline", "an ID may end with a newline", FIXABLE, 'return "1" if re.match(SAFE_ID_RE.pattern + "$", ident) else "0"', ["X04"]),
    ("fixableInverted", "plain IDs are refused and the others offered", FIXABLE, 'return "0" if SAFE_ID_RE.fullmatch(ident) else "1"', ["X04", "X02"]),
    ("appChecksCleanedId", "the app's ID is judged after it was cut to 80 characters", APP_FLAG,
     'flagged.append((clean(name), clean(bundle), clean(signer), fixable(clean(bundle))))', ["X04"]),
    ("profChecksCleanedId", "the profile's ID is judged after it was cut to 80 characters", PROF_FLAG,
     'clean(entry.get("PayloadOrganization")) or "an unknown organisation", fixable(clean(ident)))', ["X04"]),
    ("appAlwaysFixable", "every flagged app is offered", APP_FLAG, 'flagged.append((clean(name), clean(bundle), clean(signer), "1"))', ["X04"]),
    ("profAlwaysFixable", "every profile is offered", PROF_FLAG, 'clean(entry.get("PayloadOrganization")) or "an unknown organisation", "1")', ["X04"]),
    ("appNeverFixable", "no flagged app is offered", APP_FLAG, 'flagged.append((clean(name), clean(bundle), clean(signer), "0"))', ["X02"]),
    ("profNeverFixable", "no profile is offered", PROF_FLAG, 'clean(entry.get("PayloadOrganization")) or "an unknown organisation", "0")', ["X14"]),
    ("appFlagIgnored", "the shell offers an app whatever the helper said about its ID",
     APP_ADD, APP_ADD.replace('if [[ "$f4" == "1" ]]; then', 'if true; then'), ["X04"]),
    ("profFlagIgnored", "the shell offers a profile whatever the helper said about its ID",
     PROF_ADD, PROF_ADD.replace('if [[ "$f4" == "1" ]]; then', 'if true; then'), ["X04"]),
    ("appsOfferedBeyondCap", "apps that are counted but not listed are offered as well",
     ['            APP_TOTAL=$((APP_TOTAL + 1))\n            if [[ "$APP_SHOWN" -lt "$MAX_LISTED" ]]; then\n', APP_BLOCK],
     ['            APP_TOTAL=$((APP_TOTAL + 1))\n' + APP_BLOCK.replace("\n    ", "\n").replace("                if", "            if", 1)
      + '            if [[ "$APP_SHOWN" -lt "$MAX_LISTED" ]]; then\n', ''], ["X12"]),
    ("profsOfferedBeyondCap", "profiles that are counted but not listed are offered as well",
     ['            PROF_TOTAL=$((PROF_TOTAL + 1))\n            if [[ "$PROF_SHOWN" -lt "$MAX_LISTED" ]]; then\n', PROF_BLOCK],
     ['            PROF_TOTAL=$((PROF_TOTAL + 1))\n' + PROF_BLOCK.replace("\n    ", "\n").replace("                if", "            if", 1)
      + '            if [[ "$PROF_SHOWN" -lt "$MAX_LISTED" ]]; then\n', ''], ["X12"]),

    # --- counting what is offered and what is left to you ---
    ("appFixNotCounted", "an offered app is not counted as offered", '                    N_FIX_APPS=$((N_FIX_APPS + 1))\n', '                    :\n', ["X01", "X02"]),
    ("profFixNotCounted", "an offered profile is not counted as offered", '                    N_FIX_PROFS=$((N_FIX_PROFS + 1))\n', '                    :\n', ["X01", "X14"]),
    ("handAppsIgnoreCap", "apps beyond the listed ones are not counted for you", 'N_HAND_APPS=$((APP_TOTAL - N_FIX_APPS))',
     'N_HAND_APPS=$((APP_SHOWN - N_FIX_APPS))', ["X12"]),
    ("handProfsIgnoreCap", "profiles beyond the listed ones are not counted for you", 'N_HAND_PROFS=$((PROF_TOTAL - N_FIX_PROFS))',
     'N_HAND_PROFS=$((PROF_SHOWN - N_FIX_PROFS))', ["X12"]),
    ("handAppsZero", "apps with an ID that is not plain are not counted for you", 'N_HAND_APPS=$((APP_TOTAL - N_FIX_APPS))', 'N_HAND_APPS=0', ["X04"]),
    ("handProfsAll", "every profile is counted as left to you", 'N_HAND_PROFS=$((PROF_TOTAL - N_FIX_PROFS))', 'N_HAND_PROFS=$PROF_TOTAL', ["X04", "X14"]),
    ("handAppsLineDropped", "no by-hand line for apps", HAND_APPS_LINE, '    if false; then\n        echo "  $N_HAND_APPS flagged', ["X04", "X12"]),
    ("handProfsLineDropped", "no by-hand line for profiles", HAND_PROFS_LINE, '    if false; then\n        echo "  $N_HAND_PROFS flagged', ["X04", "X12"]),
    ("headerAlways", "'Fixes:' is shown even when there is nothing to fix", HEADER, 'if true; then', ["X01", "X11"]),
    ("headerNever", "'Fixes:' is never shown", HEADER, 'if false; then', ["X01"]),
    ("headerOnlyOffers", "'Fixes:' is not shown when everything is left to you", HEADER, 'if [[ "$N_FIX" -gt 0 ]]; then', ["X04"]),

    # --- what the dry run says ---
    ("dryHintDropped", "the dry run does not say how to turn removal on", DRY_HINT, '', ["X01"]),
    ("dryCountDropped", "the dry run does not say how many could be removed", DRY_COUNT, '', ["X01"]),
    ("hintUnderApply", "the 'run again as APPLY=1' hint is shown even with APPLY=1",
     '        echo "  Only the items listed above are offered. Nothing is removed unless you answer y."\n',
     '        echo "  Only the items listed above are offered. Nothing is removed unless you answer y."\n' + DRY_HINT, ["X02"]),
    ("onlyListedNoteDropped", "the 'only the listed items are offered' note is missing",
     '        echo "  Only the items listed above are offered. Nothing is removed unless you answer y."\n', '', ["X02", "X12"]),
    ("itemsPluralNever", "'1 flagged items'", '$(plural "$N_FIX" item items) can be removed', '$(plural "$N_FIX" items items) can be removed', ["X01"]),
    ("itemsPluralAlways", "'3 flagged item'", '$(plural "$N_FIX" item items) can be removed', '$(plural "$N_FIX" item item) can be removed', ["X01"]),
    ("handAppNounSingularOnly", "'15 flagged app'", '$(plural "$N_HAND_APPS" app apps) cannot', '$(plural "$N_HAND_APPS" app app) cannot', ["X04"]),
    ("handAppNounPluralOnly", "'1 flagged apps'", '$(plural "$N_HAND_APPS" app apps) cannot', '$(plural "$N_HAND_APPS" apps apps) cannot', ["X04"]),
    ("handAppPronounIt", "'Remove it yourself' for several apps", '$(plural "$N_HAND_APPS" it them) yourself', '$(plural "$N_HAND_APPS" it it) yourself', ["X04"]),
    ("handAppPronounThem", "'Remove them yourself' for one app", '$(plural "$N_HAND_APPS" it them) yourself', '$(plural "$N_HAND_APPS" them them) yourself', ["X04"]),
    ("handProfNounSingularOnly", "'5 flagged configuration profile'", '$(plural "$N_HAND_PROFS" profile profiles) cannot', '$(plural "$N_HAND_PROFS" profile profile) cannot', ["X04"]),
    ("handProfNounPluralOnly", "'1 flagged configuration profiles'", '$(plural "$N_HAND_PROFS" profile profiles) cannot', '$(plural "$N_HAND_PROFS" profiles profiles) cannot', ["X04"]),
    ("handProfPronounIt", "'Remove it yourself' for several profiles", '$(plural "$N_HAND_PROFS" it them) yourself', '$(plural "$N_HAND_PROFS" it it) yourself', ["X04"]),
    ("handProfPronounThem", "'Remove them yourself' for one profile", '$(plural "$N_HAND_PROFS" it them) yourself', '$(plural "$N_HAND_PROFS" them them) yourself', ["X04"]),
    ("handTextAppsWrong", "the by-hand steps for an app are wrong", 'HAND_APP="press and hold the app\'s icon, then tap Remove App."',
     'HAND_APP="remove it."', ["X04", "X03"]),
    ("handTextProfilesWrong", "the by-hand steps for a profile are wrong",
     'HAND_PROFILE="Settings > General > VPN & Device Management, tap the profile, then Remove Profile."', 'HAND_PROFILE="remove it."', ["X04", "X03"]),
    ("hintKindSwapped", "an app gets the profile steps and a profile the app steps",
     'if [[ "$1" == "P" ]]; then\n        echo "  $2 $HAND_PROFILE"', 'if [[ "$1" == "A" ]]; then\n        echo "  $2 $HAND_PROFILE"', ["X03"]),

    # --- what is removed, and how it is checked afterwards ---
    ("appRemoveNoUdid", "the app removal does not name the phone", APP_RM, 'pmd apps uninstall "$id" || why="$(reason_of "$TMP_DIR/err")"', ["X02", "X14"]),
    ("profRemoveNoUdid", "the profile removal does not name the phone", PROF_RM, 'pmd profile remove "$id" || why="$(reason_of "$TMP_DIR/err")"', ["X14"]),
    ("profRemovedAsApp", "a profile is removed with the app command", PROF_RM, 'pmd apps uninstall --udid "$UDID" "$id" || why="$(reason_of "$TMP_DIR/err")"', ["X14", "X03"]),
    ("reportOnExitStatus", "'Removed' is decided by the removal command's exit status", CASE,
     'case "$([[ -z "$why" ]] && echo 0 || echo 1)" in', ["X03", "X10"]),
    ("relistIgnoredGone", "the re-list is skipped and the item taken as gone", CASE, 'case "0" in', ["X03", "X07"]),
    ("relistIgnoredStill", "the re-list is skipped and the item taken as still there", CASE, 'case "1" in', ["X02"]),
    ("relistIgnoredUnknown", "the re-list is skipped and nothing is confirmed", CASE, 'case "?" in', ["X02"]),
    ("relistTypeDropped", "the apps re-list no longer asks for every type", APP_RELIST, 'pmd apps list --udid "$UDID" || { echo "?"; return; }', ["X02"]),
    ("appRelistNoUdid", "the apps re-list does not name the phone", APP_RELIST, 'pmd apps list --type Any || { echo "?"; return; }', ["X02", "X14"]),
    ("profRelistNoUdid", "the profile re-list does not name the phone", PROF_RELIST, 'pmd profile list || { echo "?"; return; }', ["X14"]),
    ("appRelistFailIgnored", "an apps re-list that fails after printing a list is believed", APP_RELIST, 'pmd apps list --type Any --udid "$UDID" || true', ["X09"]),
    ("profRelistFailIgnored", "a profile re-list that fails after printing a list is believed", PROF_RELIST, 'pmd profile list --udid "$UDID" || true', ["X09"]),
    ("appPartialBelieved", "output left by a crashing apps probe is believed", APP_PROBE, 'out="$(helper apps "$id" < "$TMP_DIR/out" 2>/dev/null)" || true', ["X09"]),
    ("profPartialBelieved", "output left by a crashing profiles probe is believed", PROF_PROBE,
     'out="$(helper profiles "$id" < "$TMP_DIR/out" 2>/dev/null)" || true', ["X09"]),
    ("relistKindSwapped", "a profile is re-checked in the apps list and the other way round",
     'if [[ "$kind" == "P" ]]; then\n        pmd profile list', 'if [[ "$kind" == "A" ]]; then\n        pmd profile list', ["X02", "X03"]),
    ("appSeenInverted", "SEEN is the wrong way round for apps", SEEN_APPS, 'emit("SEEN", "0" if probe in data else "1")', ["X02", "X03"]),
    ("profSeenInverted", "SEEN is the wrong way round for profiles", SEEN_PROFS, 'emit("SEEN", "0" if probe in ids else "1")', ["X03", "X14"]),
    ("appSeenOnlyFlagged", "an app that is still installed but no longer flagged counts as gone", SEEN_APPS,
     'emit("SEEN", "1" if probe in data and data[probe].get("SignerIdentity") != APP_STORE_SIGNER else "0")', ["X10"]),
    ("appSeenSubstring", "an app counts as still there if any ID merely contains it", SEEN_APPS,
     'emit("SEEN", "1" if any(probe in k for k in data) else "0")', ["X15"]),
    ("profSeenSubstring", "a profile counts as still there if any ID merely contains it", SEEN_PROFS,
     'emit("SEEN", "1" if any(probe in i for i in ids) else "0")', ["X15"]),
    ("profSeenOrderOnly", "a profile only counts as there when the ordered list names it", SEEN_PROFS,
     'emit("SEEN", "1" if probe in (order or []) else "0")', ["X15"]),
    ("profSeenMetaOnly", "a profile only counts as there when its details are listed", SEEN_PROFS,
     'emit("SEEN", "1" if probe in (meta or {}) else "0")', ["X15"]),
    ("profSeenManifestOnly", "a profile only counts as there when the manifest names it", SEEN_PROFS,
     'emit("SEEN", "1" if probe in (manifest or {}) else "0")', ["X15"]),
    ("stillArmIsGone", "'could not confirm' is reported as removed", '        1)\n            say "$RED"', '        1|\\?)\n            say "$RED"', ["X09"]),
    ("goneArmCoversUnknown", "'could not confirm' is reported as removed (first arm)", '        0)\n            say "$GREEN"', '        0|\\?)\n            say "$GREEN"', ["X09"]),
    ("armsSwapped", "'Removed' and 'Still present' are swapped",
     ['        0)\n            say "$GREEN"', '        1)\n            say "$RED"'], ['        1)\n            say "$GREEN"', '        0)\n            say "$RED"'], ["X02", "X03"]),

    # --- the reason shown with a failure ---
    ("appReasonDropped", "an app removal failure shows no reason", APP_RM, 'pmd apps uninstall --udid "$UDID" "$id" || why="failed"', ["X07"]),
    ("profReasonDropped", "a profile removal failure shows no reason", PROF_RM, 'pmd profile remove --udid "$UDID" "$id" || why="failed"', ["X07"]),
    ("appReasonUnmasked", "an app removal failure shows the raw error, phone ID and all", APP_RM,
     'pmd apps uninstall --udid "$UDID" "$id" || why="$(cat "$TMP_DIR/err")"', ["X07"]),
    ("profReasonUnmasked", "a profile removal failure shows the raw error, phone ID and all", PROF_RM,
     'pmd profile remove --udid "$UDID" "$id" || why="$(cat "$TMP_DIR/err")"', ["X07"]),
    ("noteDropped", "the removal command's message is never shown", '    [[ -n "$why" ]] && note=" (the removal command said: $why)"\n', '', ["X07"]),

    # --- the warnings and the order ---
    ("passcodeHintDropped", "profiles are removed without the passcode hint", PASSCODE, '', ["X14"]),
    ("passcodeHintOnApps", "apps get the passcode hint too", '        what="app"\n        pmd apps uninstall', '        what="app"\n' + PASSCODE + '        pmd apps uninstall', ["X14", "X02"]),
    ("appsFirst", "apps are offered before profiles", 'FIX_ITEMS="${FIX_ITEMS}A|$f1|$f2"$\'\\n\'', 'FIX_ITEMS="A|$f1|$f2"$\'\\n\'"${FIX_ITEMS}"', ["X14"]),

    # --- what is written down ---
    ("recordDropped", "nothing is written to ACTIONS TAKEN", 'printf \'%s\\n\' "$1" >> "$ACTIONS"', ':', ["X02"]),
    ("reportNoteDropped", "the report does not say its counts predate the changes", IN_REPORT, '', ["X02"]),
    ("reportAlwaysNone", "the report says nothing changed even after a removal", REPORT_IF, '        if false; then\n            echo "The findings and counts', ["X02"]),
    ("reportNeverNone", "the report never says nothing changed", REPORT_IF, '        if true; then\n            echo "The findings and counts', ["X01", "X06"]),
    ("screenNoteDropped", "the screen does not say its summary predates the changes", ONSCREEN, '            :\n', ["X02"]),
    ("screenNoteAlways", "the screen says its summary predates changes that never happened", SCREEN_IF,
     '        if true; then\n            echo "  The summary below shows', ["X06", "X01"]),
    ("screenNoteNever", "the screen never says its summary predates the changes", SCREEN_IF,
     '        if false; then\n            echo "  The summary below shows', ["X02"]),
]
