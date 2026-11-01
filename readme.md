# Mac Security Scanner v4.1

A single-command macOS security audit tool that generates 6 diagnostic log files and packages them into a ZIP for review.

## What It Does

The scanner runs 6 targeted scans on a Mac to detect signs of compromise, persistence mechanisms, and suspicious activity:

### Scan 1: Suspicious Hidden Files
- Searches `/Users`, `/tmp`, `/var/tmp`, `/private/tmp`, and LaunchAgent/Daemon directories for hidden files (dot-prefixed)
- Finds hidden files modified in the last 7 days
- Identifies hidden files with executable permissions
- Generates SHA-256 hashes of suspicious executables for analyst verification

### Scan 2: Launch Agents & Persistence Mechanisms
- Lists all User LaunchAgents (`~/Library/LaunchAgents/`)
- Lists all System LaunchAgents (`/Library/LaunchAgents/`)
- Lists all System LaunchDaemons (`/Library/LaunchDaemons/`)
- Lists User LaunchDaemons (`~/Library/LaunchDaemons/`)
- Dumps plist contents of all **non-Apple** agents/daemons using `plutil -p`
- Checks user and root **crontab** entries
- Lists **login items** via System Events

### Scan 3: Temp Directory Hidden Files
- Scans `/tmp`, `/var/tmp`, `/private/tmp` for hidden files modified in the last 7 days
- Provides a count of suspicious files found
- Generates SHA-256 hashes of discovered files

### Scan 4: Network Connections
- Captures all network connections in a **single snapshot** (prevents state drift)
- Lists all ESTABLISHED (active) connections
- Lists all LISTENING ports (services)
- Performs **reverse DNS resolution** on connected IPs
- Flags suspicious port indicators (4444, 1337, 31337, 8443, 9001)

### Scan 5: Hidden / Suspicious Processes
- Lists all non-root, non-system processes
- Excludes its own process and grep artifacts from results
- Flags processes with **CPU usage > 50%** (potential crypto mining)
- Identifies processes running from `/tmp` or `/var/tmp`
- Uses integer comparison (no `bc` dependency)

### Scan 6: Extended Attributes
- Checks all applications in `/Applications` for extended attributes
- Displays attribute names and values
- Flags `com.apple.quarantine` and `test` attributes as potentially suspicious
- Notes that quarantine is normal for downloaded apps but suspicious when combined with other unusual attributes

## Output

The script produces:

```
~/Desktop/NAME.Security_Check/          <-- visible folder with 6 files
~/Desktop/NAME.Security_Check.zip       <-- ZIP archive of the same 6 files
```

### Files Generated (exactly 6)

| File | Content |
|------|---------|
| `suspicious_hidden_analysis.txt` | Hidden files scan results + SHA-256 hashes |
| `launch_agents_report.txt` | LaunchAgents, Daemons, crontab, login items, plist dumps |
| `temp_hidden_files.txt` | Temp directory hidden files + hashes |
| `network_connections.txt` | Active connections, listening ports, DNS resolution |
| `hidden_processes.txt` | Non-system processes, CPU analysis, /tmp process check |
| `extended_attributes.txt` | Application metadata and attribute analysis |

## Architecture & Design Decisions

### Performance
- **Targeted `find` paths** instead of `find /` -- scans only `/Users`, `/tmp`, `/var/tmp`, `/private/tmp`, and LaunchAgent/Daemon directories where threats actually hide. Avoids scanning millions of irrelevant system files.
- **Single `lsof` snapshot** for network scan -- captures once, filters twice. Prevents state changes between ESTABLISHED and LISTEN queries.
- **Single `ps aux` capture** for process scan -- filters from snapshot to avoid capturing its own grep processes.

### Robustness
- `set -uo pipefail` -- catches unset variables and pipe failures
- `trap cleanup EXIT INT TERM` -- kills sudo refresh process and invalidates credentials on exit, interrupt, or termination
- Validates macOS (`uname` check) before running
- Checks that `zip`, `lsof`, `xattr`, `plutil` are available
- Input sanitization: name must match `^[a-zA-Z0-9._-]+$`
- Uses `-perm /111` (not deprecated `-perm +111`)
- Integer CPU comparison via `${cpu%%.*}` (no `bc` dependency)
- Subshell for `cd` during ZIP creation (doesn't change working directory)
- Grep patterns use `/System` not `^/System` (works correctly with `find -ls` output format)
- Temp file counts re-run `find` for accuracy instead of counting report file lines (which include headers)

### User Experience
- **Real-time streaming** -- findings print to the terminal as they are discovered, with color-coded prefixes (`FILE`, `EXEC`, `CONN`, `HASH`, etc.)
- **Progress bar** -- shows scan N/6 with percentage
- Sudo password requested once upfront, kept alive via background refresh (killed on exit)
- User chooses whether to keep the folder or delete it after ZIP creation

## Suspicious Indicators to Look For

When reviewing the generated reports, pay attention to:

- **Hidden files**: Recently modified dot-files in user directories, executable hidden files
- **Persistence**: Non-Apple plists in LaunchAgents/Daemons, crontab entries pointing to `/tmp` or hidden paths, unknown login items
- **Network**: Connections to unknown foreign IPs, unusual ports (4444, 1337, 31337), processes with random names making outbound connections
- **Processes**: CPU usage > 50% (crypto mining), processes running from `/tmp` or `/var/tmp`, processes with random or single-character names
- **Temp files**: Any hidden files in `/tmp` directories (often used as staging areas for malware)
- **Extended attributes**: Non-standard attributes on applications, especially combined with quarantine flags

## Requirements

- macOS (Darwin)
- Terminal access
- Admin password (for sudo)
- Built-in tools: `zip`, `lsof`, `xattr`, `plutil`, `shasum`, `host`

---

# iPhone Security Scanner v1.0

A companion to the Mac scanner for an **iPhone plugged into the Mac over USB**. It screens the phone, writes one report and packages it into a ZIP. It never installs anything itself: if a tool is missing it prints the install commands and stops. The script does not use `sudo`, so it does not ask for your Mac password.

Run it with `bash ./iphone_sec.sh`. `how-to.md` has the step-by-step version.

## What It Does

### Quick checks (nothing is copied off the phone)
- Lists the **configuration profiles** installed on the phone
- Lists the **user-installed apps that are not signed by the App Store**

### Deep scan (optional, asks first)
- Makes a full **backup** of the phone into a private folder on the Mac (`~/Library/Application Support/secure_check/`) and checks it with Amnesty International's [MVT](https://github.com/mvt-project/mvt) against the public spyware indicator lists
- The indicator lists are downloaded from the internet. Nothing from the phone is sent
- An encrypted backup holds more (saved passwords, Wi-Fi settings, website history, Health data, call history), so the script offers to turn backup encryption on. That sets a **backup password on the phone**, which stays until you turn it off in Finder (untick "Encrypt local backup"). The password is briefly visible to other programs on the Mac while the command that sets it runs; the script says so on screen
- Needs free space about the size of the phone's data and can take a long time

### Report
Findings are shown on screen and written to the report, each with a tag:

| Tag | Meaning |
|-----|---------|
| `DETECTED` | Something known to be linked to spyware was found |
| `REVIEW` | Needs a look from you |
| `INFO` | For information |
| `UNKNOWN` | A check could not run, so it did **not** pass |

A summary line gives the counts, followed by one sentence that only describes what was checked. After the findings come what the scan cannot see and a checklist of things only the phone's owner can check: passcode, iOS update, devices on the Apple Account, Find My, VPN & Device Management, app permissions, message and call forwarding, and Lockdown Mode.

### Fixes (only with `APPLY=1`)

```bash
APPLY=1 bash ./iphone_sec.sh
```

- Offers to remove a flagged app or configuration profile, **one item at a time**. Nothing is removed unless you answer `y`
- After each removal it reads the phone's list again and says whether the item is really gone
- If anything is `DETECTED`, fixes are switched off: removing things can destroy the evidence an expert needs. The script points to Amnesty International's Security Lab instead
- Everything else is manual (the checklist)

## Output

```
~/Desktop/NAME.iPhone_Security_Check/                    <-- folder with the report
~/Desktop/NAME.iPhone_Security_Check.zip                 <-- ZIP of the same report
~/Library/Application Support/secure_check/iphone_*      <-- deep scan only: the backup and MVT's raw results (private)
```

| File | Content |
|------|---------|
| `iphone_security_report.txt` | Summary, findings, actions taken, what the scan cannot see, the checklist |

The ZIP holds only the report, never the backup. The private folder holds all of the phone's data and stays on the Mac. At the end the script asks whether to delete it, and whether to delete the report folder and keep only the ZIP.

## What It Cannot See

- "Nothing found" means nothing **known** was found. New or targeted spyware may not be in any public indicator list
- iCloud / Apple ID compromise, malicious iCloud backups, phishing and SIM swap are not visible over USB
- Jailbreak status cannot be reliably detected over USB
- The passcode is only reported when a deep scan's backup says so. Otherwise it is on the checklist
- Android phones are not covered, and an iPad or iPod is treated as an iPhone
- A computer cannot clean an iPhone the way it can a Mac: there is no real-time protection, and only apps and profiles can be removed

## Requirements

- macOS (Darwin), an iPhone and a USB cable
- Terminal access
- [`pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) and [`mvt`](https://github.com/mvt-project/mvt), installed with `pipx` (the commands are in `how-to.md`)
- Python 3.8 or newer, and `zip`
- Runs on the stock macOS bash 3.2

## Status

Checked against stand-in `pymobiledevice3` / `mvt-ios` tools and a fake phone. Only an early, read-only version of the quick checks has run on a real iPhone. The deep scan (backup encryption, the backup itself, MVT on a real backup) and removing an app or profile have not been tried on a real phone yet.
