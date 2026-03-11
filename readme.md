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
