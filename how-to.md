# How to Run the Mac Security Scanner

## Step 1: Create the Folder

On your **Desktop**, create a new folder called:

```
scan_device
```

## Step 2: Drop the Script In

Place the file **`mac_sec.sh`** (attached) into the `scan_device` folder.

Your Desktop should look like:

```
Desktop/
  scan_device/
    mac_sec.sh
```

## Step 3: Open Terminal

Press **CMD + SPACE** to open Spotlight, then type **`terminal`** and hit Enter.

## Step 4: Run the Script

Paste the following into Terminal and hit Enter:

```bash
cd Desktop/scan_device
bash ./mac_sec.sh
```

The script will start running.

## Step 5: Enter Your Name

You will be prompted to type your **name** (no spaces).

This names the output folder on your Desktop as:

```
NAME.Security_Check/
```

This helps us identify whose logs we are reviewing.

## Step 6: Enter Your Password

When prompted, **type in your Mac password** and hit Enter.

> Your password will NOT appear on screen as you type -- this is normal.

The script needs your password to access system-level files and ensure the scan runs correctly across all directories.

## Step 7: Re-enter Password if Needed

Depending on your machine's security settings and installed applications, **you may need to enter your password 2-8 times** during the scan.

If the scan appears stuck or takes longer than **10 minutes**:
1. Press **CTRL + C** to interrupt
2. The script will prompt you for your password again
3. Enter it and the scan will continue

This happens when the scanner hits a permission restriction and needs your credentials refreshed.

## Step 8: Review the Results

Once complete, you will find on your Desktop:

- A **folder** called `NAME.Security_Check/` containing 6 log files
- A **ZIP file** called `NAME.Security_Check.zip` with the same 6 files

### The 6 log files generated:

| # | File | What It Scans |
|---|------|---------------|
| 1 | `suspicious_hidden_analysis.txt` | Hidden files, executables, user directory anomalies |
| 2 | `launch_agents_report.txt` | LaunchAgents, LaunchDaemons, crontab, login items |
| 3 | `temp_hidden_files.txt` | Hidden files in /tmp, /var/tmp, /private/tmp |
| 4 | `network_connections.txt` | Active network connections and listening ports |
| 5 | `hidden_processes.txt` | Running processes (excluding system processes) |
| 6 | `extended_attributes.txt` | Application metadata and extended attributes |

## Step 9: Send the ZIP

Send the **`NAME.Security_Check.zip`** file to your security team for review.

---

## Quick Reference

| Action | Keys / Command |
|--------|---------------|
| Open Terminal | **CMD + SPACE**, type `terminal` |
| Run the script | `cd Desktop/scan_device && bash ./mac_sec.sh` |
| Interrupt a stuck scan | **CTRL + C** |
| Password not showing | Normal -- just type and hit Enter |
