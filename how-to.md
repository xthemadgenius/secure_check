# How to Run the Mac Security Scanner

## Step 1: Create the Folder

On your **Desktop**, create a new folder called:

```
scan_device
```

## Step 2: Drop the Script In

Place the file **`mac_sec.sh`** (attached) into the `scan_device` folder.

Your  **Desktop** should look like:

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

---

# How to Run the iPhone Security Check

This checks an iPhone that is plugged into your Mac. It is separate from the Mac scan above, and it does **not** ask for your Mac password.

## Step 1: Install the Two Tools (once)

Open Terminal (**CMD + SPACE**, type `terminal`, hit Enter) and paste these one at a time. Skip any you already have:

```bash
brew install pipx
pipx install pymobiledevice3
pipx install mvt
pipx ensurepath
```

Then **close Terminal and open a new window** so the new commands are found. If `brew` is not found, install Homebrew first from https://brew.sh.

The script never installs anything by itself. If a tool is missing it prints these same commands and stops.

## Step 2: Drop the Script In

Place **`iphone_sec.sh`** (attached) into the same `scan_device` folder on your **Desktop** as `mac_sec.sh`:

```
Desktop/
  scan_device/
    mac_sec.sh
    iphone_sec.sh
```

## Step 3: Connect the iPhone

Plug the iPhone into the Mac with a cable, **unlock it** and keep the screen on.

If it asks **"Trust This Computer?"**, tap **Trust** and enter the phone's passcode. Without this the phone refuses to answer anything.

## Step 4: Run the Script

```bash
cd Desktop/scan_device
bash ./iphone_sec.sh
```

## Step 5: Answer the First Questions

1. **"Enter your name for the report (no spaces)"** -- letters, numbers, dots, dashes and underscores only. This names the output on your Desktop as `NAME.iPhone_Security_Check`.
2. **"I confirm this is my iPhone or I have the owner's permission (y/n)"** -- answer `y` only if that is true. If you answer `n`, no phone is contacted.
3. **"Press Enter once the iPhone is unlocked and has trusted this Mac"** -- do what Step 3 says, then hit Enter. If the script cannot see the phone, it lets you look again or quit.

The quick checks then run by themselves: the phone's configuration profiles and the apps that are not signed by the App Store. Nothing is copied off the phone.

## Step 6: The Deep Scan (optional)

The script asks **"Run the deep scan? (y/n)"**.

- **`n`** skips it. The report says the phone's data was not checked against spyware indicators.
- **`y`** makes a full backup of the iPhone into a private folder on your Mac and checks it with Amnesty International's MVT.
  - It can take a long time and needs free space about the size of the phone's data.
  - Keep the iPhone **unlocked and plugged in**, and watch it for prompts.
  - The spyware indicator lists are downloaded from the internet. Nothing from the phone is sent.

If the phone's backups are **not encrypted**, the script asks **"Turn on backup encryption? (y/n)"**. An encrypted backup holds more (saved passwords, Wi-Fi settings, website history, Health data, call history), so more can be checked.

- `y` asks you to type a new backup password twice (it does not show on screen). **Write it down.** The password stays on the phone until you turn it off in Finder by unticking **"Encrypt local backup"**. Other programs on the Mac can briefly see it while the command that sets it runs.
- `n` keeps the backup unencrypted and the scan carries on with what it can see.

If the backups are **already encrypted**, the script asks for the existing backup password. If you do not remember it, the script prints how to reset it.

## Step 7: Read the Results on Screen

Each finding has a tag:

| Tag | Meaning |
|-----|---------|
| `DETECTED` | Something known to be linked to spyware was found. **Do not wipe, reset or delete anything yet** -- stop and talk to an expert |
| `REVIEW` | Needs a look from you |
| `INFO` | For information |
| `UNKNOWN` | A check could not run, so it did **not** pass. Run the scan again |

"Nothing found" only means nothing **known** was found.

## Step 8: Fixes (optional)

By default the script changes nothing on the phone. To be offered the removal of a flagged app or configuration profile, run it like this instead:

```bash
APPLY=1 bash ./iphone_sec.sh
```

It asks about each item separately, and nothing is removed unless you answer `y`. If anything is `DETECTED`, fixes are switched off.

## Step 9: Finish Up

When the scan completes you will find on your Desktop:

- A **folder** called `NAME.iPhone_Security_Check/` containing `iphone_security_report.txt`
- A **ZIP file** called `NAME.iPhone_Security_Check.zip` with the same report

The script then asks:

- **"Delete the folder and keep only the ZIP? (y/n)"** -- the ZIP already holds the report.
- If you ran the deep scan, it asks whether to delete the **private folder** under `~/Library/Application Support/secure_check/`. That folder holds all of the phone's data (the backup and MVT's raw results). It is never part of the ZIP and stays on your Mac unless you answer `y`.

Open the report and work through **CHECK THESE YOURSELF**. These are things only the phone's owner can check, and they need the iPhone in your hand.

## Step 10: Send the ZIP

Send the **`NAME.iPhone_Security_Check.zip`** file to your security team for review. It holds only the report, never a backup.

If the report says something was `DETECTED`, contact Amnesty International's Security Lab (link in the report) from another device, not from this iPhone, and do not email the backup to anyone.

---

## iPhone Quick Reference

| Action | Command |
|--------|---------|
| Install the tools (once) | `brew install pipx`, `pipx install pymobiledevice3`, `pipx install mvt`, `pipx ensurepath` |
| Run the check | `cd Desktop/scan_device && bash ./iphone_sec.sh` |
| Run it and be offered fixes | `cd Desktop/scan_device && APPLY=1 bash ./iphone_sec.sh` |
| Stop the script | **CTRL + C** |
| Phone not answering | Unlock it, keep the screen on, tap **Trust**, then hit Enter |
