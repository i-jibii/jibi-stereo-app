# jibi-stereo-app

Stereo/voice-related files for Discord packaged as `jibi-stereo-app`.

## What’s inside

- `Stereo Plugin/` – BetterDiscord plugin (`StereoSound.plugin.js`)
- `Voice Modules/` – Discord voice module files (includes `discord_voice.node`, `index.js`, models, dlls/exes)
- `JibiStereo.exe` – helper application bundled with this package

## Install / Usage (high level)

1. Close Discord completely.
2. Back up your existing Discord voice module files before replacing anything.
3. Copy the contents of `Voice Modules/` to the appropriate Discord voice module folder for your Discord install.
4. (Optional) Install the BetterDiscord plugin from `Stereo Plugin/` in BetterDiscord’s plugins folder.
5. Start Discord.

> Paths and exact steps vary by Discord version. Always back up first.

## Antivirus / VirusTotal / Windows Defender notes

### Why scanners may flag this project

This project contains **native binaries** (`.exe`, `.dll`, `.node`) intended to work with and/or replace parts of Discord’s voice stack. Security products often flag this category because it resembles the same file/process/module modification patterns used by real malware.

In practice this means:

- A ZIP/repo can be flagged simply because it **contains PE binaries** (Windows executables/modules).
- Windows Defender/SmartScreen can block a file due to **reputation** (unsigned + uncommon/new hash) even when many VirusTotal engines show **0 detections**.
- Some detections may be **PUA/PUP** (“potentially unwanted application”) rather than a confirmed trojan.

### Notes about the bundled voice module files

It is possible for individual files such as:

- `discord_voice.node`
- `mediapipe.dll`
- `gpu_encoder_helper.exe`

to score **0/70** on VirusTotal, while **another bundled binary** (for example `JibiStereo.exe`) is flagged locally by Windows Defender. These are different binaries with different signatures/reputation and may be evaluated using different heuristics.

### What was checked

- The JavaScript voice bootstrap (`Voice Modules/index.js`) does not contain obvious token stealing, webhook posting, downloader, or persistence code (no common indicators like `leveldb`, `token`, `webhook`, `child_process`, etc. were found during review).

### What you should do

- Only use builds you trust.
- Verify hashes for releases if provided.
- If you believe a detection is a false positive, check **Windows Security → Protection history** for the exact detection name and consider submitting a false-positive report to the vendor.

## Disclaimer

Not affiliated with Discord. Modifying Discord files and/or using client mods may violate Discord’s Terms of Service. Use at your own risk.
