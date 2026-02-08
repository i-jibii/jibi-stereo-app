# jibi-stereo-app

Stereo/voice-related files for Discord (voice module + plugin) packaged as `jibi-stereo-app`.

## What’s inside
- `Stereo Plugin/` – BetterDiscord plugin (`StereoSound.plugin.js`)
- `Voice Modules/` – Discord voice module files (includes `discord_voice.node`, `index.js`, models, dlls)

## Install / Usage (high level)
1. Close Discord completely.
2. Back up your existing Discord voice module files before replacing anything.
3. Copy the contents of `Voice Modules/` to the appropriate Discord voice module folder for your Discord install.
4. (Optional) Install the BetterDiscord plugin from `Stereo Plugin/` in BetterDiscord’s plugins folder.
5. Start Discord.

> Note: Paths and exact steps can vary depending on your Discord version. Always back up first.

## Antivirus / VirusTotal note
Some antivirus engines may flag the ZIP/repo because it contains native binaries (e.g. `discord_voice.node`) that modify/replace Discord voice components. This is often heuristic detection for “Discord mod/injection-like” behavior. Review the source and use at your own risk.

## Disclaimer
This project is not affiliated with Discord. Modifying Discord files may violate Discord’s Terms of Service. Use responsibly.
