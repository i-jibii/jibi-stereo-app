# Safe Build (Learning Version)

This folder contains a **safe learning project** inspired by the Stereo Installer UI flow.

## Goals
- Build a Windows `.exe` yourself.
- Learn how to structure a small C++ Windows app with a simple GUI and an output log.
- **No risky behaviors**: no process termination, no directory deletion, no network downloading, no binary patching.

## What it does
- Shows a small window with:
  - a destination path picker (just stored/displayed; not used to modify anything)
  - a gain slider
  - a "Simulate Patch" button that writes a log file under `%LOCALAPPDATA%\\StereoInstallerSafe\\logs` and prints log lines in the UI.

## Build requirements
- Windows
- Visual Studio 2022 (or 2019) with the **Desktop development with C++** workload

## How to build
1. Open `safe-build/StereoInstallerSafe.sln` in Visual Studio.
2. Select `Release | x64`.
3. Build.
4. The EXE will be under:
   - `safe-build/x64/Release/StereoInstallerSafe.exe` (or Visual Studio's default output directory).

## Notes
This is intentionally not a Discord patcher. If you later add patching/downloading functionality, expect antivirus detections to rise because those behaviors resemble trojans.
