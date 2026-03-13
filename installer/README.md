# TrustSign Windows Installer

This folder contains the Inno Setup script to build a Windows installer for TrustSign. The installer:

- **Java 17**: If the client's machine does not have Java 17 or later, the installer shows a message and opens the Eclipse Temurin (Java 17) download page. The client installs Java, then runs the TrustSign installer again (or continues if they already have Java).
- **Application**: Installs TrustSign to `C:\Program Files\TrustSign` (or chosen directory), including the service JAR, libraries, and a default `config/config.json`.
- **Run at startup**: Optional task "Run TrustSign when Windows starts" creates a shortcut in the Startup folder so the service starts when the user logs in.
- **Shortcuts**: Start menu and optional desktop shortcut to run TrustSign.

## Prerequisites (for building the installer)

1. **Java 17+** and **Gradle** (to build the app).
2. **Inno Setup 6** ([download](https://jrsoftware.org/isinfo.php)). Either:
   - Add Inno Setup's folder to PATH so `iscc` is available, or
   - Install to the default path (`C:\Program Files (x86)\Inno Setup 6\`).

## Build the installer

From the project root:

```bash
# 1. Build the application and create the installer
./gradlew buildInstaller
```

The installer will be created at:

**`build/installer/TrustSign-0.1.0-Setup.exe`**

If you don't have Inno Setup, run the app layout and compile the script manually:

```bash
./gradlew installDist
# Then open installer\TrustSign.iss in Inno Setup and compile, or run:
# "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\TrustSign.iss
```

## What to give the client

1. **TrustSign-0.1.0-Setup.exe** – the installer.
2. If their PC does not have Java 17, they will be directed to download and install it (Eclipse Temurin 17 JRE), then run the installer again.
3. They can leave "Run TrustSign when Windows starts" checked so the service starts automatically after login.

Config is stored in `{InstallDir}\config\config.json`. The installer does not overwrite an existing `config.json` on reinstall.
