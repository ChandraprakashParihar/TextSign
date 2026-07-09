; TrustSign Windows Installer
; Requires: Inno Setup 6 (https://jrsoftware.org/isinfo.php)
; Build: ./gradlew buildInstaller (creates build/client then packages it here; same files as client folder)

#define MyAppName "TrustSign"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "TrustSign"
#define MyAppURL "https://github.com/trustsign/trustsign"
; Same content as build/client (JAR, run script, config, JRE) so installer and zip client match
#define BuildDir "..\build\client"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\build\installer
OutputBaseFilename=TrustSign-{#MyAppVersion}-Setup
; Use zip for faster builds (2-5 min). Use lzma2+SolidCompression=yes for smallest exe (15-30+ min).
Compression=zip
SolidCompression=no
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "installservice"; Description: "Install and start TrustSign as a Windows Service (recommended: runs in the background, starts before login, restarts automatically if it crashes, and keeps running through logout)"; GroupDescription: "Background service:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Same layout as build/client: JAR, launcher, README, config (incl. licence, public-key, truststore, SET-PIN), JRE, service wrapper
Source: "{#BuildDir}\*.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\run-trustsign.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\jre\*"; DestDir: "{app}\jre"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\run-trustsign.bat"; WorkingDir: "{app}"; Comment: "TrustSign text signing service"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\run-trustsign.bat"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Runs elevated (installer itself requires admin) so the Windows Service can be registered.
Filename: "{app}\service\windows\install-service.bat"; WorkingDir: "{app}\service\windows"; Description: "Install and start the TrustSign Windows Service"; Tasks: installservice; Flags: runhidden waituntilterminated postinstall skipifsilent
; Only offered when the service task is NOT selected, to avoid double-launching (service + console window both binding the same port).
Filename: "{app}\run-trustsign.bat"; Description: "Start TrustSign now (foreground console window)"; Tasks: not installservice; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
Filename: "{app}\service\windows\uninstall-service.bat"; WorkingDir: "{app}\service\windows"; Tasks: installservice; Flags: runhidden waituntilterminated; RunOnceId: "RemoveTrustSignService"

[Code]
// TrustSign installer includes a bundled JRE (Eclipse Temurin 17) so the client does not need to install Java.
begin
end.
