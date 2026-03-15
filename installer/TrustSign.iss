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
Name: "runatstartup"; Description: "Run TrustSign when Windows starts"; GroupDescription: "Startup:"; Flags: unchecked
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Same layout as build/client: JAR, launcher, README, config (incl. licence, public-key, truststore, SET-PIN), JRE
Source: "{#BuildDir}\*.jar"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\run-trustsign.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\jre\*"; DestDir: "{app}\jre"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\run-trustsign.bat"; WorkingDir: "{app}"; Comment: "TrustSign text signing service"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\run-trustsign.bat"; WorkingDir: "{app}"; Tasks: runatstartup
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\run-trustsign.bat"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\run-trustsign.bat"; Description: "Start TrustSign now"; Flags: nowait postinstall skipifsilent unchecked

[Code]
// TrustSign installer includes a bundled JRE (Eclipse Temurin 17) so the client does not need to install Java.
begin
end.
