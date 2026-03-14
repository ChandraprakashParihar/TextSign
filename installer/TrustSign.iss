; TrustSign Windows Installer
; Requires: Inno Setup 6 (https://jrsoftware.org/isinfo.php)
; Build: 1) Run "gradlew installDist" from project root
;        2) Compile this script (e.g. iscc installer\TrustSign.iss) or run "gradlew buildInstaller"

#define MyAppName "TrustSign"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "TrustSign"
#define MyAppURL "https://github.com/trustsign/trustsign"
#define BuildDir "..\build\install\trustsign"

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
Compression=lzma2
SolidCompression=yes
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
; Application (from gradle installDistWithJre: includes bundled JRE)
Source: "{#BuildDir}\bin\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\jre\*"; DestDir: "{app}\jre"; Flags: ignoreversion recursesubdirs
; Default config (client can edit later)
Source: "config.json"; DestDir: "{app}\config"; DestName: "config.json"; Flags: ignoreversion onlyifdoesntexist
; Signed licence (vendor must place licence.json here before building the installer)
Source: "licence.json"; DestDir: "{app}\config"; DestName: "licence.json"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Comment: "TrustSign text signing service"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Tasks: runatstartup
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; If Java was just installed, allow shell to pick it up
Filename: "{app}\bin\trustsign.bat"; Description: "Start TrustSign now"; Flags: nowait postinstall skipifsilent unchecked

[Code]
; No Java check: TrustSign installer includes a bundled JRE (Eclipse Temurin 17) so the client does not need to install Java.
