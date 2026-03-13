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
; Application (from gradle installDist)
Source: "{#BuildDir}\bin\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs
Source: "{#BuildDir}\lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs
; Default config (client can edit later)
Source: "config.json"; DestDir: "{app}\config"; DestName: "config.json"; Flags: ignoreversion onlyifdoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Comment: "TrustSign text signing service"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autostartup}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Tasks: runatstartup
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\bin\trustsign.bat"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; If Java was just installed, allow shell to pick it up
Filename: "{app}\bin\trustsign.bat"; Description: "Start TrustSign now"; Flags: nowait postinstall skipifsilent unchecked

[Code]
var
  JavaNeededPage: TOutputMsgMemoWizardPage;
  JavaOK: Boolean;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = JavaNeededPage.ID then
    Result := JavaOK;
end;

function GetJavaVersion(var Version: Integer): Boolean;
var
  TmpFile, Cmd, Line: String;
  ResultCode: Integer;
  Lines: TArrayOfString;
  i: Integer;
  S: String;
begin
  Result := False;
  Version := 0;
  TmpFile := ExpandConstant('{tmp}\javaver.txt');
  Cmd := 'java -version 2>' + TmpFile;
  if Exec('cmd.exe', '/c ' + Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringsFromFile(TmpFile, Lines) then
      for i := 0 to GetArrayLength(Lines) - 1 do
      begin
        S := Lines[i];
        if Pos('version "', S) > 0 then
        begin
          S := Copy(S, Pos('version "', S) + 9, 10);
          if Length(S) >= 1 then
            Version := StrToIntDef(Copy(S, 1, 1), 0);
          if (Length(S) >= 3) and (S[2] = '.') then
            Version := Version * 10 + StrToIntDef(Copy(S, 3, 1), 0);
          Result := Version >= 17;
          Break;
        end;
      end;
    DeleteFile(TmpFile);
  end;
end;

function InitializeSetup(): Boolean;
var
  JVer: Integer;
begin
  JavaOK := GetJavaVersion(JVer);
  if not JavaOK then
  begin
    JavaNeededPage := CreateOutputMsgMemoPage(wpWelcome,
      'Java 17 required', 'TrustSign needs Java 17 or later.',
      'If Java 17+ is not installed:' + #13#10 +
      '1. Click "Next" to open the download page in your browser.' + #13#10 +
      '2. Download and install "Eclipse Temurin 17 (LTS) - JRE" for Windows x64.' + #13#10 +
      '3. Run this installer again after installing Java.' + #13#10 + #13#10 +
      'If you have already installed Java 17, click Next to continue.',
      '');
  end;
  Result := True;
end;

procedure CurPageChanged(CurPageID: Integer);
var
  JVer: Integer;
begin
  if (CurPageID = JavaNeededPage.ID) and not JavaOK then
    JavaOK := GetJavaVersion(JVer);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  JVer: Integer;
begin
  Result := True;
  if CurPageID = JavaNeededPage.ID then
  begin
    if not GetJavaVersion(JVer) then
      ShellExec('open', 'https://adoptium.net/temurin/releases/?os=windows&arch=x64&package=jre&version=17', '', '', SW_SHOW);
  end;
end;
