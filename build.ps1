# Build NetScope tests and the self-contained Windows exe.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
$env:DOTNET_NOLOGO = "1"

dotnet test "$Root\NetScope.sln" -c Release
$Out = Join-Path $Root "artifacts\publish"
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
New-Item -ItemType Directory -Path $Out | Out-Null
dotnet publish "$Root\src\NetScope\NetScope.csproj" -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:DebugType=none `
  -p:DebugSymbols=false `
  -o $Out

$Exe = Join-Path $Out "NetScope.exe"
if (-not (Test-Path $Exe)) { throw "Publish did not produce NetScope.exe" }
$Zip = Join-Path $Root "artifacts\NetScope-1.0.1-win-x64.zip"
if (Test-Path $Zip) { Remove-Item $Zip -Force }
Compress-Archive -Path $Exe, (Join-Path $Root "README.md") -DestinationPath $Zip
Get-FileHash $Exe, $Zip -Algorithm SHA256 | Format-List
Write-Host "Published $Exe"
Write-Host "Zip $Zip"
