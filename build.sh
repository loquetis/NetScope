#!/usr/bin/env bash
# Build NetScope tests and the self-contained Windows exe.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -x "${HOME}/.dotnet/dotnet" ]]; then
  export DOTNET_ROOT="${DOTNET_ROOT:-${HOME}/.dotnet}"
  export PATH="${DOTNET_ROOT}:${PATH}"
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1

dotnet test "$ROOT/NetScope.sln" -c Release
OUT="$ROOT/artifacts/publish"
rm -rf "$OUT"
mkdir -p "$OUT"
dotnet publish "$ROOT/src/NetScope/NetScope.csproj" -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true \
  -p:DebugType=none \
  -p:DebugSymbols=false \
  -o "$OUT"

EXE="$OUT/NetScope.exe"
test -f "$EXE"
ZIP="$ROOT/artifacts/NetScope-1.0.1-win-x64.zip"
rm -f "$ZIP"
python3 - "$EXE" "$ROOT/README.md" "$ZIP" << 'PY'
import sys, zipfile
exe, readme, dest = sys.argv[1:]
with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    archive.write(exe, "NetScope.exe")
    archive.write(readme, "README.md")
PY
if command -v sha256sum >/dev/null; then
  sha256sum "$EXE" "$ZIP"
fi
echo "Published $EXE"
echo "Zip $ZIP"
