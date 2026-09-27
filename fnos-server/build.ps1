# CryPtBox fnOS server packaging script
# Usage: run .\build.ps1 in PowerShell
# Output: fnos-server\cryptbox-x86-<version>.fpk and cryptbox-arm-<version>.fpk

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$FpkDir = Join-Path $Root "cryptbox"
$ManifestFile = Join-Path $FpkDir "manifest"

# manifest is UTF-8 without BOM; read/write with explicit encoding to keep CJK intact
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# read version and original platform
$manifestText = [System.IO.File]::ReadAllText($ManifestFile, $Utf8NoBom)
$Version = ([regex]::Match($manifestText, '(?m)^version\s*=\s*([^\r\n]+)')).Groups[1].Value.Trim()
$OriginalPlatform = ([regex]::Match($manifestText, '(?m)^platform\s*=\s*([^\r\n]+)')).Groups[1].Value.Trim()
if (-not $Version) { throw "cannot read version from manifest" }
if (-not $OriginalPlatform) { throw "cannot read platform from manifest" }

function Set-ManifestPlatform {
    param([string]$Platform)
    $text = [System.IO.File]::ReadAllText($ManifestFile, $Utf8NoBom)
    $text = [regex]::Replace($text, '(?m)^(platform\s*=\s*)[^\r\n]*', ('${1}' + $Platform))
    [System.IO.File]::WriteAllText($ManifestFile, $text, $Utf8NoBom)
}

Write-Host "==> 1/3 build web frontend ..."
# frontend source is shared/web, output goes to shared/web/dist (go:embed all:dist)
Push-Location (Join-Path $Root "..\shared\web")
npm.cmd install | Out-Null
npm.cmd run build
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "frontend build failed" }
Pop-Location

Write-Host "==> 2/3 cross-compile linux binaries (amd64/arm64) ..."
Push-Location $Root
$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o (Join-Path $FpkDir "app\cryptbox-server") .
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "amd64 build failed" }
$env:GOARCH = "arm64"
go build -o (Join-Path $FpkDir "app\cryptbox-server-arm64") .
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "arm64 build failed" }
Pop-Location

Write-Host "==> 3/3 pack fpk (x86 / arm) ..."
# fnpack outputs cryptbox.fpk into the current working directory
Push-Location $Root

Set-ManifestPlatform "x86"
fnpack build -d $FpkDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "x86 pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "cryptbox-x86-$Version.fpk")

Set-ManifestPlatform "arm"
fnpack build -d $FpkDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "arm pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "cryptbox-arm-$Version.fpk")

# restore original platform
Set-ManifestPlatform $OriginalPlatform
Pop-Location

Write-Host "Done! Output:"
Write-Host "  $(Join-Path $Root "cryptbox-x86-$Version.fpk")"
Write-Host "  $(Join-Path $Root "cryptbox-arm-$Version.fpk")"
