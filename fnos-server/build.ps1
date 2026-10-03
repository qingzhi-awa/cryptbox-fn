# CryPtBox fnOS server packaging script
# Usage: run .\build.ps1 in PowerShell
# Output:
#   中文版: fnos-cryptbox-x86-<version>.fpk / fnos-cryptbox-arm-<version>.fpk
#   英文版: fygo-cryptbox-x86-<version>.fpk / fygo-cryptbox-arm-<version>.fpk

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$CnDir = Join-Path $Root "cryptbox"
$EnDir = Join-Path $Root "cryptbox-en"
$CnManifest = Join-Path $CnDir "manifest"
$EnManifest = Join-Path $EnDir "manifest"

# manifest is UTF-8 without BOM; read/write with explicit encoding to keep CJK intact
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

# read version and original platform from both manifests
$cnText = [System.IO.File]::ReadAllText($CnManifest, $Utf8NoBom)
$Version = ([regex]::Match($cnText, '(?m)^version\s*=\s*([^\r\n]+)')).Groups[1].Value.Trim()
$CnOriginalPlatform = ([regex]::Match($cnText, '(?m)^platform\s*=\s*([^\r\n]+)')).Groups[1].Value.Trim()
$enText = [System.IO.File]::ReadAllText($EnManifest, $Utf8NoBom)
$EnOriginalPlatform = ([regex]::Match($enText, '(?m)^platform\s*=\s*([^\r\n]+)')).Groups[1].Value.Trim()
if (-not $Version) { throw "cannot read version from manifest" }

function Set-Platform {
    param([string]$ManifestFile, [string]$Platform)
    $text = [System.IO.File]::ReadAllText($ManifestFile, $Utf8NoBom)
    $text = [regex]::Replace($text, '(?m)^(platform\s*=\s*)[^\r\n]*', ('${1}' + $Platform))
    [System.IO.File]::WriteAllText($ManifestFile, $text, $Utf8NoBom)
}

Write-Host "==> 1/3 build web frontend ..."
# frontend source is shared/web, output goes to shared/web/dist (go:embed all:dist)
Push-Location (Join-Path $Root "..\shared\web")
npm.cmd install | Out-Null
# 注入前端版本号（与 manifest 一致），用于运行时版本自检与页脚显示
$env:APP_VERSION = $Version
npm.cmd run build
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "frontend build failed" }
Pop-Location

Write-Host "==> 2/3 cross-compile linux binaries (amd64/arm64) ..."
Push-Location $Root
$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
# 注入版本号：界面与 /api/status 会显示，便于确认「是否装成了新版 / 前端是否已刷新」
$LdFlags = "-X github.com/qingzhi-awa/cryptbox/shared/version.Version=$Version"
go build -ldflags $LdFlags -o (Join-Path $CnDir "app\cryptbox-server") .
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "amd64 build failed" }
$env:GOARCH = "arm64"
go build -ldflags $LdFlags -o (Join-Path $CnDir "app\cryptbox-server-arm64") .
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "arm64 build failed" }
Pop-Location

Write-Host "==> 3/3 pack fpk (cn x86/arm + en x86/arm) ..."
# fnpack outputs cryptbox.fpk into the current working directory
Push-Location $Root

# ---- 中文版 ----
Set-Platform $CnManifest "x86"
fnpack build -d $CnDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cn x86 pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "fnos-cryptbox-x86-$Version.fpk")

Set-Platform $CnManifest "arm"
fnpack build -d $CnDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cn arm pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "fnos-cryptbox-arm-$Version.fpk")

# ---- 英文版（复用中文版编译出的 Linux 二进制）----
Copy-Item -Force (Join-Path $CnDir "app\cryptbox-server") (Join-Path $EnDir "app\cryptbox-server")
Copy-Item -Force (Join-Path $CnDir "app\cryptbox-server-arm64") (Join-Path $EnDir "app\cryptbox-server-arm64")

Set-Platform $EnManifest "x86"
fnpack build -d $EnDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "en x86 pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "fygo-cryptbox-x86-$Version.fpk")

Set-Platform $EnManifest "arm"
fnpack build -d $EnDir
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "en arm pack failed" }
Move-Item -Force (Join-Path $Root "cryptbox.fpk") (Join-Path $Root "fygo-cryptbox-arm-$Version.fpk")

# restore original platform
Set-Platform $CnManifest $CnOriginalPlatform
Set-Platform $EnManifest $EnOriginalPlatform
Pop-Location

Write-Host "Done! Output:"
Write-Host "  $(Join-Path $Root "fnos-cryptbox-x86-$Version.fpk")"
Write-Host "  $(Join-Path $Root "fnos-cryptbox-arm-$Version.fpk")"
Write-Host "  $(Join-Path $Root "fygo-cryptbox-x86-$Version.fpk")"
Write-Host "  $(Join-Path $Root "fygo-cryptbox-arm-$Version.fpk")"
