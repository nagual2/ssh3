# Regenerates the Windows resource object for the ssh3 client (application
# icon + version info) and rebuilds the Windows executables.
#
# The version has a single source of truth: version.go in the repository root.
# Usage (from the repository root): powershell -File cmd\ssh3\gen-syso.ps1
#
# Requires: go, go-winres (go install github.com/tc-hib/go-winres@latest).

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot | Split-Path -Parent
$versionGo = Join-Path $repoRoot 'version.go'

$content = Get-Content $versionGo -Raw
$maj = [regex]::Match($content, 'SOFTWARE_MAJOR int = (\d+)').Groups[1].Value
$min = [regex]::Match($content, 'SOFTWARE_MINOR int = (\d+)').Groups[1].Value
$pat = [regex]::Match($content, 'SOFTWARE_PATCH int = (\d+)').Groups[1].Value
if (-not $maj -or -not $min -or -not $pat) {
    throw "cannot parse SOFTWARE_MAJOR/MINOR/PATCH from $versionGo"
}
$version = "$maj.$min.$pat"

$winres = Join-Path $PSScriptRoot 'go-winres.exe'
if (-not (Test-Path $winres)) {
    # go env output is UTF-8 and Windows PowerShell mangles non-ASCII user
    # names when capturing it: resolve the default GOPATH from the environment
    $winres = Join-Path $env:USERPROFILE 'go\bin\go-winres.exe'
}

& $winres make --in (Join-Path $PSScriptRoot 'winres.json') `
    --out (Join-Path $PSScriptRoot 'rsrc') `
    --arch amd64 `
    --product-version $version --file-version $version
if ($LASTEXITCODE -ne 0) { throw "go-winres failed with exit code $LASTEXITCODE" }
Write-Output "resources generated for ssh3 $version"
