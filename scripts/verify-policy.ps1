param([switch]$InstallVerus)
$ErrorActionPreference = 'Stop'

# Keep this version equal to the versions in verification/toolchain.json and Cargo's vstd dependency.
$leeloRoot = Split-Path -Parent $PSScriptRoot
$verusVersion = '0.2026.06.28.1847ab3'
$verusHash = 'b466ff30c263f2c7ccceb2e44e994a51ed40e39cb0522fb9c4c630cb1a3f0a28'
$verusArchive = Join-Path $leeloRoot ".tools/verus-$verusVersion-x86-win.zip"
$verusDir = Join-Path $leeloRoot ".tools/verus-$verusVersion"
$verusExe = Join-Path $verusDir 'verus-x86-win/verus.exe'

if (-not (Test-Path -LiteralPath $verusExe)) {
    if (-not $InstallVerus) {
        throw 'Pinned Verus not installed. Re-run with -InstallVerus to download it into .tools. Rust 1.96.0 must already be available through rustup.'
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $verusArchive) | Out-Null
    $verusUrl = "https://github.com/verus-lang/verus/releases/download/release/$verusVersion/verus-$verusVersion-x86-win.zip"
    Invoke-WebRequest -Uri $verusUrl -OutFile $verusArchive
    $actualHash = (Get-FileHash -LiteralPath $verusArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $verusHash) { throw "Verus archive checksum mismatch: $actualHash" }
    Expand-Archive -LiteralPath $verusArchive -DestinationPath $verusDir -Force
}

$versionOutput = & $verusExe --version 2>&1
if ($LASTEXITCODE -ne 0) { throw "Cannot run pinned verifier: $versionOutput" }
if (($versionOutput | Out-String) -notmatch [regex]::Escape($verusVersion)) { throw 'Wrong Verus version.' }
Write-Output $versionOutput

# Reject local proof bypasses. Standard-library contracts remain part of the trusted computing base.
$proofSources = @(
    (Join-Path $leeloRoot 'verification/policy.rs'),
    (Join-Path $leeloRoot 'crates/leelo-policy/src/verified.rs'),
    (Join-Path $leeloRoot 'crates/leelo-policy/src/verified_compile.rs')
)
$bypass = Select-String -LiteralPath $proofSources -Pattern '\b(assume|admit)\s*\(|external_body|assume_specification|verifier::external'
if ($bypass) { throw "Unreviewed proof bypass found: $bypass" }

Push-Location $leeloRoot
try {
    & $verusExe --edition=2024 verification/policy.rs --rlimit 40 --no-cheating
    if ($LASTEXITCODE -ne 0) { throw 'Policy verification failed.' }
} finally {
    Pop-Location
}
