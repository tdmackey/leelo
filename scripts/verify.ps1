param([switch]$InstallVerus)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'verify-policy.ps1') -InstallVerus:$InstallVerus

$leeloRoot = Split-Path -Parent $PSScriptRoot
$verusExe = Join-Path $leeloRoot '.tools/verus-0.2026.06.28.1847ab3/verus-x86-win/verus.exe'
$proofSources = @(
    (Join-Path $leeloRoot 'verification/gf256.rs'),
    (Join-Path $leeloRoot 'verification/sss.rs'),
    (Join-Path $leeloRoot 'crates/leelo-sss/src/gf256.rs'),
    (Join-Path $leeloRoot 'crates/leelo-sss/src/interpolation.rs'),
    (Join-Path $leeloRoot 'verification/release.rs'),
    (Join-Path $leeloRoot 'crates/leelo-engine/src/release.rs')
)
$bypass = Select-String -LiteralPath $proofSources -Pattern '\b(assume|admit)\s*\(|external_body|assume_specification|verifier::external'
if ($bypass) { throw "Unreviewed arithmetic proof bypass found: $bypass" }
Push-Location $leeloRoot
try {
    & $verusExe --edition=2024 verification/sss.rs --rlimit 15 --no-cheating
    if ($LASTEXITCODE -ne 0) { throw 'Field arithmetic and interpolation verification failed.' }
    & $verusExe --edition=2024 verification/release.rs --rlimit 40 --no-cheating
    if ($LASTEXITCODE -ne 0) { throw 'Context and release sequence verification failed.' }
} finally {
    Pop-Location
}
