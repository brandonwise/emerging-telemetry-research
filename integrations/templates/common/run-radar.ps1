param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RadarArguments
)

$ErrorActionPreference = "Stop"
$ConfigRoot = $PSScriptRoot
$ProjectRoot = if ($env:RADAR_PROJECT_ROOT) { $env:RADAR_PROJECT_ROOT } else { $ConfigRoot }
while (-not (Test-Path (Join-Path $ProjectRoot "pyproject.toml"))) {
    $Parent = Split-Path -Parent $ProjectRoot
    if (-not $Parent -or $Parent -eq $ProjectRoot) {
        throw "Could not find the Outcome Radar project root; set RADAR_PROJECT_ROOT"
    }
    $ProjectRoot = $Parent
}

$CommandArguments = @("run", "outcome-radar")
$EnvironmentFile = Join-Path $ConfigRoot "radar.env"
if (Test-Path $EnvironmentFile) {
    $CommandArguments += @("--env-file", $EnvironmentFile)
}
$CommandArguments += @("portable", "run", "--json")
$CommandArguments += $RadarArguments

Push-Location $ProjectRoot
try {
    & uv @CommandArguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
