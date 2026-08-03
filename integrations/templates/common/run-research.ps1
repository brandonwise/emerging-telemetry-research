param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ResearchArguments
)

$ErrorActionPreference = "Stop"
$ConfigRoot = $PSScriptRoot
$ProjectRoot = if ($env:ETR_PROJECT_ROOT) { $env:ETR_PROJECT_ROOT } else { $ConfigRoot }
while (-not (Test-Path (Join-Path $ProjectRoot "pyproject.toml"))) {
    $Parent = Split-Path -Parent $ProjectRoot
    if (-not $Parent -or $Parent -eq $ProjectRoot) {
        throw "Could not find the Emerging Telemetry Research project root; set ETR_PROJECT_ROOT"
    }
    $ProjectRoot = $Parent
}

$CommandArguments = @("run", "emerging-telemetry-research")
$EnvironmentFile = Join-Path $ConfigRoot "research.env"
if (Test-Path $EnvironmentFile) {
    $CommandArguments += @("--env-file", $EnvironmentFile)
}
$CommandArguments += @("portable", "run", "--json")
$CommandArguments += $ResearchArguments

Push-Location $ProjectRoot
try {
    & uv @CommandArguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
