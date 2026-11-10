$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
Set-Location -LiteralPath $repository
$launcherPath = Join-Path $repository 'qianyi.ps1'
$launcher = [ScriptBlock]::Create([IO.File]::ReadAllText($launcherPath, [Text.Encoding]::UTF8))
. $launcher

$pythonHash = (Get-FileHash qianyi.py -Algorithm SHA256).Hash.ToLowerInvariant()
$launcherHash = (Get-FileHash qianyi.ps1 -Algorithm SHA256).Hash.ToLowerInvariant()
if ($pythonHash -ne $QianyiPythonHash -or -not (Get-Content README.md -Raw).Contains($launcherHash)) {
    throw 'Published bootstrap checksums do not match.'
}

$script:Python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
$remote = Get-QianyiRemoteCommand 'import-ssh'
$expectedArgs = @('with spaces', 'with "quotes"', 'path\', '', $remote)
$process = Start-QianyiProcess $script:Python (@('-B', '-c', 'import json,sys; print(json.dumps(sys.argv[1:]))') + $expectedArgs) $true
try {
    $process.StandardInput.BaseStream.Dispose()
    $actual = @($process.StandardOutput.ReadToEnd() | ConvertFrom-Json)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or $actual.Count -ne $expectedArgs.Count) {
        throw 'The native argument list has the wrong length.'
    }
    for ($i = 0; $i -lt $actual.Count; $i++) {
        if ($actual[$i] -cne $expectedArgs[$i]) { throw "Native argument $i was modified." }
    }
}
finally { Close-QianyiProcess $process }
Write-Host 'Windows native process argument quoting passed.'

$script:Actions = [Collections.Generic.List[string]]::new()
$script:SourceFails = $false

function Start-QianyiSsh($Endpoint, [string] $Key, [string] $Action) {
    $script:Actions.Add($Action)
    if ($Action -eq 'export-ssh') {
        $program = 'import sys, qianyi; qianyi.write_ssh_frame(sys.stdout.buffer, bytes(range(256)) * 1024)'
        if ($script:SourceFails) { $program += '; sys.exit(17)' }
    }
    else {
        $program = 'import sys, qianyi; assert qianyi.read_ssh_frame(sys.stdin.buffer) == bytes(range(256)) * 1024'
    }
    return (Start-QianyiProcess $script:Python @('-B', '-c', $program) ($Action -eq 'export-ssh'))
}

$source = @{ Address = '192.0.2.10'; Port = 22 }
$target = @{ Address = '192.0.2.11'; Port = 22 }
Invoke-QianyiTransfer $source $target 'unused fixture key'
if (($script:Actions -join ',') -ne 'export-ssh,import-ssh') { throw 'Wrong relay order.' }
Write-Host 'Windows PowerShell delivered the complete binary snapshot without text conversion.'

$script:Actions.Clear()
$script:SourceFails = $true
$failed = $false
try { Invoke-QianyiTransfer $source $target 'unused fixture key' }
catch {
    $failed = $_.Exception.Message -like '*17*'
    if (-not $failed) { throw }
}
if (-not $failed -or ($script:Actions -join ',') -ne 'export-ssh') {
    throw 'A failed source must never start the target SSH command.'
}
Write-Host 'Windows relay stops before the target when export fails.'
