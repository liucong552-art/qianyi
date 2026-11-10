# Windows PowerShell 5.1 and later. Credentials stay in the local SSH client.
$ErrorActionPreference = 'Stop'
$QianyiPythonHash = 'ceed30ced2f92da48976cd6ec461a6c29fb16c80de652bb552cf6dd641be025e'
$QianyiFrameLimit = 32MB + 8192 + 128
$QianyiLinuxBootstrap = @'
set -eu
umask 077
d="$(mktemp -d /run/qianyi.XXXXXXXX)"
trap 'rm -rf -- "$d"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
curl --proto '=https' -fsSL --max-time 90 https://raw.githubusercontent.com/liucong552-art/qianyi/main/qianyi.py -o "$d/qianyi.py"
printf '%s  %s\n' "$1" "$d/qianyi.py" | sha256sum -c - >/dev/null
python3 -I -B "$d/qianyi.py" "$2"
'@

function Read-QianyiEndpoint([string] $Prompt) {
    while ($true) {
        $inputValue = (Read-Host $Prompt).Trim()
        if ($inputValue -match '^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$') {
            $address = $Matches[1]
            $port = if ($Matches.ContainsKey(2)) { [int] $Matches[2] } else { 22 }
            $parsed = $null
            if ([Net.IPAddress]::TryParse($address, [ref] $parsed) -and
                $parsed.ToString() -eq $address -and $port -ge 1 -and $port -le 65535) {
                return [pscustomobject] @{ Address = $address; Port = $port }
            }
        }
        Write-Host '请输入 IPv4 地址。如果 SSH 不是 22 端口，可以填 IPv4:端口。'
    }
}

function Find-QianyiKey {
    foreach ($name in @('vps_root_ed25519', 'id_ed25519', 'id_ecdsa', 'id_rsa')) {
        $path = Join-Path $env:USERPROFILE ".ssh\$name"
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            return $path
        }
    }
    while ($true) {
        $path = (Read-Host '请输入 Windows 上用于登录两台 VPS 的 SSH 私钥文件路径').Trim().Trim('"')
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf) -and -not $path.EndsWith('.pub')) {
            return (Resolve-Path -LiteralPath $path).ProviderPath
        }
        Write-Host '没有找到私钥文件，请检查路径。'
    }
}

function Join-QianyiArguments([string[]] $Arguments) {
    # ProcessStartInfo.Arguments uses the Windows native command-line quoting rules.
    $quoted = foreach ($argument in $Arguments) {
        '"' + ($argument -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
    }
    return $quoted -join ' '
}

function Start-QianyiProcess([string] $Executable, [string[]] $Arguments, [bool] $ReadOutput) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = Join-QianyiArguments $Arguments
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $ReadOutput
    return [Diagnostics.Process]::Start($info)
}

function Get-QianyiRemoteCommand([ValidateSet('export-ssh', 'import-ssh')][string] $Action) {
    $bootstrap = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($QianyiLinuxBootstrap))
    # Decode only the shell command. The original standard input still carries the snapshot.
    return ('bash -c "$(printf %s ' + $bootstrap + ' | base64 -d)" qianyi ' + $QianyiPythonHash + ' ' + $Action)
}

function Start-QianyiSsh($Endpoint, [string] $Key, [string] $Action) {
    $ssh = (Get-Command ssh.exe -CommandType Application | Select-Object -First 1).Source
    $arguments = @(
        '-T', '-a', '-x',
        '-o', 'ClearAllForwardings=yes', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
        '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'AddKeysToAgent=no',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
        '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
        '-i', $Key, '-p', [string] $Endpoint.Port, "root@$($Endpoint.Address)",
        (Get-QianyiRemoteCommand $Action)
    )
    return (Start-QianyiProcess $ssh $arguments ($Action -eq 'export-ssh'))
}

function Close-QianyiProcess($Process) {
    if ($null -ne $Process) {
        try {
            if (-not $Process.HasExited) {
                try { $Process.Kill() } catch [InvalidOperationException] {}
            }
        }
        finally { $Process.Dispose() }
    }
}

function Copy-QianyiFrame([IO.Stream] $InputStream, [IO.MemoryStream] $Destination) {
    $buffer = [byte[]]::new(65536)
    try {
        while (($length = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($Destination.Length + $length -gt $QianyiFrameLimit) {
                throw '源机返回的数据超过迁移大小限制。'
            }
            $Destination.Write($buffer, 0, $length)
        }
    }
    finally { [Array]::Clear($buffer, 0, $buffer.Length) }
}

function Invoke-QianyiTransfer($Source, $Target, [string] $Key) {
    $packet = [IO.MemoryStream]::new($QianyiFrameLimit)
    $sender = $null
    $receiver = $null
    try {
        Write-Host "正在从源机 $($Source.Address) 读取节点快照..."
        $sender = Start-QianyiSsh $Source $Key 'export-ssh'
        $sender.StandardInput.BaseStream.Dispose()
        Copy-QianyiFrame $sender.StandardOutput.BaseStream $packet
        $sender.WaitForExit()
        if ($sender.ExitCode -ne 0 -or $packet.Length -eq 0) {
            throw "源机导出失败，迁移停在源机阶段（SSH 退出码 $($sender.ExitCode)）。"
        }

        Write-Host "正在向目标机 $($Target.Address) 交付快照并接管节点..."
        $packet.Position = 0
        $receiver = Start-QianyiSsh $Target $Key 'import-ssh'
        $targetPipe = $receiver.StandardInput.BaseStream
        try { $packet.CopyTo($targetPipe) }
        finally { $targetPipe.Dispose() }
        $receiver.WaitForExit()
        if ($receiver.ExitCode -ne 0) {
            throw "目标机未报告迁移完成（SSH 退出码 $($receiver.ExitCode)）。请查看上方报错。"
        }
    }
    finally {
        try { Close-QianyiProcess $receiver }
        finally {
            try { Close-QianyiProcess $sender }
            finally {
                [Array]::Clear($packet.GetBuffer(), 0, [int] $packet.Length)
                $packet.Dispose()
            }
        }
    }
}

function Invoke-Qianyi {
    $source = Read-QianyiEndpoint '源机公网 IPv4（现在正在用的 VPS）'
    $target = Read-QianyiEndpoint '目标机公网 IPv4（准备接班的 VPS）'
    if ($source.Address -eq $target.Address -and $source.Port -eq $target.Port) {
        throw '源机和目标机填成了同一个 SSH 地址。'
    }
    $key = Find-QianyiKey
    Write-Host "迁移方向 $($source.Address) → $($target.Address)。目标机的 443 和同端口节点会被接管。"
    Invoke-QianyiTransfer $source $target $key
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Qianyi
}
