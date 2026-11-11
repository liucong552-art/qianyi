# qianyi

两台已安装 [jieshu](https://github.com/liucong552-art/jieshu) 的 VPS 轮换接班。源机保持运行。目标机接管源机的 443 主节点和所有未到期的普通、WG-NAT 临时节点，同端口以源机为准，目标机独有的节点保留。源机由你在切换验证后重装。下一轮从当前生产机重新导出。

## 开始前

- 两台 VPS 均须已有标准的 `jieshu` 443 主节点、相同版本的 `jieshu` 管理库、Python 3.10+、systemd、nftables、`ss` 和 `curl`。两台 VPS 直接传输时，源机还需要 OpenSSL。
- Windows 一键方式需要能用同一个私钥从 Windows 登录两台 VPS，并已核对两台的 SSH 主机指纹。两台 VPS 直接传输方式则使用目标机到源机的 root SSH 和 TCP 本地转发。
- WG-NAT 节点使用目标机已有的同名 WireGuard 接口。预检会检查其标记路由和最近握手，迁入节点改用目标机的 mark、路由表和优先级。
- 迁入端口若被其他服务占用，或有无法归属的文件、自定义 systemd 单元、独立的 portbw 或暂停策略，程序会在替换前停止。
- 源机迁入端口的标准 `jieshu` IPv4 黑名单随节点迁移。工具识别新版 CIDR 表和旧版单 IP 表，使用目标机的标准 CIDR 表持久保存，并保留目标机原有封禁。
- 源机已安装 `vless_traffic` 时，导出前会采集一次，将 443 和迁入临时节点最近 30 个北京时间自然日的每日流量一同带走。目标机会用自己的计数器继续累计，并保留其他节点的历史。目标机缺少该组件时，工具会自动安装经过版本校验的原生统计程序。

## Windows 一键迁移

**如果你平时在 Windows 用私钥登录两台 VPS，直接把下面整段粘贴到 Windows PowerShell。** 程序会分别询问两台 VPS 的公网 IPv4 和 SSH 端口。端口是 22 时按回车，其他端口直接输入数字。脚本优先使用 `.ssh\vps_root_ed25519`，也识别常用的 SSH 私钥文件名。

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $client = [Net.WebClient]::new()
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $previousTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $body = $client.DownloadData('https://raw.githubusercontent.com/liucong552-art/qianyi/main/qianyi.ps1')
        $hash = ([BitConverter]::ToString($sha256.ComputeHash($body))).Replace('-', '').ToLowerInvariant()
        if ($hash -ne 'b6402be10d8f73a16d8201c99c2d27474ae2c87800cd095744bbf74b188c27f5') {
            throw '启动脚本校验失败，请重新打开 GitHub README 并复制最新命令。'
        }
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls
        $client.Dispose()
        $sha256.Dispose()
    }
    & ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($body)))
}
```

Windows 会用已有私钥分别登录两台 VPS，通过 SSH 把快照从源机传给目标机。快照只经过 Windows 内存，私钥文件留在电脑上。如果 SSH 提示 `Enter passphrase`，输入创建私钥时设置的口令。换电脑后，在新电脑上准备能登录两台 VPS 的私钥，并用平时的 SSH 登录方式核对两台机器的主机指纹。看到「迁移完成」后，用原链接验收节点，再切 DNS 和重装旧机。

## 两台 VPS 直接传输

适合目标机已有凭据登录源机的场景。Windows 一键方式使用上面的独立入口。

## 第一步，在源机运行

把下面整段原样粘贴到**源机的 root 终端**。脚本会从当前 SSH 会话读取源机地址和 SSH 端口。提示值正确时按回车即可。

```bash
(
  set -eu
  umask 077
  d=$(mktemp -d /run/qianyi.XXXXXXXX)
  trap 'rm -rf -- "$d"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  curl --proto '=https' -fsSL --max-time 90 \
    https://raw.githubusercontent.com/liucong552-art/qianyi/main/qianyi.py -o "$d/qianyi.py"
  printf '%s  %s\n' 'b1531787566de709d73fb1aa037d29d407fb3ba8dea7117a8614464734542213' "$d/qianyi.py" | sha256sum -c -
  python3 -I -B "$d/qianyi.py" send
)
```

如果通过云控制台登录，或云平台将外部 SSH 端口映射到了另一个内部端口，按提示直接输入目标机能连接的源机管理 IPv4 和对外 SSH 端口。

保持源机终端开启。默认传输窗口 20 分钟。系统自动选择空闲的临时传输端口，只在源机回环地址监听。脚本会把两个端口都填进目标机命令。

## 第二步，在目标机运行

1. 粘贴源端打印的目标机命令。出现提示后，再粘贴一次性令牌。令牌不回显，不放在命令参数里。
2. 等待出现「迁移完成」。用原客户端链接验证 443、普通和 NAT 节点，然后切换对应 A 记录。如有 IPv6 入站，另核对 AAAA 记录。链接若直接写源机 IP，DNS 切换不会更改该 IP。
3. 确认新机接管后，自行重装旧机。下次由这轮的目标机执行第一步。

原链接、节点凭据、到期时间、配额总量、快照时已用量、重置周期和 IP 限制配置随节点迁入。IP 黏性集合属于本机运行状态，迁移到新机时从空集合开始。DNS 并行期两台机器分别计数。443 接管会更新目标机的主节点配置、发布链接和相关默认值，并保留目标机的 IPv6 发布设置、Xray 安装及 WireGuard 配置。

每日流量只包含导出时已采集的历史，源机在导出后的新用量仍留在源机。目标同端口被接管时，该节点的每日历史采用源机记录，其他节点继续保留自己的记录。为了补每日历史而重复导入旧源机的整份迁移包，会覆盖目标机已经新增的配额用量。每日流量是原生业务数据，会随统计组件保存在目标机。

## 清理和失败恢复

正常完成时，两端立即删除本次下载的脚本、TLS 证书和私钥、检查配置、SSH 隧道的 socket 和临时主机密钥文件。包只在内存中传输。目标端清除本次防护表、临时 systemd 配置和恢复文件后才打印「迁移完成」。旧版 `zhuanyi` 两个已知脚本只在其路径和 SHA-256 均匹配时自动删除。业务配置、已有管理脚本和系统日志继续由原来的机制管理。

预检拒绝时目标机业务配置不会被替换。提交前启动或验收失败会恢复目标机原节点。收到未完成收尾提示时，使用上面的临时运行命令，把最后一行改成 `python3 -I -B "$d/qianyi.py" recover`，在提示的目标机上运行。恢复文件只在需要恢复或清理时保留，含节点凭据，仅供 root 读取。断电或强制终止时需重新连接后运行恢复，避免在状态不明时再次导入。

## 测试

```bash
python3 -B -m unittest discover -s tests -v
```

测试包含真实回环 TLS 传输、本地事务模拟，以及 Windows PowerShell 的二进制转发测试。真机验收仍需在两台 VPS 上检查 Xray/Reality、WireGuard、配额规则、重启恢复和双向轮换。
