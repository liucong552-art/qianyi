# qianyi

两台已安装 [jieshu](https://github.com/liucong552-art/jieshu) 的 VPS 轮换接班。源机保持运行。目标机接管源机的 443 主节点和所有未到期的普通、WG-NAT 临时节点，同端口以源机为准，目标机独有的节点保留。源机由你在切换验证后重装。下一轮从当前生产机重新导出。

## 开始前

- 两台 VPS 均须已有标准的 `jieshu` 443 主节点、相同版本的 `jieshu` 管理库、Python 3.10+、systemd、nftables、`ss` 和 `curl`。源机需要 OpenSSL。
- 默认使用目标机到源机的 root SSH 和 TCP 本地转发。源机需启用默认的 Ed25519 主机密钥，目标端需能以正常 SSH 认证连接源机。新工具不修改防火墙、安全组或 SSH 配置。
- WG-NAT 节点使用目标机已有的同名 WireGuard 接口。预检会检查其标记路由和最近握手，迁入节点改用目标机的 mark、路由表和优先级。
- 迁入端口若被其他服务占用，或有无法归属的文件、自定义 systemd 单元、独立的 portbw 或暂停策略，程序会在替换前停止。
- 源机迁入端口的标准 `jieshu` IPv4 黑名单随节点迁移。工具识别新版 CIDR 表和旧版单 IP 表，使用目标机的标准 CIDR 表持久保存，并保留目标机原有封禁。

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
  printf '%s  %s\n' '4e4c7aaf4cb26e3fbced7a2caea3fe979f0bc6119e3d95add2b013866b41cf46' "$d/qianyi.py" | sha256sum -c -
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

## 清理和失败恢复

正常完成时，两端立即删除本次下载的脚本、TLS 证书和私钥、检查配置、SSH 隧道的 socket 和临时主机密钥文件。包只在内存中传输。目标端清除本次防护表、临时 systemd 配置和恢复文件后才打印「迁移完成」。旧版 `zhuanyi` 两个已知脚本只在其路径和 SHA-256 均匹配时自动删除。业务配置、已有管理脚本和系统日志继续由原来的机制管理。

预检拒绝时目标机业务配置不会被替换。提交前启动或验收失败会恢复目标机原节点。收到未完成收尾提示时，使用上面的临时运行命令，把最后一行改成 `python3 -I -B "$d/qianyi.py" recover`，在提示的目标机上运行。恢复文件只在需要恢复或清理时保留，含节点凭据，仅供 root 读取。断电或强制终止时需重新连接后运行恢复，避免在状态不明时再次导入。

## 测试

```bash
python3 -B -m unittest discover -s tests -v
```

测试包含真实回环 TLS 传输及本地事务模拟。真机验收仍需在两台 VPS 上检查 Xray/Reality、WireGuard、配额规则、重启恢复和双向轮换。
