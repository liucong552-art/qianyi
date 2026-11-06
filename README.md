# qianyi：jieshu 临时用户节点迁移

独立 Python 3 工具，用于两台 **Debian 13 / root / systemd** 公网服务器轮换生产角色。默认在当前生产机执行，通过目标真实公网 IPv4 和正常 SSH 认证交接。只迁移全部普通 VLESS 临时节点、WG-NAT 临时节点及相关用户状态。

**当前是待真实 VPS 验收的实现版本。** 已有可运行代码和本地自动化测试；没有在你的两台 VPS 上运行过，不能把本地测试通过理解为生产验收完成。首次先按 [VPS 验收清单](docs/VPS_ACCEPTANCE.md) 在测试节点/测试服务器演练。实时进度保存在 [PROGRESS.md](PROGRESS.md)，源码依据在 [SOURCE_AUDIT.md](docs/SOURCE_AUDIT.md)。

**开发已按用户要求暂停。最后复查发现 gate 与原 watchdog 的 temp.lock 存在死锁风险，尚未修复；当前不要用于生产交接。** 下次继续先处理 PROGRESS.md 中的待完成项。

## 保留什么

| 对象 | 迁移行为 |
|---|---|
| 每个节点的 JSON / URL | 原文保留；逐节点核对 UUID、端口、域名、Reality 私钥推导公钥、Short ID、SNI、flow；不读取主节点私钥覆盖用户 |
| 普通 / NAT 类型 | 普通直出保持；NAT 保留原 mark/routing，与目标已有 WG_IF/MARK/TABLE_ID/RULE_PRIORITY 逐项匹配 |
| 名称、ID、TAG、OWNER_TAG | 保留 `.env`、原链接片段、配额/IP 归属关系 |
| 配额 | 结算持久化用量和内核实时计数；目标从剩余额度恢复；不调用创建器或 `pq_add.sh` |
| 创建 / 到期 / 周期 | 保留原 epoch；只按原 30 天规则处理确实到期的重置，不重新计时；到期节点不启动 |
| IP 数量和超时 | 保留配置；连接断开后的动态槽位在目标由重新连接建立，不复制旧机 IP 占用集合 |
| portbw | 保留每个端口静态/自动策略、当前限速阶段与截止时间；目标使用自己的网卡，重新分配自己的 tc 槽位 |
| 端口暂停 | 识别 `pause_vless_PORT`；迁入后增加启动恢复，避免重启意外解除禁用 |
| 来源黑名单 | 识别标准 `jsh_cidrban` 和旧 `jsh_ipban`；只迁移用户端口的语义条目，合并到目标标准 CIDR 表 |
| disabled / inactive 节点 | 保持不可使用：迁入转为持久端口暂停，避免被原 watchdog 拉起后意外恢复余额使用 |

不迁移 443、主节点链接、默认发布域名、WireGuard 配置、NAT 机、业务 DNS、每日统计/访问日志或服务商流量信息。目标 443 和 WG 文件交接前后有摘要核对。

## 支持的安装版本

当前适配 [jieshu 提交 3e1972393cd9e6f097b27b76f919a649def61ae4](https://github.com/liucong552-art/jieshu/tree/3e1972393cd9e6f097b27b76f919a649def61ae4) 生成的安装产物。没有统一可靠的安装版本号，因此核对 [compatibility.json](compatibility.json) 中 39 个产物的 SHA-256；可选 NAT / portbw 按实际依赖检查。两机 Xray 版本需一致。

检查失败会明确停止，不自动升级 jieshu，不自动修复 WG，不提供跳过哈希的 `--force`。不能通过随意修改哈希清单把未知版本当作兼容版本。若实际版本不同，应先审计那个版本的源码再增加适配。

要求两机时钟已同步，原 quota/GC/watchdog/restore/shutdown-save 任务已启用；使用限速的节点还要求目标已安装同版 portbw 并正确选择了目标网卡。目标默认没有临时用户节点，但工具仍会检查文件、归属、监听、内核对象和 tc action 冲突。自定义防火墙限制、未知 systemd drop-in、残留节点或不完整计数会拒绝迁移，不覆盖未知数据。

## 下载和检查

以下命令在当前生产机执行。将 `目标公网IP` 替换成真实地址；不要填业务域名。工具使用 OpenSSH 的 known_hosts 校验，第一次应先正常 SSH 并人工核对主机密钥。

```bash
git clone https://github.com/liucong552-art/qianyi.git /root/qianyi
cd /root/qianyi
python3 qianyi.py --help
python3 -m unittest discover -s tests -v

# 按实际 SSH 端口填写；先核对目标身份
ssh -p 22 root@目标公网IP
# 登录确认后 exit 返回当前生产机

# 只读：不停止服务、不写业务文件、不重建内核对象
python3 qianyi.py preflight --target 目标公网IP --ssh-port 22
```

可以用 SSH 默认密钥、ssh-agent 或正常密码认证；指定已有本机私钥时附加 `--identity /root/.ssh/你的私钥`。工具不存储密码，不复制 SSH 私钥。新装的旧服务器会有新 SSH 主机密钥，应正常核验并更新 known_hosts，不能关闭主机密钥检查。

Python 不需要第三方 pip 包。运行依赖已有 jieshu 环境中的 nftables、iproute2、OpenSSH、OpenSSL、systemd、timedatectl、flock、timeout、Xray；NAT 还需要 wg/iptables，portbw 需要 tc。程序不自动安装这些依赖。

## 建议的交接步骤

### 1. 提前准备

```bash
python3 qianyi.py prepare --target 目标公网IP --ssh-port 22
```

会重复预检，将同一份工具安装到两机 `/usr/local/lib/qianyi/agent.py`，建立 root 私有事务目录及重启保护服务，输出一个 32 位事务编号。此时源用户节点继续服务。准备阶段的信息不能当作最终快照；正式交接会再次读取最新节点和状态。

### 2. 正式交接

将下面 `事务编号` 替换成上一步输出。维护期间不要在任何终端运行节点创建/删除、配额重置、封禁、限速修改或安装升级命令。工具会协调原后台任务，并在关键事务内持有原锁。

```bash
python3 /usr/local/lib/qianyi/agent.py cutover 事务编号
```

SSH 认证在前台完成，之后交接作为 `qianyi-transfer-事务编号.service` 在源机 systemd 后台运行；终端断线不会杀掉任务。SSH 控制连接仅能由 root 访问。

工具会停止相关 timers，等正在运行的短任务自然结束，按原锁顺序冻结写入；安装仅针对这些节点端口的输入/输出阻断，清空其迁移期间的 ExecStopPost，再停止监听。计数读取成功后，先持久化结算意图，再恢复源持久余额/零实时计数，生成一次性快照。

目标在阻断下导入原凭据，恢复 quota/IP/黑名单/限速，再校验配置、认证参数、WG 依赖和监听，最后开放。源机不会因为 DNS 缓存继续独立消耗另一份用户余额。

需要一步开始时可用：

```bash
python3 qianyi.py migrate --target 目标公网IP --ssh-port 22
```

这会依次 prepare 和 cutover。第一次使用建议分步操作。

### 3. 查看结果，再修改 DNS

```bash
python3 /usr/local/lib/qianyi/agent.py status 事务编号
python3 /usr/local/lib/qianyi/agent.py verify 事务编号
```

源机显示 **RETIRED** 表示目标已确认 OPEN、源节点已停止并归档。此时会明确提示：可以手工把业务域名 **A 记录改为目标公网 IPv4**。业务域名不替换成目标安装用的备用域名。

`verify` 检查运行状态、防护、原配置和链接摘要、WG 依赖；**不是外部 Reality 握手测试**。可以先在测试客户端用本机 hosts/解析覆盖把业务域名指向目标，保持原链接不变验证，再更新公共 DNS。所有计费以实际节点流量为准，客户端验收产生的流量也会正常计入。

### 4. 外部验收后确认

普通节点和 NAT 节点都用原链接测试；再核对余额、到期、IP 限制、封禁、限速和一次目标正常重启。确认实际可用后执行：

```bash
python3 /usr/local/lib/qianyi/agent.py confirm 事务编号
```

此命令记录你的外部验收确认，不会自动重装或擦除旧服务器。随后由你自行重装旧机、安装 jieshu、建立 WG，使其重新成为只有 443 的空备用机。

## 下次反向迁移

到新的当前生产机运行同样的 `preflight → prepare → cutover`，目标填写重装后的旧机真实 IP。没有 A/B 固定方向；每轮新建事务编号，重新发现全部节点，读取最新元数据与实时计数。上一轮迁入节点及后来使用 jieshu 原命令新建的节点都纳入本轮，并逐个保留自己的密钥。

例：总额 100 GiB、已用 60 GiB 导入后余额 40 GiB；再实际用 10 GiB，下一轮结算后已用 70 GiB、剩余 30 GiB。期间如果原周期按规则正常重置，遵循该周期；不是迁移导致重新发放。

不要把原归档当作新的迁移输入。已接管的目标永久拒绝该事务重新导入；接管后恢复旧余额的操作没有入口。

## 中断、重试与回退

```bash
python3 /usr/local/lib/qianyi/agent.py status
python3 /usr/local/lib/qianyi/agent.py resume 事务编号
```

`resume` 重新认证 SSH，然后从持久状态继续。已经完成结算的事务复用同一份已封存快照；这个源机此时被持久冻结，没有新用户流量，所以不构成旧状态覆盖。下一轮生产迁移必须用新的事务和最新状态。

| 状态 | 含义和操作 |
|---|---|
| PREPARED | 源仍在线；可 cutover，或 abort 取消准备 |
| FREEZING | 正在冻结/结算或该阶段失败；源可能已暂停，先看错误，再 resume |
| SEALED / TRANSFERRING | 源已冻结且快照持久化；修复明确问题后 resume |
| READY（目标） | 已恢复并在屏障内验证；尚未开放，可安全重试或协调撤销 |
| OPEN_UNCERTAIN（源） | 已请求开放但确认未收齐；目标可能已经产生新流量，只能查询/继续，禁止旧余额回退 |
| OPEN（目标）/ RETIRED（源） | 目标接管；只能以目标最新状态发起下一轮迁移 |
| ABORTED | 该目标事务永久作废，不允许旧包再次开放 |
| RESUMED | 目标确认撤销后，源按结算余额恢复 |

目标尚未开放且确需取消时，在源机执行：

```bash
python3 /usr/local/lib/qianyi/agent.py abort 事务编号
```

工具必须通过 SSH 得到目标已撤销并停止监听的确认，才能恢复源节点。目标无法联系时不会冒险恢复源。目标已 OPEN 或开放结果不确定时拒绝旧余额回退；若目标已承载流量，应保留目标数据、修复其环境，或从它重新生成最新快照迁向一个满足空备用机预检的目标。

撤销后的目标可能保留部分导入和隔离状态，供恢复调查；不会自动覆盖/抹除它。重用前需按 [恢复说明](docs/RECOVERY.md) 处理或由你重装该空备用机。

## 安全与运行边界

- 事务、结算意图、快照、原始归档在 `/var/lib/qianyi/`，文件 0600、私有目录 0700；它们包含凭据和私钥。不要上传到 GitHub、聊天、普通工单或日志。仓库只有程序、合成测试资料、说明。
- 暂停规则迁入后由 qianyi 持久恢复；解除它用 `python3 /usr/local/lib/qianyi/agent.py unpause 端口`，不要只删除运行时 nft 表。来源黑名单仍可用 jieshu README 的标准命令管理。
- 动态 IP 槽位和带宽采样基线重建；配置、当前限速和 hold/cooldown 截止时间接续。工具不搬旧 TCP 会话、计数句柄、网卡名或整套 nft/tc 规则。
- 只操作自有 `qianyi_fence` 表、节点对应的原生对象和必要服务覆盖；不清空全机防火墙，不替换网卡 root qdisc。
- 内核计数缺失、未知限制、损坏状态会停止交接并保留关闭状态。若源在最终计数尚未成功持久化前突然掉电，丢失的内核计数无法凭空恢复，程序不会填零或开放另一份余额。
- 常规重启使用原 jieshu shutdown-save/restore；突然断电对尚未持久化计数的影响仍受原项目计量机制限制。真实重启正确性必须执行验收，不以静态配置检查代替。
- 验收完成后仍可用 jieshu 原命令管理/创建节点；程序不改变这些命令的默认发布域名或主节点配置。`verify` 用于本轮交接验收，之后主动修改节点配置可能导致它报告与交接快照不同，下一轮以修改后的当前状态为准。

## 开发和测试

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile qianyi.py tools/build_profile.py
python3 qianyi.py build /root/qianyi-standalone.py
python3 /root/qianyi-standalone.py --help
```

生成的 standalone 含固定兼容性清单，可单文件使用。实际安装时工具也会生成同样的独立文件。`tools/build_profile.py 上游源码目录` 只提取 heredoc 和计算 SHA，不执行上游安装器；改变适配版本仍需要先完成源码审计及相应测试。
