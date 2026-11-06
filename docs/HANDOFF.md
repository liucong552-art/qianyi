# 接手说明：以本仓库为准，不依赖原聊天或临时工作目录

更新时间：2026-11-06（北京时间）。已从 `fdb6d86` 接手并分阶段继续提交。下面是最新交接状态；原失败证据仍保留。不要把当前版本宣称为已完成生产验收。

## 最先阅读

1. PROGRESS.md：当前状态和最新检查点。
2. docs/REQUIREMENTS.md：已确认需求与范围，不要让用户重新说明。
3. docs/SOURCE_AUDIT.md：真实源码依据。
4. 本文件：实现导航、已验证内容、未完成事项。
5. README.md、docs/RECOVERY.md、docs/VPS_ACCEPTANCE.md：操作和待验收项目。

项目地址：https://github.com/liucong552-art/qianyi 。直接在此仓库保存阶段性代码、测试、结果和进度，不依赖对话记忆。不要上传真实用户快照、凭据、SSH 私钥或服务器日志。

## 当前结果：务必区分

- 迁移程序沿用已有实现，未从头重写。未取得用户 VPS 登录信息，没有操作真实用户节点或上传真实凭据/快照。
- **Reality 烟测已修复并通过。** 阶段 1 `f1ac316`：[CI 42236445140](https://github.com/liucong552-art/qianyi/actions/runs/42236445140)。串行 TLS 目标与新版 freedom 对回环 HTTP 的拦截是两个独立原因，证据与固定官方源码链接见 [TESTING.md](TESTING.md)。旧失败 42233920479 及 CI_LAST_FAILURE.txt 为历史记录。
- **READY/RESUMED 到期与锁修复已提交。** 阶段 2 `9f026cd`：[CI 42237634038](https://github.com/liucong552-art/qianyi/actions/runs/42237634038) 全部成功。本地 73 项 unittest 通过；其中 14 项新增到期/恢复/真实 flock 回归，systemd/nft 调用仍是夹具。
- Debian 13 隔离容器中的真实上游 quota/IP/nft、portbw/nft/tc、固定 Xray v26.10.31 原 URL/独立密钥/错误公钥/新增节点多轮烟测均通过。这些脚本未执行完整迁移 CLI、SSH、systemd 重启或真实 WG。
- 本轮文档整理同时加强了两处既有断言：RESUMED 回归直接调用真实 verify_protection 逻辑（输入为受控 nft 夹具）；错误公钥拒绝后立即再测同一服务的正确原 URL。最终提交 `1c40cc0` 的 [CI 42238894007](https://github.com/liucong552-art/qianyi/actions/runs/42238894007) 已确认全部通过；后续仅记录结果的提交不修改已测代码。
- **仍未完成真实 VPS 验收。** 不得据容器烟测声称公网原链接、WG 出站、正常重启、掉线恢复、双向多轮交接已经验收。

## 下一步按顺序做

1. 核对 main 最新提交与 CI，先读 PROGRESS.md。不要重复修复已完成的 Reality/READY/RESUMED 项；新增发现须记录具体复现与影响。
2. 在两台有授权的测试 Debian 13 VPS 和外部客户端按 [VPS_ACCEPTANCE.md](VPS_ACCEPTANCE.md) 演练完整 CLI、SSH、systemd、普通/NAT 原链接及 WG。没有实际环境时这项保持未执行。
3. 重点执行 READY 自然到期/原 GC 删除后重启（部分及全部节点）、RESUMED 已有新增流量后中断重试、真实 watchdog→systemctl restart→gate 锁路径。保留 443/WG 摘要；不重放旧余额。
4. 验收结果按用例填写程序提交、环境版本、实际/预期和时间，只保存脱敏摘要。每个后续阶段提交本仓库并更新 PROGRESS.md；真实用户凭据、私钥、快照、服务器日志不得上传。

## Reality 夹具与边界

- 固定官方 Xray v26.10.31，ZIP SHA-256：`e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`。没有改变版本来绕开旧失败。
- `tests/tls_target.py` 在每个连接线程完成 TLS 1.3 握手，支持 Xray 的并发 ALPN/CCS 探测。`test_reality_fixture.py` 用真实 TLS socket 验证未完成握手不会阻塞下一客户端。
- `reality_smoke.py` 只在一次性容器执行。HTTP 目标地址 `93.184.216.34/32` 绑定在该 netns 的 lo，先断言 local 路由，不访问公网。业务域名只通过容器 hosts 覆盖；保留节点原链接和 freedom/NAT 出站配置。
- 三个公开合成节点使用三套独立 Reality 密钥；普通与带 mark NAT 认证测试均通过，**带 mark 不等于 WG 出站**。`show=false` 避免输出派生握手材料。

## 代码导航

| 位置/函数 | 作用与关键约束 |
|---|---|
| qianyi.py / validate_node | 元数据 literal 解析；原 config/URL 原文保留；逐节点公私钥、UUID、SNI、SID、业务域名、type/归属校验；NAT 链接使用 SERVER_ADDR，不以安装域名 PUBLIC_DOMAIN 覆盖 |
| quota_live / settled_quota | 严格读取 named quota.used 与 in/out counter，取两者较大值加 SAVED_USED，再封顶总额；读取失败不可当零；完全耗尽时验证无条件 drop |
| apply_due | 按原 30 天周期推进原 NEXT_RESET_EPOCH；已到期不重置；不重新发放额外周期 |
| probe / check_profile | 只读检查 Debian 13、root、时钟、精确安装产物、目标为空、端口、未知残留、Xray 版本、WG 元组与路由；不修复 WG |
| freeze | 重读最新状态；协调 timers/workers，持原锁；清空迁移期间 ExecStopPost、加端口屏障、停源；settlement.json 在任何计数重建前落盘，随后 snapshot.json / SEALED |
| target_stage / import_write | 目标屏障内写前归属日志；restore-intent.json 固定导入重置时刻；先配额/IP/ban/portbw，再启监听；READY 重试不直接重放导入 |
| recover_ready | 仅从未 OPEN 的目标重启恢复；锁内读目标当前持久余额；到期且已停止的节点不重建文件/限速，未到期缺文件拒绝 |
| target_open / worker | 先落盘 OPEN，再去屏障；源请求前记 OPEN_UNCERTAIN；回复丢失先查询，OPEN 后拒绝旧 stage/abort |
| retire_source | 源继续屏障，原文件归档到私有 originals/；保留源快照，不自动重装 |
| source_abort / finish_source_resume | 先获得目标永久 ABORTED 且无监听的证明；RESUMED 在原生锁内读/验当前状态，锁外启动，二次验证后收尾；不重放快照 |
| current_nodes / verify_target | 在原生锁内读当前存活节点，核对原身份/期限/JSON/URL/unit；到期节点须无服务及监听；不补缺失文件 |
| gate | 原 watchdog 持 temp.lock 等 systemctl restart；gate 现已改为只取得 LOCKS[1:]，避免父子死锁；有实际文件锁回归测试 |
| boot_restore | 恢复迁移屏障和暂停；重定基自动限速时钟；核对当前原生 blacklist 恢复结果，避免恢复失败放行；不从旧快照重新封禁已被合法解除的 IP |
| rebase_bandwidth / install_bandwidth | 不复制源网卡/TC 槽位；目标自行分配；保留策略、当前速度及 hold/cooldown，先结算 last_busy_at + hold 再跨机转换截止时间 |
| remote / agent | 正常 root SSH、真实公网 IPv4、严格主机密钥校验；安全的 JSON 错误回传；不记录含凭据的 subprocess stderr |
| refresh_subscription | 直接执行原生 vless_temp_sub.sh 并继承持锁标志；不另起 systemd 子任务等待父锁 |

## 必须保留的设计事实

- 固定原始源码提交：3e1972393cd9e6f097b27b76f919a649def61ae4。不能直接拿移动的 jieshu main 更新哈希。
- 兼容清单含 39 个安装产物、两种 systemd 模板及原始源码 SHA。最初网页文本多了结尾换行的错误已经修复；tools/build_profile.py 现校验关键文件 Git blob ID。
- 源的持久余额与内核计数是两个部分；只有停止用户流量及后台写入后才可最终结算。source settlement WAL 的作用是避免崩溃重试重复累加旧计数。
- 源主要阶段：PREPARING / PREPARED / FREEZING / SEALED / TRANSFERRING / OPEN_UNCERTAIN / RETIRED；撤销后 RESUMED。目标：PREPARED / STAGING / READY / OPEN，或 ABORTING / ABORTED。
- 目标 OPEN 是不可逆的余额所有权提交点。不能以“网络没收到回复”为由恢复源。
- qianyi_fence 是自有、带标记的 per-port 输入/输出屏障；不 flush 整机规则。
- 原 NAT ExecStartPre 会调用修改网络的 guard；迁入节点改用只读 gate。不能恢复为调用原 guard 的启动路径。
- 流量 quota、IP 防护、黑名单、限速都要先于用户端口开放。动态 IP 槽位和限速采样基线重新建立，配置和已有有效限制继续。
- 当前严格拒绝未知版本/自定义 unit/规则；这是保护状态完整性的边界，不能加随意 --force 绕过。

## 冷启动接续

普通开发机执行（不需要用户 VPS）：

    git clone https://github.com/liucong552-art/qianyi.git
    cd qianyi
    python3 -m unittest discover -s tests -v
    python3 -m py_compile qianyi.py tools/build_profile.py tests/reality_smoke.py
    python3 qianyi.py build /tmp/qianyi-standalone.py
    python3 /tmp/qianyi-standalone.py --help

需要上游时，在独立目录 git init / fetch --depth=1 该固定提交，再 detached checkout。按 compatibility.json 的 sources 字典核对 SHA。GitHub 原始内容 API 应使用 base64 或 git clone 得到准确字节，不要从显示文本推断结尾换行。正常继续开发不用重新生成 compatibility.json。

所有会实际操作 nft/tc 的 tests/nft_kernel.py、tests/native_portbw.py，以及修改测试容器 hosts 的 tests/reality_smoke.py，只能按 workflow 在一次性隔离容器运行；不得在生产 VPS 直接执行。

## 保存策略

GitHub 是持久事实来源；临时源码副本、导入的 Python 模块、工具变量、运行进程都可重新构建。关键证据 fixtures 和失败摘要已保存。不要承诺保留聊天后台状态，不要复制真实迁移运行目录到公开仓库。
