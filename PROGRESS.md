# qianyi 开发进度

目标：独立开发 jieshu 临时用户节点迁移工具，支持 Debian 13 两台 root VPS 任意方向反复轮换。保留每个节点的原业务域名、端口、UUID、独立 Reality 凭据、名称/归属、普通或 WG-NAT 类型，以及实时结算后的用量、周期/到期、IP/限速/禁用限制。

范围：不迁移 443，不改目标 WG/NAT，不改 DNS，不重装源机，不监控服务商额度。目标需实查为空；未知版本/残留/计数读取失败应拒绝。最终交接先冻结源流量及后台写入，再结算、快照、恢复目标防护、验证、放行。禁止旧余额重放；接管后回退需以新用量重新迁移。

## 当前状态（2026-11-06 接续）

**本轮代码、测试和操作说明已完成并分阶段提交 main；仍待真实 VPS 验收。** 最后包含测试变更的提交为 `1c40cc077edb947eb83f057649443236b69763cb`，完整 CI [42238894007](https://github.com/liucong552-art/qianyi/actions/runs/42238894007) 的 unit / debian13-nft 均成功。后续仅保存这份结果与交接文档，不改变已测代码。

已从 GitHub main `fdb6d86` 接手，核对分支、提交与五份交接文档；没有使用原聊天或旧临时目录。原代码基线 58 项 unittest 已在本次环境重新通过。

### 阶段 1：Reality 烟测诊断与测试夹具修复

- 使用校验过 SHA-256 的官方 Xray v26.10.31，在非特权本地诊断程序中复现旧夹具 curl 28。该诊断只测普通节点，连接地址临时指向 loopback，不算完整原 URL / NAT 验收。
- 串行 OpenSSL `s_server` 无法同时处理 Xray 的 ALPN/CCS 后台探测和实际握手。改为逐连接线程 TLS 1.3 目标后，日志出现 `hs.readClientFinished() err: <nil>`、`uConn.Verified: true`，证明原合成 Reality 凭据可认证。
- 随后发现第二层失败：v26.10.31 freedom 默认阻断 VLESS 的私网/回环目标，日志为 `blocked target ... blackholing connection`。源码依据和复现过程见 docs/TESTING.md。
- 完整烟测改用隔离 netns 内本地绑定的全局地址类别 /32，并断言路由为 local/lo；不修改原节点 freedom/NAT 出站策略，不访问外部 HTTP。保持错误公钥拒绝、多轮、三个独立密钥等原断言。
- 新增真实 TLS socket 并发回归，本次 59 项 unittest 及 Python 编译通过；提交 `f1ac316` 的完整 CI 已通过：[42236445140](https://github.com/liucong552-art/qianyi/actions/runs/42236445140)。unit 与 Debian 13 job 均 success，日志确认原生 nft/portbw 及原 URL Reality 多轮/错误公钥测试均完成。真实 VPS 仍未执行。

### 阶段 2：READY / RESUMED 到期与锁边界

- READY 重启恢复跳过已到期节点的文件、quota/IP 和限速重建；原生 GC 删除 unit 时不因 stop 返回失败直接中断，但必须确认服务停止、无残留监听。所有未到期节点仍要求完整当前文件，禁止从快照补回缺失凭据/余额。
- 新增 current_nodes：在原生锁内读取当前元数据，核对原身份/期限与 JSON/URL/unit，沿用当前持久余额及 IP 配置。已到期节点仅在无活动服务/监听时排除；不延长期限。
- RESUMED 前后两次持 temp→quota→IP→portbw→blacklist 锁读取与验证；中间释放锁再调用 systemd start，避免父进程等待门禁子进程。收尾不恢复旧配额、限制或限速，不重新依赖 SSH；丢失实时计数则拒绝而非清零。
- verify_target 的读取与验证进入同一原生锁边界。撤销后的防护恢复步骤跳过到期节点；冻结结算步骤仍保留其审计数据。
- 本地 **73 项 unittest 通过**，Python 编译、diff whitespace 检查通过。新增 14 项到期/故障/真实 flock 回归；systemd/nft 仍为夹具，不能称为系统集成验收。
- 阶段 2 提交 `9f026cd` 的 [完整 CI 42237634038](https://github.com/liucong552-art/qianyi/actions/runs/42237634038) 已确认 unit、debian13-nft 两项均成功。旧失败证据 docs/CI_LAST_FAILURE.txt 保留。

### 阶段 3：复核、操作与交接文档

- 更新 README、HANDOFF、RECOVERY、VPS_ACCEPTANCE、SOURCE_AUDIT、TESTING，移除过时的“仍暂停/Reality 失败/RESUMED 需 SSH”现状描述；保留旧失败原文作为历史。
- 写明 READY / RESUMED 自然到期、文件缺失、残留监听、锁等待的操作与停止条件；真实 VPS 清单增加部分/全部到期、重置中断、收尾前后新增流量、watchdog restart/gate 锁与 GC/save/reset 并发验证。
- 代码复核确认：READY 仅未 OPEN 可恢复，RESUMED 不调用旧快照恢复；metadata/防护读验同锁，systemd start 在锁外；原身份、期限、链接和独立凭据继续校验。443/WG 的摘要保护及固定兼容清单未改变。
- 增强现有回归：70 GiB 持久 + 3 GiB 实时用量场景直接执行 verify_protection；错误公钥拒绝后立即用同一服务正确原 URL 重连，避免把服务异常误判为拒绝认证。
- 本地 73 项测试、Python 编译、standalone 构建/帮助、diff 检查通过；固定上游 7 个源文件 SHA-256 与 39 个产物清单核对一致，未运行安装器。阶段 3 提交 `1c40cc0` 的 [完整 CI 42238894007](https://github.com/liucong552-art/qianyi/actions/runs/42238894007) 已通过，并核对两个 job 的步骤与测试摘要。

## 之前的开发记录（历史，非当前验收结论）

接续检查点：已修复 gate 等待 watchdog 的 temp.lock、RESUMED 收尾不必要的 SSH 依赖，补齐原生 IP 防护完整表达式校验、孤立防护对象检查及订阅刷新。53 项本地测试通过；新的 CI 结果待确认。真实 nft JSON 已固化为 tests/fixtures/nft-iplimit-debian13.json，不再依赖会过期的 CI 日志。

继续检查点：提交 2c09d21 的两项 CI 均通过（运行 42231122138）。后续修正了 portbw.owned 返回二元组导致空目标误报的问题，以及滚动限速 last_busy_at 截止时间结算，补查 portbw unit 与目标 tc 能力；54 项单元测试通过，新增真实 portbw/nft/tc 集成测试待 CI 确认。

最新检查点：f42d3d6 的真实 portbw/nft/tc 集成已通过（运行 42232358917），包括保留 443 策略和网卡 root qdisc、静态/自动策略、目标 tc 槽位及失败重试。新增远端安全错误回传、CIDR 基链验证、黑名单启动失败拦截；58 项本地测试通过。新增固定官方 Xray v26.10.31 的真实认证烟测待 CI 确认；该测试明确不覆盖真实 WG/systemd/SSH/VPS。

- 本项目直接在指定仓库 main 分阶段提交；最近提交历史是实际持久检查点。
- 已完成源码审计，固定上游提交 3e1972393cd9e6f097b27b76f919a649def61ae4，详见 docs/SOURCE_AUDIT.md。
- 已实现第一版独立 Python 程序：只读预检、SSH、systemd 后台交接、冻结/结算/快照、目标恢复、不可重放状态、重试/撤销/归档、逐节点凭据及限制校验。
- 已生成 39 个安装产物哈希的兼容性清单。
- 已实际通过 48 项本地 unittest，包括两轮余额续接、不同 Reality 密钥、NAT 独立业务域名、计数读取失败、结算断点恢复、OPEN 后禁止回放、先防护后启动、元数据安全解析、原生限制识别；Python 编译和 standalone 构建/帮助检查通过。
- 已补全中文 README、故障恢复说明、真实 VPS 验收清单。
- GitHub Actions 第一轮两个 job 均通过：[运行记录](https://github.com/liucong552-art/qianyi/actions/runs/42191850012)。Debian 13.7 / nftables 1.1.3 容器内实际 TCP 流量计入 8728 字节，IP 集合、CIDR、暂停和原子迁移屏障通过。
- 已追加 READY 阶段重启恢复、导入重置意图持久化、RESUMED 恢复收尾测试。
- 第二轮真实上游库 CI 暴露了源码文本末尾多一个换行造成的整文件哈希问题；已用原始 Git blob 校正所有源码字节，并让 build_profile.py 验证固定 Git blob ID。不要从网页文本重新生成哈希。
- 最新代码提交 `a44345912c8dc0a0d5b6dcc4bd0b39084cefa9c9` 的两个 CI job 均已通过：[运行记录](https://github.com/liucong552-art/qianyi/actions/runs/42193015826)。此轮直接从固定上游 vless.sh 提取 common/quota/IP 库，在隔离 Debian 13 容器中实际执行恢复、TCP 计量、结算、耗尽规则、限制识别及屏障检查。
- **尚未完成真实 VPS 验收，不能据此声称可直接用于生产。** 没有服务器登录信息，也没有对真实用户节点执行任何操作。

## 本轮持久检查点

| 提交 | 内容 | 实际结果 |
|---|---|---|
| `f1ac316` | Reality TLS/HTTP 夹具修复与根因证据 | CI 42236445140 全部成功；59 项 unittest |
| `9f026cd` | READY 到期恢复、RESUMED 当前状态与锁、14 项回归 | CI 42237634038 全部成功；73 项 unittest |
| `1c40cc0` | 操作/交接文档、增强真实验证逻辑及认证负例 | CI 42238894007 全部成功；73 项 unittest |

最终容器日志：Debian 13.7、nftables 1.1.3，TCP 实际计入 8728 字节；上游 quota/IP/nft、portbw/tc、Xray 26.10.31 原 URL/三套密钥/多轮及错误公钥检查完成。完整 CLI/SSH/systemd/WG/真实 VPS 均未执行。没有上传真实用户凭据、私钥、迁移快照或服务器日志。

## 接续方法

先阅读本文件、README.md 和 docs/SOURCE_AUDIT.md，查看最近提交、运行测试，再从未完成项继续。真实用户快照、凭据和私钥永不进入本仓库。每个阶段将更新此文件并提交。

## 待完成（当前）

1. 两台测试 Debian 13 VPS + 外部客户端执行完整 CLI / SSH / systemd / WG / 公网原链接验收。尚无真实 VPS 信息，此项未执行。
2. 按 docs/VPS_ACCEPTANCE.md 重点测试真实 watchdog/gate 与 GC/save/reset 锁调度、READY 自然到期清理后重启、RESUMED 已有新增用量后收尾、多轮双向迁移；每项记录实际结果，不用模拟结果替代。

## 已保存的实现与测试边界

- `qianyi.py`：Python 标准库 CLI，preflight/prepare/migrate/cutover/resume/abort/status/verify/confirm；root SSH 控制连接、systemd 后台 worker、持久事务、源最终结算 WAL、目标导入 WAL、端口屏障、保护恢复、源归档。
- `compatibility.json` / `tools/build_profile.py`：固定上游提交的 39 个产物哈希与两种 unit 模板；只解析源码，不运行安装器。
- `tests/test_qianyi.py` / `tests/test_recovery.py` / `tests/test_reality_fixture.py`：合计 73 项本地测试通过；真实 OpenSSL 公钥推导、TLS sockets、flock；systemd/nft 恢复路径使用受控夹具/故障注入。
- `tests/nft_kernel.py` / `tests/native_portbw.py` / `tests/reality_smoke.py` / workflow：隔离容器内执行真实 quota/IP/nft、portbw/tc、Xray Reality 认证；不测试完整 CLI、WG、SSH 或 systemd 重启。
- `docs/SOURCE_AUDIT.md`、`README.md`、`docs/RECOVERY.md`、`docs/VPS_ACCEPTANCE.md`：源码依据、中文操作、失败恢复、待执行验收。
- 上游固定为 `3e1972393cd9e6f097b27b76f919a649def61ae4`，以后继续先检查当前仓库进度；不能直接用移动的 upstream main 替换兼容清单。
- 没有用户服务器登录凭据，没有接触生产节点；仓库不含真实用户快照或私钥。

