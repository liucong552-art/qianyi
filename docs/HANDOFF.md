# 接手说明：以本仓库为准，不依赖原聊天或临时工作目录

更新时间：2026-11-06（北京时间）。用户因额度不足要求立即暂停并保存，允许其他 AI 接手。不要把当前版本宣称为已完成生产验收。

## 最先阅读

1. PROGRESS.md：当前状态和最新检查点。
2. docs/REQUIREMENTS.md：已确认需求与范围，不要让用户重新说明。
3. docs/SOURCE_AUDIT.md：真实源码依据。
4. 本文件：实现导航、已验证内容、未完成事项。
5. README.md、docs/RECOVERY.md、docs/VPS_ACCEPTANCE.md：操作和待验收项目。

项目地址：https://github.com/liucong552-art/qianyi 。直接在此仓库保存阶段性代码、测试、结果和进度，不依赖对话记忆。不要上传真实用户快照、凭据、SSH 私钥或服务器日志。

## 当前结果：务必区分

- 迁移程序已经实现，非伪代码。尚未在真实 VPS 执行；未取得用户服务器登录信息。
- 58 项本地 unittest 已通过；最近 GitHub unit job 也通过。
- Debian 13.7 / nftables 1.1.3 容器中，真实上游 quota/IP 库的恢复、TCP 计量、结算、耗尽规则、暂停、CIDR、迁移屏障已通过。
- 同一隔离容器中，真实 portbw + nft/tc 恢复、静态上下载限速配置、自动 hold/cooldown、最近确认拥塞的期限、tc 槽位重试、保留原 443 策略/root qdisc 已通过。这不等于真实公网速率测试。
- **新增真实 Xray 认证烟测仍失败，整体 CI 目前为失败。** 最近代码提交 943bd3eeab374003da42d7b49e60dc37692a4ac1；运行 https://github.com/liucong552-art/qianyi/actions/runs/42233920479 。失败在 tests/reality_smoke.py 首个原链接连接，curl 退出码 28。此前两个原生脚本已成功。
- 最新失败日志的相关片段保存在 docs/CI_LAST_FAILURE.txt；全部来自合成测试，已过滤密钥相关诊断行。不要将这项失败掩盖或删掉断言来让 CI 变绿。

## 下一步按顺序做

1. 诊断并解决 Reality 烟测失败。先判断是隔离 TLS 测试目标、测试配置还是认证数据的问题，不能未经证据认定迁移代码或测试环境哪一方有错。烟测不执行完整迁移 CLI，也没有真实 WG。
2. 复核 recover_ready() 的到期边界：它当前读取快照所有节点文件；READY 后节点自然到期且原 ExecStopPost 已清理文件，再重启恢复时，可能因已到期节点文件缺失而停住。应遵循原到期规则，不能为了通过恢复而重建/延期已到期节点。这是暂停前发现的**待验证风险，尚未修复或增加测试**。
3. 复核 finish_source_resume()：已在 RESUMED 时禁止旧快照重放，并移除本机收尾对 SSH 的依赖；但 verify_protection 当前没有在此函数内持有原生锁，而且对已过期/被原 GC 删除节点的处理需补查。RESUMED 可能已经产生新流量，只能使用当前持久/内核状态，不能恢复旧余额。
4. 完成最终代码复核、针对上述发现的故障回归及中文文档更新。可增加 systemd/SSH 的隔离集成测试；不要把模拟调用当作两台真实 VPS 验收。
5. 按 VPS_ACCEPTANCE.md 明确列出仍待真实 VPS 的项目。没有 VPS 信息时不要凭空宣称普通/NAT 外部原链接、WG 出站和完整重启验收已通过。
6. 每阶段提交 GitHub，并更新 PROGRESS.md 的实际结果和未完成事项。最终交付也要给出明确的测试边界。

## Reality 测试现场

- tests/reality_smoke.py 在一次性 Debian 容器运行；用本地 OpenSSL s_server 作为 TLS 目标，Python HTTP 服务作为实际代理访问目标。
- 官方 Xray v26.10.31；ZIP SHA-256 固定为 e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214，下载和校验步骤已在 workflow 中。
- 使用 node() 产生的公开合成凭据，普通/NAT 两个节点、第三个后增节点，三个不同 Reality 密钥。准备覆盖替换进程后的原 URL、业务域名仅解析覆盖、错误公钥拒绝、多轮新增节点。
- NAT 配置保留 sockopt.mark，但测试没有 WireGuard；不能把它称作 WG 出站测试。
- 已尝试限制 OpenSSL TLS 目标为 X25519，并开启合成测试的调试日志；仍失败。Xray 自身 x25519 推导的公钥与 OpenSSL 推导已交叉核对，断言通过。
- 日志显示客户端开始拨号业务域名，服务端/本地 TLS 目标出现 bad certificate、unexpected CCS 等消息；根因尚未确认。
- 官方 Xray 配置来源可查看 XTLS/Xray-core 的 v26.10.31 / infra/conf/transport_security.go，包含 REALITYConfig 的 publicKey/password/dest/target 等解析；不要盲猜新版字段。

## 代码导航

| 位置/函数 | 作用与关键约束 |
|---|---|
| qianyi.py / validate_node | 元数据 literal 解析；原 config/URL 原文保留；逐节点公私钥、UUID、SNI、SID、业务域名、type/归属校验；NAT 链接使用 SERVER_ADDR，不以安装域名 PUBLIC_DOMAIN 覆盖 |
| quota_live / settled_quota | 严格读取 named quota.used 与 in/out counter，取两者较大值加 SAVED_USED，再封顶总额；读取失败不可当零；完全耗尽时验证无条件 drop |
| apply_due | 按原 30 天周期推进原 NEXT_RESET_EPOCH；已到期不重置；不重新发放额外周期 |
| probe / check_profile | 只读检查 Debian 13、root、时钟、精确安装产物、目标为空、端口、未知残留、Xray 版本、WG 元组与路由；不修复 WG |
| freeze | 重读最新状态；协调 timers/workers，持原锁；清空迁移期间 ExecStopPost、加端口屏障、停源；settlement.json 在任何计数重建前落盘，随后 snapshot.json / SEALED |
| target_stage / import_write | 目标屏障内写前归属日志；restore-intent.json 固定导入重置时刻；先配额/IP/ban/portbw，再启监听；READY 重试不直接重放导入 |
| recover_ready | 仅用于从未 OPEN 的目标重启恢复；读目标当前持久余额，不用源旧余额覆盖；到期缺失文件边界尚待检查 |
| target_open / worker | 先落盘 OPEN，再去屏障；源请求前记 OPEN_UNCERTAIN；回复丢失先查询，OPEN 后拒绝旧 stage/abort |
| retire_source | 源继续屏障，原文件归档到私有 originals/；保留源快照，不自动重装 |
| source_abort / finish_source_resume | 先获得目标永久 ABORTED 且无监听的证明，才能恢复源；RESUMED 收尾不能重新结算/导入旧快照 |
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
