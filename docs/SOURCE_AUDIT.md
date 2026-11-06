# 源码审计与设计依据

审计固定于 [jieshu 3e1972393cd9e6f097b27b76f919a649def61ae4](https://github.com/liucong552-art/jieshu/tree/3e1972393cd9e6f097b27b76f919a649def61ae4)。安装器没有足够可靠的统一版本号，因此以安装产物 SHA-256 校验兼容性；不自动升级生产机。

## 已阅读的关联

| 源文件 | 关键内容与迁移处理 |
|---|---|
| README.md | 创建/查询/重置/暂停/黑名单/限速/备份章节；暂停表 `pause_vless_PORT`、`jsh_cidrban`、旧 `jsh_ipban` 均不能忽略 |
| vless.sh 1643–2408 | common.sh、literal env、目录、节点身份；逐节点保留 Xray JSON 和原 `.url`，不读主节点私钥替换 |
| vless.sh 2632–3582 | IP 动态集合、配额保存、恢复、30 日周期；已用量=min(总额, SAVED_USED_BYTES+max(quota.used,入站counter+出站counter))；读失败绝非零 |
| vless.sh 4483–4589 | ExecStopPost 可能结算并删除到期节点；持 temp 锁可让 stop-post 退出，但为跨重启保护还需要持久暂停 drop-in |
| vless.sh 4661–5043 | env/json/url/unit 四者关联；配额/IP 归属 OWNER_KIND=temp、OWNER_TAG=TAG；恢复不能调用创建器或 pq_add |
| vless.sh 5058–5668 | 看门狗能拉起节点、清理到期及连续故障节点；启动门禁检查配额/IP；必须协调 workers 与锁，启动前恢复限制 |
| natjichang.sh | LANDING=nat；freedom 出站 sockopt.mark、routing tag；WG_IF/MARK/TABLE_ID/RULE_PRIORITY 需匹配目标已有环境 |
| vpswg.sh | guard 会修改路由及 iptables；原 NAT ExecStartPre 会调用 guard，迁入节点需替换为 qianyi 的只读检查，禁止以“预检”名义调用原 healthcheck/guard |
| portbw.py / portbw-install.sh | 独立按端口 JSON，tc slot/interface 是本机对象；保留策略和当前有效速度，重新分配目标 tc 槽位；自动限速 hold/cooldown 的 CLOCK_BOOTTIME 需转成跨主机截止时间再重建 |
| traffic.py | 每日展示统计独立于配额，不是余额来源；不迁移历史流量日志 |

## 事务原则

1. 只读发现/精确版本校验；空目标、端口、文件归属、未知 nft/tc 配置不满足即停止。
2. 提前在目标部署同一工具及事务目录，正式交接再重新读取最新节点。准备时的发现结果不是可导入快照。
3. 停止 timers 并等待短任务自然结束；用持久 systemd 条件阻止重新启动；按 temp → quota → iplimit → portbw → blacklist 顺序持锁。先装节点范围的输入/输出阻断，再停节点；ExecStopPost 被清空，保护恢复文件。
4. 在阻断、无节点进程、无后台写入下读取实时计数并生成一次性一致快照。任何计数失败保留冻结状态，不假设零，不导入。
5. 目标使用唯一事务编号及快照摘要，先阻断后导入；按原时间规则处理真正到期/周期重置；防护、限速、认证参数和监听检查后才能开放。
6. 开放前先落盘不可回放状态。开放响应丢失也不能重新导入；只读查询/验证可以重试。
7. 源机冻结保留至目标接管；不自动删除恢复资料、不自动重装。开放后的回退必须从新生产机产生新快照，禁止恢复旧余额。

## 验证边界

本地单元/仿真测试不能证明两台真实 Debian 13 的 nftables、tc、systemd、SSH 与 Reality 外网连接已通过。交付文档必须单列真实 VPS 验收项。

JSON 格式另核对 [Debian 13 libnftables-json(5)](https://manpages.debian.org/trixie/libnftables1/libnftables-json.5.en.html)：named quota 的 bytes/used/inv、named counter 引用、集合 timeout 单位为秒（不是内核 API 的毫秒）、动态 set 操作、th 端口及 concat 表达式。内核真实输出兼容性仍需 VPS 验收。
