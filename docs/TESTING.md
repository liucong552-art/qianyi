# 自动化测试证据与边界

## Reality 失败诊断（2026-11-06）

原始失败保留于 [CI_LAST_FAILURE.txt](CI_LAST_FAILURE.txt)，对应提交 `943bd3e`、运行 42233920479。不是通过记录。

本次用同一官方 Xray v26.10.31 二进制并核对 workflow 固定 SHA-256，在非特权本地诊断程序中逐步复现：

1. 保持旧 OpenSSL `s_server`，仅将测试客户端拨号改成 loopback；普通节点仍 curl 28，服务端仅到 `hs.c.conn == conn: true`。
2. 只将 TLS 目标换成并发 Python/OpenSSL TLS 1.3 服务，出现 `hs.handshake() err: <nil>`、`hs.readClientFinished() err: <nil>` 和客户端 `uConn.Verified: true`。下一处失败为 freedom 的 `blocked target: tcp:127.0.0.1:...`。这证实存在两个独立的测试环境问题，不是密钥推导错误。
3. 完整 CI 夹具保持原链接与出站 JSON，在一次性 netns 的 lo 上绑定 `93.184.216.34/32` 作为本地 HTTP 目标，断言路由类型为 local、设备为 lo，离开测试时删除。该地址只是隔离命名空间内的本地别名，不会访问该公网服务器。TEST-NET、benchmark 和回环地址均在该 Xray 版本默认拦截表中。

官方版本依据：

- [Xray go.mod](https://github.com/XTLS/Xray-core/blob/v26.10.31/go.mod) 固定 REALITY 依赖为 `83f621788ca8`。
- [REALITY record_detect.go](https://github.com/XTLS/REALITY/blob/83f621788ca8/record_detect.go) 为各 ALPN 并发启动握手记录/CCS 探测；串行测试服务会被未完成握手占住。
- [freedom.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/freedom/freedom.go) 的 `getDefaultFinalRule` 对 VLESS 默认应用 private IP 拦截。
- [geodata/consts.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/common/geodata/consts.go) 定义被拦截的回环、私网及特殊用途地址范围。

本地诊断不等同于原 URL/NAT 全套烟测；随后阶段 1 提交 `f1ac316` 的完整 CI [42236445140](https://github.com/liucong552-art/qianyi/actions/runs/42236445140) 两个 job 均通过，已从日志核对所有原断言完成。未修改生产节点配置校验，也没有删除失败断言。`show` 恢复为 false，避免输出握手派生材料。

## 各层测试分别证明什么

| 层级 | 内容 | 不能证明 |
|---|---|---|
| unittest | 数据验证、用量/重置、故障注入、真实 flock、并发本地 TLS socket | 两台 VPS/systemd/WG/SSH |
| nft_kernel.py | 固定上游 quota/IP 库、真实 nft 内核、TCP 计量与屏障 | Reality 握手、完整 CLI |
| native_portbw.py | 固定上游 portbw、真实 nft/tc、时钟接续、保留 443/root qdisc | 公网吞吐、真实 WG |
| reality_smoke.py | 固定 Xray、普通及带 mark 节点、原 URL、三套独立密钥、进程替换、多轮新增、错误公钥拒绝 | 完整迁移 CLI、SSH、systemd 重启、WG 出站、公共 DNS |
| [VPS_ACCEPTANCE.md](VPS_ACCEPTANCE.md) | 真实双机全流程验收清单 | 尚未执行，不能填通过 |

涉及 nft/tc/hosts/IP 的脚本只能在 workflow 指定的一次性容器执行。不能在用户生产 VPS 上直接运行。

## READY / RESUMED 回归（阶段 2）

本地共 73 项 unittest 通过。`tests/test_recovery.py` 使用真实私有临时文件及真实 flock，模拟 systemd/监听/nft；14 项新增用例覆盖：部分或全部节点已到期且文件已删、到期边界相等、未到期节点六类文件缺失、stop 失败且仍 active、到期节点残留监听、期限遭修改、READY 重置落盘后中断重试、RESUMED 最新 70 GiB 持久用量加 3 GiB 实时计数保持、实时计数缺失拒绝、启动时跨越到期、读取和验证持锁、systemd start 不持原生锁、verify 到期计数。

这些测试不启动真实 systemd、SSH、WireGuard；完整系统恢复仍按 VPS_ACCEPTANCE.md 验收。阶段 2 `9f026cd` 的完整 CI [42237634038](https://github.com/liucong552-art/qianyi/actions/runs/42237634038) 已通过两个 job。

## 最终复核（阶段 3）

在上述回归中，最新用量场景已增强为直接调用 verify_protection（真实生产验证函数，内核输入仍是合成夹具）；Reality 负例后增加同一服务的正确原 URL 重连。本地 73 项测试、py_compile、standalone 构建/帮助及 diff 检查通过，固定上游 7 个源文件 SHA-256 核对一致（兼容清单仍为 39 个产物）。本阶段完整 CI 待提交后确认，真实 VPS 仍未执行。
