# qianyi 开发进度

目标：独立开发 jieshu 临时用户节点迁移工具，支持 Debian 13 两台 root VPS 任意方向反复轮换。保留每个节点的原业务域名、端口、UUID、独立 Reality 凭据、名称/归属、普通或 WG-NAT 类型，以及实时结算后的用量、周期/到期、IP/限速/禁用限制。

范围：不迁移 443，不改目标 WG/NAT，不改 DNS，不重装源机，不监控服务商额度。目标需实查为空；未知版本/残留/计数读取失败应拒绝。最终交接先冻结源流量及后台写入，再结算、快照、恢复目标防护、验证、放行。禁止旧余额重放；接管后回退需以新用量重新迁移。

## 当前状态（2026-11-06）

**已按用户要求暂停，等待下次继续。当前版本不能直接用于生产：最后复查发现下述 gate 锁顺序问题，尚未修复。**

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

## 接续方法

先阅读本文件、README.md 和 docs/SOURCE_AUDIT.md，查看最近提交、运行测试，再从未完成项继续。真实用户快照、凭据和私钥永不进入本仓库。每个阶段将更新此文件并提交。

## 待完成

1. **优先修复 gate 死锁风险。** qianyi.py 的 gate() 当前使用 `locks(readonly=True)`，包含 temp.lock。真实上游 vless_managed_watchdog.sh 在持有 temp.lock 时调用 `systemctl restart`；ExecStartPre gate 再等待这把锁，会使重启失败，长期可能触发原 watchdog 清理。gate 应只取得检查防护必要的 quota/IP/portbw 等锁，不能再等父管理器持有的 temp.lock；核实原 watchdog 启动边界的其他锁状态，并增加回归测试。该修复尚未开始。
2. 继续复查 READY/RESUMED 的中断恢复；RESUMED 可能已经产生新流量，重试只能收尾，不能重新恢复旧快照。launch 对 RESUMED 仍会要求目标 SSH，可改为本机收尾；不要误把它当成新的迁移。
3. check_native_tables 对 IP 防护目前核对注释、端口、基链、集合容量/timeout/flags，但还未完整核对 refresh/claim/family/drop 的全部表达式。最新 CI 日志有 `native_ip_expressions=` 的真实 nft JSON（全部是合成测试资料）；可据此补强严格校验，防止未知条件被重建丢失。
4. 目标聚合订阅 `/root/vless_temp_subscription*.txt` 当前由原 watchdog 下一轮刷新；可在节点启动后调用已审计 vless_temp_sub.sh 及时刷新，注意它需要 temp 锁，不得在持锁进程中另起 systemd 等待。原用户链接已原文保留，此处是原管理审计完整性。
5. 最后一轮实现审查、更新 README/恢复说明及测试记录。README 状态仍应标为待真实 VPS 验收。
6. 按 docs/VPS_ACCEPTANCE.md 在两台测试 VPS 完成 Reality 实连、WG、systemd 启停/重启、掉线/重试、反向多轮验收；此项需要真实环境，未执行。

## 已保存的实现与测试边界

- `qianyi.py`：Python 标准库 CLI，preflight/prepare/migrate/cutover/resume/abort/status/verify/confirm；root SSH 控制连接、systemd 后台 worker、持久事务、源最终结算 WAL、目标导入 WAL、端口屏障、保护恢复、源归档。
- `compatibility.json` / `tools/build_profile.py`：固定上游提交的 39 个产物哈希与两种 unit 模板；只解析源码，不运行安装器。
- `tests/test_qianyi.py`：48 项本地测试实际通过；真实 OpenSSL 推导合成 Reality 公钥，其他系统行为使用受控夹具/故障注入。
- `tests/nft_kernel.py` / `.github/workflows/tests.yml`：在隔离容器调用真实上游 quota/IP 库和 nft 内核，不测试 Xray Reality 实连、WG 或完整 systemd 重启。
- `docs/SOURCE_AUDIT.md`、`README.md`、`docs/RECOVERY.md`、`docs/VPS_ACCEPTANCE.md`：源码依据、中文操作、失败恢复、待执行验收。
- 上游固定为 `3e1972393cd9e6f097b27b76f919a649def61ae4`，以后继续先检查当前仓库进度；不能直接用移动的 upstream main 替换兼容清单。
- 没有用户服务器登录凭据，没有接触生产节点；仓库不含真实用户快照或私钥。

