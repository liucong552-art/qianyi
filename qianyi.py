#!/usr/bin/env python3
"""Two-VPS jieshu handover. The release runs from a private directory in /run."""

import argparse
import base64
import contextlib
import copy
from dataclasses import asdict, dataclass
import fcntl
import getpass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID


FORMAT = 1
MAX_PACKET = 32 * 1024 * 1024
MAX_STATE_FILE = 1024 * 1024
SOURCE_URL = "https://raw.githubusercontent.com/liucong552-art/qianyi/main/qianyi.py"
STATE = "/var/lib/vless-reality"
LOCK_DIR = "/run/vless-reality"
XRAY_DIR = "/usr/local/etc/xray"
XRAY = "/usr/local/bin/xray"
SYSTEMD = "/etc/systemd/system"
LIB = "/usr/local/lib/vless-reality"
SBIN = "/usr/local/sbin"
MAIN_FILES = {
    "meta": f"{STATE}/main/main.env",
    "config": f"{XRAY_DIR}/config.json",
    "url": "/root/vless_reality_vision_url.txt",
}
MAIN_SUB = "/root/v2ray_subscription_base64.txt"
MAIN_DEFAULTS = "/etc/default/vless-reality"
JOURNAL = f"{STATE}/.qianyi-recovery.json"
PROFILE = (
    f"{LIB}/common.sh",
    f"{LIB}/quota-lib.sh",
    f"{LIB}/quota-query.py",
    f"{LIB}/iplimit-lib.sh",
    f"{SBIN}/vless_run_temp.sh",
    f"{SBIN}/vless_cleanup_one.sh",
    f"{SBIN}/vless_temp_sub.sh",
)
NAT_PROFILE = f"{SBIN}/vless_nat_preflight.sh"
LEGACY = {
    "/root/jieshu_transfer.py": "f2b69aa4024671ea45f590028fe73b6b22c05ed8ec085046873b69a193a2df3f",
    "/root/jieshu_node_migrate_incremental.py": "e39bb58fa288a6571ca4bc7fd0584081834d0d9c8c7c67bfd779d8acdbfd46b9",
}
TAG = re.compile(r"vless-temp-[A-Za-z0-9._-]{1,96}")
IFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
KEY = re.compile(r"[A-Z][A-Z0-9_]*")
HEX = re.compile(r"[0-9a-f]{64}")
FENCE = re.compile(r"qianyi_[0-9a-f]{16}")


class MigrationError(Exception):
    pass


def require(ok, message):
    if not ok:
        raise MigrationError(message)


def exists(path):
    return os.path.lexists(path)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "JSON 含重复字段")
        value[key] = item
    return value


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_keys)


def encode_json(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def secure_read(path, max_bytes=MAX_STATE_FILE):
    path = Path(path)
    require(path.resolve() == path, f"拒绝符号链接路径 {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                f"文件必须由 root 拥有且不可由其他用户写入 {path}")
        require(info.st_size <= max_bytes, f"文件过大 {path}")
        data = stream.read(max_bytes + 1)
        require(len(data) <= max_bytes, f"文件过大 {path}")
        return data


def env_decode(data):
    result = {}
    for line in data.decode("utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, val = line.partition("=")
        require(sep and KEY.fullmatch(key) and key not in result, "节点元数据格式无效或字段重复")
        result[key] = val
    return result


def env_encode(value):
    return "".join(f"{key}={val}\n" for key, val in value.items()).encode()


def validate_env(value):
    require(isinstance(value, dict) and all(
        KEY.fullmatch(key) and isinstance(val, str) and not any(ord(c) < 32 for c in val)
        for key, val in value.items()
    ), "节点元数据含无效字段")


def number(raw, label, low=0, high=9_000_000_000_000_000_000):
    require(isinstance(raw, str) and bool(re.fullmatch(r"0|[1-9][0-9]{0,18}", raw)), f"{label} 格式无效")
    value = int(raw)
    require(low <= value <= high, f"{label} 超出范围")
    return value


def mark_value(raw):
    if isinstance(raw, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,8}", raw):
        return int(raw, 16)
    return number(raw, "MARK", 1, 2**32 - 1)


def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def pending_file(path):
    return path.with_name(f".{path.name}.qianyi-new")


def write_file(path, data, mode=0o600):
    path = Path(path)
    require(path.resolve() == path and path.parent.is_dir(), f"写入目录缺失或为符号链接 {path.parent}")
    temporary = pending_file(path)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def remove_file(path):
    path = Path(path)
    if exists(path):
        path.unlink()
        fsync_directory(path.parent)


@dataclass
class Node:
    tag: str
    port: int
    meta: dict
    config: dict
    url: str
    quota: dict | None = None
    iplimit: dict | None = None

    @property
    def main(self):
        return self.tag == "main"

    @property
    def unit(self):
        return "xray.service" if self.main else f"{self.tag}.service"

    @property
    def expiry(self):
        return 0 if self.main else number(self.meta.get("EXPIRE_EPOCH"), "EXPIRE_EPOCH", 1)

    @property
    def family(self):
        return self.meta.get("IP_VERSION", "4")

    @property
    def nat(self):
        return self.meta.get("LANDING") == "nat"

    def paths(self):
        if self.main:
            return MAIN_FILES
        return {
            "meta": f"{STATE}/temp/{self.tag}.env",
            "config": f"{XRAY_DIR}/{self.tag}.json",
            "url": f"{STATE}/temp/{self.tag}.url",
            "unit": f"{SYSTEMD}/{self.unit}",
        }


def policy_paths(port):
    return {"quota": f"{STATE}/quota/{port}.env", "iplimit": f"{STATE}/iplimit/{port}.env"}


def main_defaults(raw, meta):
    values = {key: meta[key] for key in ("PUBLIC_DOMAIN", "REALITY_DEST", "REALITY_SNI", "PORT")}
    values.update(CAMOUFLAGE_DOMAIN=meta.get("CAMOUFLAGE_DOMAIN", ""),
                  NODE_NAME=meta.get("NODE_NAME", "VLESS-REALITY-IPv4"))
    lines = []
    written = set()
    for line in raw.decode("utf-8").splitlines():
        match = re.match(r"^([ \t]*(?:export[ \t]+)?)([A-Z][A-Z0-9_]*)=", line)
        if match and match[2] in values:
            prefix, key = match.groups()
            lines.append(f"{prefix}{key}={shlex.quote(values[key])}")
            written.add(key)
        else:
            lines.append(line)
    lines.extend(f"{key}={shlex.quote(val)}" for key, val in values.items() if key not in written)
    return ("\n".join(lines) + "\n").encode()


def validate_policies(node):
    if not node.main:
        quota = node.meta.get("PQ_LIMIT_BYTES", "")
        require(bool(quota) == (node.quota is not None), f"端口 {node.port} 配额元数据不完整")
        limit = number(node.meta.get("IP_LIMIT", "0"), "IP_LIMIT")
        require((limit > 0) == (node.iplimit is not None), f"端口 {node.port} IP 限制元数据不完整")
    for policy in (node.quota, node.iplimit):
        if policy is None:
            continue
        validate_env(policy)
        require(policy.get("PORT") == str(node.port), f"端口 {node.port} 策略归属不符")
        if node.main:
            valid_owner = (policy.get("OWNER_KIND"), policy.get("OWNER_TAG", "")) in {
                ("manual", ""), ("main", ""), ("main", "main"),
            }
        else:
            valid_owner = (policy.get("OWNER_KIND"), policy.get("OWNER_TAG")) == ("temp", node.tag)
        require(valid_owner, f"端口 {node.port} 策略归属不符")
    if node.quota is not None:
        total = number(node.quota.get("ORIGINAL_LIMIT_BYTES"), "ORIGINAL_LIMIT_BYTES", 1)
        saved = number(node.quota.get("SAVED_USED_BYTES"), "SAVED_USED_BYTES", 0, total)
        left = number(node.quota.get("LIMIT_BYTES"), "LIMIT_BYTES", 0, total)
        require(saved + left == total and node.quota.get("REBUILD_PENDING", "0") == "0",
                f"端口 {node.port} 配额处于异常或待恢复状态")
        if not node.main:
            require(total == number(quota, "PQ_LIMIT_BYTES"), f"端口 {node.port} 配额总额不符")
        for field in ("RESET_INTERVAL_SECONDS", "NEXT_RESET_EPOCH", "EXPIRE_EPOCH"):
            number(node.quota.get(field, "0"), field)
    if node.iplimit is not None:
        ip_count = number(node.iplimit.get("IP_LIMIT"), "IP_LIMIT", 1, 65535)
        sticky = number(node.iplimit.get("IP_STICKY_SECONDS"), "IP_STICKY_SECONDS", 1, 2**31 - 1)
        family = node.iplimit.get("IP_VERSION", "4")
        require(family == node.family and node.iplimit.get("SET_NAME", f"vr_il{family}_{node.port}") ==
                f"vr_il{family}_{node.port}", f"端口 {node.port} 的 IP 限制与节点不符")
        if not node.main:
            require(ip_count == limit and sticky == number(node.meta.get("IP_STICKY_SECONDS"), "IP_STICKY_SECONDS"),
                    f"端口 {node.port} IP 限制数量或黏性时间不符")


def validate_node(node):
    require(isinstance(node.tag, str) and (node.main or TAG.fullmatch(node.tag)), "非法节点标识")
    require(type(node.port) is int and 1 <= node.port <= 65535 and (node.port == 443) == node.main,
            "443 必须是受管理主节点，临时节点端口必须不同")
    validate_env(node.meta)
    require(node.meta.get("PORT") == str(node.port), f"端口 {node.port} 与元数据不符")
    require(node.family in ("4", "6") and (not node.main or node.family == "4"), "入站协议族无效")
    if not node.main:
        require(node.meta.get("TAG") == node.tag and node.expiry > 0
                and node.meta.get("LANDING", "") in ("", "nat"), f"端口 {node.port} 临时节点元数据不符")
    cfg = node.config
    require(isinstance(cfg, dict) and set(cfg) <= {"log", "inbounds", "outbounds", "routing"},
            f"端口 {node.port} 包含非标准 Xray 配置")
    try:
        inbound, = cfg["inbounds"]
        stream = inbound["streamSettings"]
        reality = stream["realitySettings"]
        client, = inbound["settings"]["clients"]
        user = str(UUID(node.meta["UUID"]))
        sni = node.meta["REALITY_SNI"]
        short = node.meta["SHORT_ID"]
        public = node.meta["PBK"]
        dest = node.meta["REALITY_DEST"]
        matches = (
            inbound["port"] == node.port and inbound["protocol"] == "vless"
            and inbound["listen"] == ("::" if node.family == "6" else "0.0.0.0")
            and str(UUID(client["id"])) == user and client.get("flow") == "xtls-rprx-vision"
            and stream.get("security") == "reality" and stream.get("network") == "tcp"
            and reality["serverNames"] == [sni] and reality.get("dest") == dest
            and isinstance(reality.get("privateKey"), str) and bool(reality["privateKey"])
            and short in reality["shortIds"]
        )
        require(matches and (not node.main or reality["privateKey"] == node.meta["PRIVATE_KEY"]),
                f"端口 {node.port} Xray 配置与节点身份不符")
        require(isinstance(node.url, str) and node.url.strip() == node.url and len(node.url) <= 8192
                and all(ord(c) >= 32 for c in node.url), f"端口 {node.port} 链接格式无效")
        url = urlsplit(node.url)
        query = parse_qs(url.query)
        published = (node.meta.get("SERVER_ADDR") or node.meta["PUBLIC_DOMAIN"]) if node.nat else node.meta["PUBLIC_DOMAIN"]
        require(url.scheme == "vless" and str(UUID(unquote(url.username))) == user
                and url.port == node.port and url.hostname == published.strip("[]").lower()
                and query.get("sid") == [short] and query.get("pbk") == [public]
                and query.get("sni") == [sni] and query.get("security") == ["reality"]
                and query.get("flow") == ["xtls-rprx-vision"], f"端口 {node.port} 原链接与节点身份不符")
        if node.nat:
            require(IFACE.fullmatch(node.meta.get("WG_IF", "")), f"端口 {node.port} WireGuard 接口名无效")
            outbound, = [item for item in cfg["outbounds"] if item.get("tag") == "nat"]
            require(inbound.get("tag") == node.tag and cfg["routing"]["rules"] == [
                {"type": "field", "inboundTag": [node.tag], "outboundTag": "nat"}
            ] and outbound.get("protocol") == "freedom"
                    and outbound["streamSettings"]["sockopt"]["mark"] == mark_value(node.meta.get("MARK")),
                    f"端口 {node.port} NAT 路由与节点元数据不符")
        else:
            require(not cfg.get("routing") and [item.get("tag") for item in cfg["outbounds"]] == ["direct", "block"],
                    f"端口 {node.port} 普通节点包含非标准出站")
    except (KeyError, ValueError, AttributeError, TypeError):
        raise MigrationError(f"端口 {node.port} 的配置或原链接格式异常") from None
    validate_policies(node)
    return node


def parse_node(item):
    require(isinstance(item, dict) and set(item) == {"tag", "port", "meta", "config", "url", "quota", "iplimit"},
            "迁移包节点结构不支持")
    return validate_node(Node(**item))


def unique_nodes(nodes):
    require(len({n.port for n in nodes}) == len(nodes) and len({n.tag for n in nodes}) == len(nodes),
            "发现重复节点端口或标识")


def decode_bundle(packet):
    bundle = decode_json(packet)
    require(isinstance(bundle, dict) and set(bundle) == {"format", "profile", "nodes", "origin"}
            and bundle["format"] == FORMAT and isinstance(bundle["origin"], str) and HEX.fullmatch(bundle["origin"]),
            "迁移包版本不支持")
    require(isinstance(bundle["nodes"], list) and 1 <= len(bundle["nodes"]) <= 512
            and isinstance(bundle["profile"], dict), "迁移包结构无效")
    nodes = [parse_node(item) for item in bundle["nodes"]]
    unique_nodes(nodes)
    require(any(n.main for n in nodes), "迁移包缺少 443 主节点")
    return bundle["origin"], bundle["profile"], nodes


def plan_nodes(incoming, current):
    """Port is the collision key. An incoming internal tag may be renamed."""
    replaced = {n.port: current[n.port] for n in incoming if n.port in current}
    occupied = {n.tag for port, n in current.items() if port not in replaced}
    all_tags = occupied | {n.tag for n in incoming}
    planned = []
    for node in incoming:
        if node.tag in occupied:
            node = copy.deepcopy(node)
            tag = f"vless-temp-qy-{node.port}-{sha(node.tag.encode())[:12]}"
            require(tag not in all_tags, f"端口 {node.port} 的目标内部节点标识已占用")
            all_tags.add(tag)
            node.tag = tag
            node.meta.update(TAG=tag, ID=tag.removeprefix("vless-temp-"))
            for policy in (node.quota, node.iplimit):
                if policy is not None:
                    policy["OWNER_TAG"] = tag
            if node.nat:
                node.config["inbounds"][0]["tag"] = tag
                node.config["routing"]["rules"][0]["inboundTag"] = [tag]
            print(f"端口 {node.port} 内部标识改为 {tag}，原链接保留。", flush=True)
        planned.append(node)
    return planned, replaced


def unit_text(node):
    paths = node.paths()
    iface = node.meta.get("WG_IF")
    dependency = f"Requisite=wg-quick@{iface}.service\n" if node.nat else ""
    ordering = f" wg-quick@{iface}.service" if node.nat else ""
    preflight = f"ExecStartPre={NAT_PROFILE} {node.tag}\n" if node.nat else ""
    nat = " NAT" if node.nat else ""
    return f"""[Unit]
Description=Temporary VLESS{nat} {node.tag} IPv{node.family}
{dependency}After=network-online.target vless-managed-restore.service{ordering}
Wants=network-online.target
ConditionPathExists={paths['config']}
ConditionPathExists={paths['meta']}

[Service]
Type=simple
User=root
Group=root
{preflight}ExecStart={SBIN}/vless_run_temp.sh {node.tag} {paths['config']}
ExecStopPost={SBIN}/vless_cleanup_one.sh {node.tag} --from-stop-post
Restart=on-failure
RestartSec=3s
SuccessExitStatus=0 124 143
TimeoutStopSec=60
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def normalized_unit(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def guard_file(unit):
    return Path(SYSTEMD) / f"{unit}.d" / "80-qianyi-transaction.conf"


def permit_file(table):
    return Path(f"/run/{table}.permit")


def guard_data(table):
    return f"[Unit]\nConditionPathExists=|!{JOURNAL}\nConditionPathExists=|{permit_file(table)}\n".encode()


class Host:
    def __init__(self, work):
        self.work = work

    def run(self, *args, input_data=None, check=True, timeout=60, env=None):
        command = [str(arg) for arg in args]
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"BASH_ENV", "ENV", "CDPATH"} and not key.startswith(("VR_", "BASH_FUNC_"))}
        environment.update(LC_ALL="C", PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        environment.update(env or {})
        try:
            result = subprocess.run(command, input=input_data, env=environment, text=True,
                                    capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise MigrationError(f"命令不可用或执行超时 {Path(command[0]).name}") from None
        require(not check or result.returncode == 0,
                f"命令失败 {Path(command[0]).name} {' '.join(command[1:3])}（退出码 {result.returncode}）")
        return result

    @contextlib.contextmanager
    def lock(self, *names):
        with contextlib.ExitStack() as stack:
            for name in names:
                path = Path(LOCK_DIR) / name
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                stack.callback(os.close, fd)
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                        f"无效的 jieshu 锁 {name}")
                deadline = time.monotonic() + 30
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        require(time.monotonic() < deadline, f"jieshu 锁繁忙 {name}")
                        time.sleep(0.1)
            yield

    def temp_lock(self):
        require(Path(LOCK_DIR).is_dir() and Path(LOCK_DIR).resolve() == Path(LOCK_DIR),
                "缺少 jieshu 运行目录，请先安装并启动 jieshu")
        return self.lock("temp.lock")

    def policy_lock(self):
        return self.lock("portquota.lock", "iplimit.lock")

    def native(self, script, *args):
        preamble = f"""set -Eeuo pipefail
source {LIB}/quota-lib.sh
source {LIB}/iplimit-lib.sh
"""
        return self.run("/bin/bash", "-c", preamble + script, "qianyi", *args,
                        env={"VR_TEMP_LOCK_HELD": "1", "VR_PQ_LOCK_HELD": "1", "VR_IL_LOCK_HELD": "1"}).stdout.strip()

    def profile(self, nat):
        paths = (*PROFILE, NAT_PROFILE) if nat else PROFILE
        result = {path: sha(secure_read(path)) for path in paths}
        require(os.access(XRAY, os.X_OK), "目标机缺少可执行 Xray")
        return result

    def identity(self):
        raw = secure_read("/etc/machine-id").strip()
        require(re.fullmatch(rb"[a-f0-9]{32}", raw) and raw != b"0" * 32, "本机 machine-id 无效")
        return sha(raw)

    def inventory(self):
        nodes = {}
        for path in sorted((Path(STATE) / "temp").glob("vless-temp-*.env")):
            require(TAG.fullmatch(path.stem), f"无效的 jieshu 节点文件 {path.name}")
            meta = env_decode(secure_read(path))
            port = number(meta.get("PORT"), "PORT", 1, 65535)
            require(meta.get("TAG") == path.stem and port not in nodes and port != 443,
                    f"临时节点归属异常或端口重复 {path.name}")
            nodes[port] = Node(path.stem, port, meta, {}, "")
        main = env_decode(secure_read(MAIN_FILES["meta"]))
        require(main.get("PORT") == "443", "两台机器都须已有 jieshu 的 443 主节点")
        nodes[443] = Node("main", 443, main, {}, "")
        return nodes

    def read_node(self, entry):
        paths = entry.paths()
        config = decode_json(secure_read(paths["config"]))
        url = secure_read(paths["url"]).decode("utf-8").rstrip("\n")
        rules = {
            name: env_decode(secure_read(path)) if exists(path) else None
            for name, path in policy_paths(entry.port).items()
        }
        return validate_node(Node(entry.tag, entry.port, dict(entry.meta), config, url, **rules))

    def sys(self, *args, check=True, timeout=65):
        return self.run("systemctl", *args, check=check, timeout=timeout)

    def property(self, unit, name):
        return self.sys("show", "--property", name, "--value", unit).stdout.strip()

    def active(self, unit):
        return self.sys("is-active", "--quiet", unit, check=False).returncode == 0

    def enabled(self, unit):
        state = self.sys("is-enabled", unit, check=False).stdout.strip()
        require(state in {"enabled", "disabled"}, f"{unit} 启用状态异常 {state or '未知'}")
        return state == "enabled"

    def check_unit(self, node):
        path = f"{SYSTEMD}/{node.unit}"
        installed = secure_read(path).decode("utf-8")
        require(self.property(node.unit, "FragmentPath") == path and not self.property(node.unit, "DropInPaths"),
                f"{node.unit} 有自定义路径或 drop-in，拒绝自动替换")
        if node.main:
            require(self.property(node.unit, "User") == "root"
                    and f"argv[]={XRAY} run -config {MAIN_FILES['config']} ;" in
                    self.property(node.unit, "ExecStart"), "目标 443 服务并非标准 jieshu 主节点")
            for hook in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost"):
                require(not self.property(node.unit, hook), f"443 服务存在自定义 {hook}")
        else:
            require(normalized_unit(installed) == normalized_unit(unit_text(node)),
                    f"{node.unit} 包含自定义内容或 jieshu 版本不支持")

    def listeners(self, ports):
        result = {}
        for line in self.run("ss", "-H", "-ltnp").stdout.splitlines():
            cols = line.split()
            if len(cols) < 5:
                continue
            local = cols[3].rpartition(":")[2]
            if not local.isdecimal() or int(local) not in ports:
                continue
            port = int(local)
            pids = {int(pid) for pid in re.findall(r"\bpid=(\d+)\b", line)}
            require(pids, f"端口 {port} 监听者归属未知")
            result.setdefault(port, set()).update(pids)
        return result

    def owns(self, unit, pids):
        group = self.property(unit, "ControlGroup")
        if not group:
            return False
        for pid in pids:
            try:
                groups = [line.split(":", 2)[-1] for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()]
            except FileNotFoundError:
                return False
            if not any(path == group or path.startswith(group + "/") for path in groups):
                return False
        return True

    def inspect_owners(self, ports, nodes):
        listeners = self.listeners(ports)
        for port, pids in listeners.items():
            node = nodes.get(port)
            require(node is not None and self.owns(node.unit, pids),
                    f"端口 {port} 被其他服务占用，拒绝停止或覆盖")
        return listeners

    def capture_quota(self, node):
        if node.quota is None:
            return
        status, total, used, left = self.native('vr_pq_snapshot_unlocked "$1"', node.port).split("|")
        require(status in {"active", "exhausted"} and total == node.quota["ORIGINAL_LIMIT_BYTES"],
                f"端口 {node.port} 实时配额读取失败或保护状态异常")
        node.quota.update(SAVED_USED_BYTES=used, LIMIT_BYTES=left, LAST_SAVE_EPOCH=str(int(time.time())))
        validate_policies(node)

    def policy_state(self, node):
        if node.quota is not None:
            status = self.native('vr_pq_snapshot_unlocked "$1"', node.port).split("|", 1)[0]
            require(status in {"active", "exhausted"}, f"端口 {node.port} 配额规则未就绪")
        if node.iplimit is not None:
            require(self.native('vr_il_state "$1"', node.port) == "active", f"端口 {node.port} IP 限制未就绪")
        elif not node.main:
            require(self.native('vr_il_family_guard_state "$1"', node.port) == "active",
                    f"端口 {node.port} 协议族隔离未就绪")

    def capture_ip_slots(self, node):
        if node.iplimit is None:
            return []
        name = f"vr_il{node.family}_{node.port}"
        data = decode_json(self.run("nft", "-j", "list", "set", "inet", "vr_iplimit", name).stdout)
        entry, = [item["set"] for item in data["nftables"] if "set" in item and item["set"]["name"] == name]
        now = int(time.time())
        slots = []
        for item in entry.get("elem", []):
            require(isinstance(item, dict) and "elem" in item,
                    f"端口 {node.port} 的 IP 黏性集合格式不支持")
            elem = item["elem"]
            address = ipaddress.ip_address(elem["val"])
            seconds = elem.get("expires")
            require(address.version == int(node.family) and type(seconds) is int and seconds >= 0,
                    f"端口 {node.port} 的 IP 黏性集合格式不支持")
            if seconds:
                slots.append([str(address), now + seconds])
        return slots

    def restore_ip_slots(self, node, slots):
        if not slots:
            return
        require(node.iplimit is not None, f"端口 {node.port} 恢复材料缺少 IP 限制")
        now = int(time.time())
        commands = []
        for value, until in slots:
            address = ipaddress.ip_address(value)
            require(address.version == int(node.family) and type(until) is int, "恢复 IP 黏性集合格式无效")
            remaining = min(until - now, int(node.iplimit["IP_STICKY_SECONDS"]))
            if remaining > 0:
                commands.append(f"add element inet vr_iplimit vr_il{node.family}_{node.port} "
                                f"{{ {address} timeout {remaining}s }}")
        if commands:
            self.nft("\n".join(commands))

    def tables(self):
        data = decode_json(self.run("nft", "-j", "list", "tables").stdout)
        return {item["table"]["name"] for item in data["nftables"]
                if "table" in item and item["table"].get("family") == "inet"}

    def check_optional_policies(self, ports):
        tables = self.tables()
        paused = {port for port in ports if f"pause_vless_{port}" in tables}
        bandwidth = {port for port in ports if exists(f"/var/lib/portbw/ports/{port}.json")}
        if "pbw_policy" in tables:
            raw = self.run("nft", "-n", "list", "table", "inet", "pbw_policy").stdout
            bandwidth |= ports & {int(port) for port in re.findall(r'comment "pbw-(\d+)-', raw)}
        blocked = set()
        for table, file, pattern in (
            ("jsh_cidrban", "/etc/jsh-cidrban.nft", r'comment "jshcidr:(\d+):'),
            ("jsh_ipban", "/etc/jsh-ipban.nft", r"\.\s+(\d+)\b"),
        ):
            text = self.run("nft", "-n", "list", "table", "inet", table).stdout if table in tables else ""
            if exists(file):
                text += "\n" + secure_read(file).decode()
            blocked |= ports & {int(port) for port in re.findall(pattern, text)}
        require(not (paused or bandwidth or blocked),
                f"待迁端口有独立策略，须先单独处理。暂停 {sorted(paused)}，portbw {sorted(bandwidth)}，黑名单 {sorted(blocked)}")

    def adapt_nat(self, node):
        if not node.nat:
            return
        iface = node.meta["WG_IF"]
        settings = env_decode(secure_read(f"/etc/wireguard/{iface}.env"))
        mark = mark_value(settings.get("MARK"))
        table = number(settings.get("TABLE_ID"), "TABLE_ID", 1, 2**31 - 1)
        priority = number(settings.get("RULE_PRIORITY"), "RULE_PRIORITY", 1, 32765)
        require(mark > 0 and table not in (253, 254, 255) and self.active(f"wg-quick@{iface}.service"),
                f"端口 {node.port} 需要目标机已运行的 WireGuard {iface}")
        route = decode_json(self.run("ip", "-j", "route", "get", "1.1.1.1", "mark", str(mark)).stdout)
        require(route and route[0].get("dev") == iface, f"端口 {node.port} 的 WireGuard 标记路由未就绪")
        rows = self.run("wg", "show", iface, "latest-handshakes").stdout.splitlines()
        recent = max((int(row.split()[1]) for row in rows if len(row.split()) == 2), default=0)
        max_age = number(node.meta.get("HANDSHAKE_MAX", "180"), "HANDSHAKE_MAX", 1, 86400)
        require(recent > 0 and -5 <= int(time.time()) - recent <= max_age,
                f"端口 {node.port} 的 WireGuard 握手超时")
        node.meta.update(MARK=str(mark), TABLE_ID=str(table), RULE_PRIORITY=str(priority))
        for outbound in node.config["outbounds"]:
            if outbound.get("tag") == "nat":
                outbound["streamSettings"]["sockopt"]["mark"] = mark

    def test_config(self, node):
        path = self.work / "check.json"
        try:
            write_file(path, encode_json(node.config))
            result = self.run(XRAY, "run", "-test", "-config", path, check=False)
            require(result.returncode == 0, f"端口 {node.port} 的 Xray 配置校验失败")
        finally:
            path.unlink(missing_ok=True)

    def nft(self, commands):
        self.run("nft", "-f", "-", input_data=commands + "\n")

    def fence(self, table, ports):
        numbers = ", ".join(map(str, sorted(ports)))
        self.nft(f"""create table inet {table}
add chain inet {table} inbound {{ type filter hook input priority -120; policy accept; }}
add chain inet {table} outbound {{ type filter hook output priority -120; policy accept; }}
add rule inet {table} inbound tcp dport {{ {numbers} }} drop
add rule inet {table} outbound tcp sport {{ {numbers} }} drop""")

    def unfence(self, table):
        if table in self.tables():
            self.nft(f"delete table inet {table}")
        require(table not in self.tables(), f"临时防护表仍存在 {table}")

    def guard_units(self, table, units):
        for unit in sorted(units):
            path = guard_file(unit)
            require(path.parent.resolve() == path.parent, f"服务保护目录为符号链接 {unit}")
            if not path.parent.exists():
                path.parent.mkdir(mode=0o755)
                fsync_directory(path.parent.parent)
            if exists(path):
                require(secure_read(path) == guard_data(table), f"服务已有未知保护 {unit}")
            else:
                write_file(path, guard_data(table), 0o644)
        self.sys("daemon-reload")

    def permit_units(self, table):
        path = permit_file(table)
        if exists(path):
            require(secure_read(path) == b"qianyi\n", "启动许可文件归属异常")
        else:
            write_file(path, b"qianyi\n")

    def clear_guards(self, table, units):
        for unit in sorted(units):
            path = guard_file(unit)
            if exists(path):
                require(secure_read(path) == guard_data(table), f"服务保护文件归属异常 {unit}")
                remove_file(path)
            if path.parent.is_dir():
                path.parent.rmdir()
                fsync_directory(path.parent.parent)
        self.sys("daemon-reload")
        remove_file(permit_file(table))

    def clear_policies(self, ports):
        self.native('for port; do vr_pq_delete_managed_port "$port"; vr_il_delete_managed_port "$port"; done',
                    *sorted(ports))

    def install(self, nodes):
        for node in nodes:
            paths = node.paths()
            write_file(paths["config"], encode_json(node.config))
            write_file(paths["meta"], env_encode(node.meta))
            write_file(paths["url"], (node.url + "\n").encode())
            if node.main:
                write_file(MAIN_SUB, base64.b64encode(node.url.encode()))
            else:
                write_file(paths["unit"], unit_text(node).encode(), 0o644)
            for name, path in policy_paths(node.port).items():
                value = getattr(node, name)
                if value is not None:
                    write_file(path, env_encode(value))
            self.native("""port="$1"
if [[ -f "$VR_QUOTA_STATE_DIR/$port.env" ]]; then
    vr_pq_restore_one "$VR_QUOTA_STATE_DIR/$port.env"
    vr_pq_reset_due_one "$VR_QUOTA_STATE_DIR/$port.env"
fi
if [[ "$2" == temp ]]; then vr_il_apply_family_guard "$port" "$3"; fi
if [[ -f "$VR_IPLIMIT_STATE_DIR/$port.env" ]]; then
    vr_il_restore_one "$VR_IPLIMIT_STATE_DIR/$port.env"
fi""", node.port, "main" if node.main else "temp", node.family)
            self.policy_state(node)

    def remove_temp_nodes(self, nodes):
        for node in nodes:
            if not node.main:
                for path in node.paths().values():
                    remove_file(path)

    def refresh_subscription(self):
        self.run(f"{SBIN}/vless_temp_sub.sh", env={"VR_TEMP_LOCK_HELD": "1"})

    def wait_ready(self, nodes):
        by_port = {node.port: node for node in nodes}
        if not by_port:
            return
        deadline = time.monotonic() + 25
        stable = 0
        while time.monotonic() < deadline:
            listening = self.inspect_owners(set(by_port), by_port)
            if all(port in listening and self.active(node.unit) for port, node in by_port.items()):
                stable += 1
                if stable == 3:
                    return
            else:
                stable = 0
            time.sleep(1)
        raise MigrationError("等待节点稳定监听超时，请查看目标机对应的 systemd 服务")

    def legacy(self, *, remove=False):
        for path, digest in LEGACY.items():
            if exists(path):
                require(sha(secure_read(path)) == digest, f"旧迁移脚本 {path} 内容不匹配，请确认归属后处理")
                if remove:
                    remove_file(path)


def source_bundle(host):
    with host.temp_lock(), host.policy_lock():
        require(not exists(JOURNAL) and not exists(pending_file(Path(JOURNAL))),
                "本机还有未完成的接管，请先运行 recover")
        current = host.inventory()
        now = int(time.time())
        nodes = [host.read_node(entry) for entry in current.values()
                 if entry.main or entry.expiry > now]
        by_port = {node.port: node for node in nodes}
        host.check_optional_policies(set(by_port))
        listeners = host.inspect_owners(set(by_port), by_port)
        for node in nodes:
            host.check_unit(node)
            require(node.port in listeners and host.active(node.unit) and host.enabled(node.unit),
                    f"源端口 {node.port} 未处于正常运行并启用状态，请先处理")
            host.policy_state(node)
            host.capture_quota(node)
        profile = host.profile(any(node.nat for node in nodes))
        packet = encode_json({"format": FORMAT, "origin": host.identity(), "profile": profile,
                              "nodes": [asdict(node) for node in nodes]})
        require(len(packet) <= MAX_PACKET and len(nodes) <= 512, "节点数量或迁移包超过限制")
        return packet


def expired(node, now=None):
    return not node.main and node.expiry <= (int(time.time()) if now is None else now)


def journal_write(tx):
    packet = encode_json(tx)
    require(len(packet) <= MAX_PACKET * 2, "恢复文件超过大小限制")
    write_file(JOURNAL, packet)


def journal_read():
    data = decode_json(secure_read(JOURNAL, MAX_PACKET * 2))
    require(isinstance(data, dict)
            and set(data) == {"format", "fence", "phase", "new", "old", "defaults", "main_subscription"}
            and data["format"] == FORMAT and isinstance(data["fence"], str) and FENCE.fullmatch(data["fence"])
            and data["phase"] in {"prepare", "restore", "rollback_done", "publish"}
            and isinstance(data["old"], list) and isinstance(data["new"], list), "恢复文件格式不支持")
    new, old = transaction_nodes(data)
    unique_nodes(new)
    unique_nodes([node for _, node in old])
    require(any(n.main for n in new) and any(n.main for _, n in old), "恢复文件缺少 443")
    require({node.port for _, node in old} <= {node.port for node in new}, "恢复文件端口不匹配")
    for record, node in old:
        require(type(record.get("active")) is bool and type(record.get("enabled")) is bool
                and isinstance(record.get("slots"), list), f"端口 {node.port} 恢复状态无效")
    for key in ("defaults", "main_subscription"):
        require(isinstance(data[key], str) and len(data[key]) <= MAX_STATE_FILE * 2,
                "主节点恢复材料异常")
        base64.b64decode(data[key], validate=True)
    return data


def transaction_nodes(tx):
    return [parse_node(item) for item in tx["new"]], [(item, parse_node(item["node"])) for item in tx["old"]]


def transaction_files(nodes):
    paths = {Path(MAIN_SUB), Path(MAIN_DEFAULTS), Path(JOURNAL)}
    for node in nodes:
        paths.update(map(Path, node.paths().values()))
        paths.update(map(Path, policy_paths(node.port).values()))
        paths.add(guard_file(node.unit))
    return paths


def clean_pending(nodes, table):
    for path in transaction_files(nodes) | {permit_file(table)}:
        temporary = pending_file(path)
        if exists(temporary):
            secure_read(temporary, MAX_PACKET * 2)
            remove_file(temporary)


@contextlib.contextmanager
def defer_interrupts():
    signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    old = {sig: signal.signal(sig, signal.SIG_IGN) for sig in signals}
    try:
        yield
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def stop_defined(host, units):
    defined = [unit for unit in sorted(units) if host.property(unit, "LoadState") != "not-found"]
    if defined:
        for unit in defined:
            require(host.property(unit, "FragmentPath") == f"{SYSTEMD}/{unit}",
                    f"服务归属异常，未停止 {unit}")
        host.sys("stop", *defined, timeout=100)


def restore_target(host, tx, *, recovering=False):
    new, backup = transaction_nodes(tx)
    old = [node for _, node in backup]
    ports = {node.port for node in new}
    units = {node.unit for node in new + old}
    clean_pending(new + old, tx["fence"])
    if tx["phase"] == "restore":
        if tx["fence"] not in host.tables():
            host.fence(tx["fence"], ports)
        host.guard_units(tx["fence"], units)
        stop_defined(host, units)
        require(not host.listeners(ports), "恢复时端口已被外部服务占用")
        for node in new:
            if not node.main and host.property(node.unit, "LoadState") != "not-found":
                host.sys("disable", node.unit)
        with host.policy_lock():
            host.clear_policies(ports)
            host.remove_temp_nodes(new + old)
            write_file(MAIN_DEFAULTS, base64.b64decode(tx["defaults"], validate=True))
            host.install(old)
            write_file(MAIN_SUB, base64.b64decode(tx["main_subscription"], validate=True))
            for record, node in backup:
                host.restore_ip_slots(node, record["slots"])
        host.sys("daemon-reload")
        for record, node in backup:
            host.sys("enable" if record["enabled"] else "disable", node.unit)
        active = [node for record, node in backup if record["active"] and not expired(node)]
        if active:
            host.permit_units(tx["fence"])
            host.sys("start", *(node.unit for node in active), timeout=150)
        host.wait_ready(active)
        host.refresh_subscription()
        tx["phase"] = "rollback_done"
        journal_write(tx)
    elif recovering:
        active = [node for record, node in backup if record["active"] and not expired(node)]
        if active:
            host.permit_units(tx["fence"])
            host.sys("start", *(node.unit for node in active), timeout=150)
        host.wait_ready(active)
        host.refresh_subscription()
    host.clear_guards(tx["fence"], units)
    host.unfence(tx["fence"])
    remove_file(JOURNAL)


def publish_target(host, tx, *, recovering=False):
    nodes, old = transaction_nodes(tx)
    if recovering:
        clean_pending(nodes + [node for _, node in old], tx["fence"])
        live = [node for node in nodes if not expired(node)]
        host.permit_units(tx["fence"])
        host.sys("start", *(node.unit for node in live), timeout=150)
        host.wait_ready(live)
        with host.policy_lock():
            for node in live:
                host.policy_state(node)
        host.refresh_subscription()
        host.legacy(remove=True)
    host.clear_guards(tx["fence"], {node.unit for node in nodes} | {node.unit for _, node in old})
    host.unfence(tx["fence"])
    remove_file(JOURNAL)


def apply_bundle(host, packet):
    origin, profile, all_incoming = decode_bundle(packet)
    with host.temp_lock():
        require(not exists(JOURNAL) and not exists(pending_file(Path(JOURNAL))),
                "目标机还有未完成的接管，请先运行 recover")
        require(origin != host.identity(), "源机和目标机 machine-id 相同，请核对两台机器")
        require(profile == host.profile(any(node.nat for node in all_incoming)),
                "两端 jieshu 运行库版本不一致，请先对齐")
        now = int(time.time())
        incoming = [node for node in all_incoming if not expired(node, now)]
        if len(incoming) != len(all_incoming):
            print("已跳过传输期间到期的临时节点。", flush=True)
        host.legacy()
        current = host.inventory()
        nodes, conflicts = plan_nodes(incoming, current)
        ports = {node.port for node in nodes}
        for node in nodes:
            if node.main:
                version = current[443].meta.get("XRAY_VERSION")
                if version is None:
                    node.meta.pop("XRAY_VERSION", None)
                else:
                    node.meta["XRAY_VERSION"] = version
            host.adapt_nat(node)
            validate_node(node)
            host.test_config(node)

        with host.policy_lock():
            host.check_optional_policies(ports)
            old = [host.read_node(entry) for entry in conflicts.values()]
            old_by_port = {node.port: node for node in old}
            old_by_unit = {node.unit: node for node in old}
            host.inspect_owners(ports, old_by_port)
            paths = {path for node in old for path in node.paths().values()}
            for node in old:
                host.check_unit(node)
            for node in nodes:
                for path in node.paths().values():
                    require(path in paths or not exists(path), f"目标上有未归属的文件 {path}")
                if node.unit not in old_by_unit:
                    require(host.property(node.unit, "LoadState") == "not-found",
                            f"目标上有非本轮管理的服务 {node.unit}")
                if node.port not in old_by_port:
                    require(not any(exists(path) for path in policy_paths(node.port).values()),
                            f"端口 {node.port} 已有无法归属的策略文件")
            for path in transaction_files(nodes + old):
                is_guard = path.name == "80-qianyi-transaction.conf"
                require((not exists(path.parent) if is_guard else path.parent.is_dir())
                        and path.resolve() == path and not exists(pending_file(path)),
                        f"目标路径异常或有未归属的临时文件 {path}")
            old_subscription = secure_read(MAIN_SUB)
            old_defaults = secure_read(MAIN_DEFAULTS)
            new_defaults = main_defaults(old_defaults, next(node.meta for node in nodes if node.main))
            backup = [dict(node=asdict(node), active=host.active(node.unit),
                           enabled=host.enabled(node.unit), slots=[]) for node in old]

        tx = dict(format=FORMAT, fence=f"qianyi_{secrets.token_hex(8)}", phase="prepare",
                  new=[asdict(node) for node in nodes], old=backup,
                  defaults=base64.b64encode(old_defaults).decode(),
                  main_subscription=base64.b64encode(old_subscription).decode())
        journal_write(tx)
        try:
            host.fence(tx["fence"], ports)
            host.guard_units(tx["fence"], {node.unit for node in nodes + old})
            with host.policy_lock():
                # The scoped fence prevents an old target quota moving after this snapshot.
                for record, entry in zip(backup, old, strict=True):
                    node = host.read_node(entry)
                    host.capture_quota(node)
                    record["slots"] = host.capture_ip_slots(node)
                    record["node"] = asdict(node)
                tx["phase"] = "restore"
                journal_write(tx)

            require(not any(expired(node) for node in nodes), "预检期间有迁入节点到期，请重新导出")
            stop_defined(host, set(old_by_unit))
            require(not host.listeners(ports), "目标端口未停止或被其他服务抢占")
            incoming_units = {node.unit for node in nodes}
            for node in old:
                if node.unit not in incoming_units:
                    host.sys("disable", node.unit)
            with host.policy_lock():
                host.clear_policies(ports)
                host.remove_temp_nodes(old)
                write_file(MAIN_DEFAULTS, new_defaults)
                host.install(nodes)
            host.sys("daemon-reload")
            host.sys("enable", *(node.unit for node in nodes), timeout=100)
            host.permit_units(tx["fence"])
            host.sys("start", *(node.unit for node in nodes), timeout=150)
            host.wait_ready(nodes)
            host.refresh_subscription()
            with host.policy_lock():
                for node in nodes:
                    host.policy_state(node)
            host.legacy(remove=True)

            # Once publication is durable, never restore old quota after opening traffic.
            tx["phase"] = "publish"
            journal_write(tx)
            publish_target(host, tx)
        except BaseException:
            with defer_interrupts():
                try:
                    durable = journal_read() if exists(JOURNAL) else None
                    if durable is not None and durable["phase"] == "publish":
                        raise MigrationError("目标配置已提交，清理未确认，请运行 recover 完成收尾")
                    if durable is not None:
                        restore_target(host, durable)
                        print("已恢复目标机原节点状态，源机仍在运行。", file=sys.stderr, flush=True)
                except Exception as recovery:
                    raise MigrationError(f"目标未完成收尾，保留恢复文件 {JOURNAL}。{recovery}") from None
            raise
        print(f"目标已接管 443，替换 {len(old) - 1} 个临时节点，新增 {len(nodes) - len(old)} 个临时节点。", flush=True)


def recover_target(host):
    with host.temp_lock(), defer_interrupts():
        if not exists(JOURNAL):
            pending = pending_file(Path(JOURNAL))
            if exists(pending):
                secure_read(pending, MAX_PACKET * 2)
                remove_file(pending)
            host.legacy(remove=True)
            return
        tx = journal_read()
        if tx["phase"] == "publish":
            publish_target(host, tx, recovering=True)
        else:
            restore_target(host, tx, recovering=True)
            host.legacy(remove=True)


class Workspace:
    def __init__(self, path):
        self.path = path

    @classmethod
    def for_cli(cls):
        path = Path(__file__).absolute()
        directory = path.parent
        require(path.name == "qianyi.py" and directory.parent == Path("/run")
                and re.fullmatch(r"qianyi\.[A-Za-z0-9]{8}", directory.name)
                and path.resolve() == path, "请使用 README 的临时运行命令")
        info = directory.stat()
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "迁移目录权限必须为 root 0700")
        return cls(directory)

    def cleanup(self):
        if self.path.exists():
            shutil.rmtree(self.path)
        require(not exists(self.path), f"临时工作目录未清理 {self.path}")


# The helper is read completely by Python before its private directory is removed.
# The outer shell covers a failed download or interpreter startup.
BOOTSTRAP = r"""set -eu
umask 077
u="$1"; h="$2"; shift 2
d="$(mktemp -d /run/qianyi.XXXXXXXX)"
trap 'rm -rf -- "$d"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
curl --proto '=https' -fsSL --max-time 90 "$u" -o "$d/qianyi.py"
printf '%s  %s\n' "$h" "$d/qianyi.py" | sha256sum -c - >/dev/null
python3 -I -B "$d/qianyi.py" "$@"
"""


def bootstrap_command(digest, args):
    return shlex.join(["bash", "-c", BOOTSTRAP.replace("\n", "; ").strip("; "), "qianyi",
                       SOURCE_URL, digest, *args])


def ssl_server(host, work):
    key = work / "key.pem"
    cert = work / "cert.pem"
    host.run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-days", "1", "-subj", "/CN=qianyi-session", "-keyout", key, "-out", cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    digest = sha(ssl.PEM_cert_to_DER_cert(cert.read_text()))
    return context, digest


def check_request(conn, token, deadline):
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) >= 4096 or time.monotonic() >= deadline:
            return False
        conn.settimeout(max(0.001, deadline - time.monotonic()))
        part = conn.recv(4096 - len(data))
        if not part:
            return False
        data += part
    headers, body = data.split(b"\r\n\r\n", 1)
    request, *lines = headers.split(b"\r\n")
    expected = b"Bearer " + token.encode("ascii")
    auth = [line.partition(b":")[2].strip() for line in lines if line.partition(b":")[0].lower() == b"authorization"]
    return request == b"POST /bundle HTTP/1.1" and not body and len(auth) == 1 and secrets.compare_digest(auth[0], expected)


def serve_packet(bind, port, context, packet, token, ttl, ready, cleanup):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, port))
        listener.listen(8)
        deadline = time.monotonic() + ttl
        ready(listener.getsockname()[1])
        while time.monotonic() < deadline:
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                break
            with raw:
                request_deadline = min(deadline, time.monotonic() + 5)
                try:
                    raw.settimeout(max(0.001, request_deadline - time.monotonic()))
                    conn = context.wrap_socket(raw, server_side=True)
                except OSError:
                    continue
                with conn:
                    try:
                        authorized = check_request(conn, token, request_deadline)
                    except OSError:
                        continue
                    if not authorized:
                        continue
                    listener.close()
                    # A valid response attests that the sender has already removed its files.
                    # The bundle and TLS state are now in memory only.
                    cleanup()
                    conn.settimeout(45)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                 + f"Content-Length: {len(packet)}\r\n".encode()
                                 + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n")
                    conn.sendall(packet)
                    return
    raise MigrationError("传输会话已到期，请从源机重新执行")


def fetch_packet(raw, pin, token, digest):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    raw.settimeout(45)
    with context.wrap_socket(raw, server_hostname=None) as conn:
        require(secrets.compare_digest(sha(conn.getpeercert(binary_form=True)), pin),
                "源 TLS 证书指纹不符，未发送令牌")
        conn.sendall(b"POST /bundle HTTP/1.1\r\nHost: qianyi-source\r\nAuthorization: Bearer "
                     + token.encode("ascii") + b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        with http.client.HTTPResponse(conn) as response:
            response.begin()
            require(response.status == 200 and not response.chunked, "源传输响应异常")
            size = number(response.getheader("Content-Length"), "迁移包长度", 1, MAX_PACKET)
            packet = response.read(size)
        require(len(packet) == size and secrets.compare_digest(sha(packet), digest),
                "迁移包长度或 SHA-256 不符")
        return packet


def ssh_host_key(value):
    require(isinstance(value, str) and len(value) <= 256, "SSH 主机公钥格式无效")
    try:
        blob = base64.b64decode(value, validate=True)
    except ValueError:
        raise MigrationError("SSH 主机公钥格式无效") from None
    require(len(blob) == 51 and blob.startswith(b"\0\0\0\x0bssh-ed25519\0\0\0 "), "SSH 主机公钥格式无效")
    return value


@contextlib.contextmanager
def connect_source(args, work):
    if args.ssh_key is None:
        with socket.create_connection((args.host, args.port), timeout=20) as raw:
            yield raw
        return
    pin = work / "known_hosts"
    forward = work / "source.sock"
    write_file(pin, f"qianyi-source ssh-ed25519 {ssh_host_key(args.ssh_key)}\n".encode())
    ssh = subprocess.Popen([
        "ssh", "-F", "/dev/null", "-N", "-T", "-p", str(args.ssh_port),
        "-o", "HostKeyAlias=qianyi-source", "-o", f"UserKnownHostsFile={pin}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no", "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindMask=0177",
        "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
        "-L", f"{forward}:127.0.0.1:{args.port}", f"root@{args.host}",
    ])
    try:
        deadline = time.monotonic() + 90
        while not forward.exists():
            require(ssh.poll() is None and time.monotonic() < deadline,
                    "SSH 隧道未就绪，检查 root SSH、主机公钥和 AllowTcpForwarding")
            time.sleep(0.1)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
            raw.settimeout(20)
            raw.connect(str(forward))
            yield raw
    finally:
        with defer_interrupts():
            if ssh.poll() is None:
                ssh.terminate()
                try:
                    ssh.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ssh.kill()
                    ssh.wait()
            forward.unlink(missing_ok=True)
            pin.unlink(missing_ok=True)


def send(args, host, workspace):
    address, ssh_port, transfer_port = source_endpoint(args)
    host.legacy()
    packet = source_bundle(host)
    context, pin = ssl_server(host, workspace.path)
    token = secrets.token_urlsafe(32)
    fingerprint = sha(secure_read(Path(__file__).absolute()))
    ssh_options = []
    if not args.direct:
        key = secure_read("/etc/ssh/ssh_host_ed25519_key.pub").decode().split()
        require(len(key) >= 2 and key[0] == "ssh-ed25519", "未找到有效的源机 Ed25519 SSH 主机公钥")
        ssh_options = ["--ssh-key", ssh_host_key(key[1]), "--ssh-port", str(ssh_port)]

    def ready(port):
        command = bootstrap_command(fingerprint, ["receive", "--host", address, "--port", str(port),
                                                  "--pin", pin, "--sha256", sha(packet), *ssh_options])
        print("保持源端终端开启。请在目标机的 root 终端运行这一行：", flush=True)
        print(command, flush=True)
        print(f"目标机提示输入令牌时粘贴这一串：{token}", flush=True)

    def cleanup():
        host.legacy(remove=True)
        workspace.cleanup()

    serve_packet("0.0.0.0" if args.direct else "127.0.0.1", transfer_port,
                 context, packet, token, args.ttl, ready, cleanup)
    print("源机已发送快照并清理本轮迁移工具与临时文件。", flush=True)


def receive(args, host):
    require(HEX.fullmatch(args.pin) and HEX.fullmatch(args.sha256), "证书或迁移包 SHA-256 格式无效")
    require(sys.stdin.isatty(), "请从目标机交互式 root 终端运行")
    token = getpass.getpass("一次性迁移令牌（输入不回显）：")
    require(re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "一次性迁移令牌格式无效")
    with connect_source(args, host.work) as raw:
        packet = fetch_packet(raw, args.pin, token, args.sha256)
    apply_bundle(host, packet)


def port_arg(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1 到 65535 之间")
    return port


def ipv4(value):
    return str(ipaddress.IPv4Address(value))


def ssh_endpoint(connection):
    fields = connection.split()
    if len(fields) != 4:
        return None, None
    try:
        address = ipaddress.ip_address(fields[2])
    except ValueError:
        address = None
    if isinstance(address, ipaddress.IPv6Address):
        address = address.ipv4_mapped
    if address and (not address.is_global or address.is_multicast):
        address = None
    try:
        port = port_arg(fields[3])
    except (ValueError, argparse.ArgumentTypeError):
        port = None
    return str(address) if address else None, port


def prompt_setting(label, default, parse):
    suffix = f"（回车使用 {default}）" if default is not None else ""
    while True:
        try:
            value = input(f"{label}{suffix} > ").strip()
        except EOFError:
            raise MigrationError(f"没有收到{label}，请在源机终端重新运行") from None
        if not value and default is not None:
            return default
        try:
            return parse(value)
        except (ValueError, argparse.ArgumentTypeError):
            print(f"{label}格式不正确，请重新输入。", file=sys.stderr)


def source_endpoint(args):
    detected_host, detected_port = ssh_endpoint(os.environ.get("SSH_CONNECTION", ""))
    address = args.host or detected_host
    ssh_port = args.ssh_port or detected_port or 22
    if args.host is None and sys.stdin.isatty():
        address = prompt_setting("目标机能连接的源机管理 IPv4", address, ipv4)
        if not args.direct and args.ssh_port is None:
            ssh_port = prompt_setting("源机对外的 SSH 端口", ssh_port, port_arg)
    require(address, "未识别到源机管理 IPv4，请在源机终端运行并按提示填写")
    # A loopback listener can use port zero. Direct mode needs a known
    # externally reachable port, so keep its existing default.
    transfer_port = args.port if args.port is not None else (48999 if args.direct else 0)
    return address, ssh_port, transfer_port


def parse_args(argv):
    parser = argparse.ArgumentParser(description="jieshu 双 VPS 一次性轮换")
    sub = parser.add_subparsers(dest="action", required=True)
    source = sub.add_parser("send", help="从当前生产机导出，等待目标机接收")
    source.add_argument("--host", type=ipv4, help="源机管理 IPv4（默认从 SSH 会话读取或交互填写）")
    source.add_argument("--ssh-port", type=port_arg, help="源机 SSH 端口（默认读取当前登录端口）")
    source.add_argument("--port", type=port_arg, help="传输端口（默认由系统分配，直连模式默认 48999）")
    source.add_argument("--ttl", type=int, choices=range(60, 3601), metavar="60–3600", default=1200)
    source.add_argument("--direct", action="store_true", help="使用已有可达的 HTTPS 端口，跳过 SSH 隧道")
    target = sub.add_parser("receive", help="接收并按端口接管 443 和临时节点")
    target.add_argument("--host", required=True, type=ipv4)
    target.add_argument("--port", required=True, type=port_arg)
    target.add_argument("--pin", required=True)
    target.add_argument("--sha256", required=True)
    target.add_argument("--ssh-key")
    target.add_argument("--ssh-port", type=port_arg, default=22)
    sub.add_parser("recover", help="恢复或完成上次被中断的目标机事务")
    return parser.parse_args(argv)


def on_interrupt(signum, _frame):
    raise MigrationError(f"迁移收到中断信号 {signum}")


def main(argv=None):
    args = parse_args(argv)
    workspace = None
    try:
        require(os.geteuid() == 0, "请以 root 运行")
        require(sys.version_info >= (3, 10), "需要 Python 3.10 或更新版本")
        workspace = Workspace.for_cli()
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, on_interrupt)
        host = Host(workspace.path)
        if args.action == "send":
            send(args, host, workspace)
        elif args.action == "receive":
            receive(args, host)
        else:
            recover_target(host)
        workspace.cleanup()
    except (MigrationError, OSError, ValueError, KeyError, TypeError) as exc:
        if workspace is not None:
            try:
                with defer_interrupts():
                    workspace.cleanup()
            except (MigrationError, OSError):
                print(f"清理失败，检查迁移工作目录 {workspace.path}", file=sys.stderr)
        if isinstance(exc, MigrationError):
            message = str(exc)
        elif isinstance(exc, OSError):
            message = exc.strerror or type(exc).__name__
        else:
            message = f"配置、迁移包或系统命令输出格式异常（{type(exc).__name__}）"
        print(f"迁移未完成。{message}", file=sys.stderr)
        return 1
    if args.action == "receive":
        print("迁移完成。两端的本轮临时文件和工具已清理，请验证原链接、切 DNS，再自行重装旧机。", flush=True)
    elif args.action == "recover":
        print("恢复与清理完成，请检查目标节点状态。", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
