import base64
import contextlib
import copy
from dataclasses import asdict
import datetime as dt
from io import BytesIO
import os
from pathlib import Path
import queue
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
from uuid import uuid5, NAMESPACE_DNS

import qianyi as q


def node(tag, port, *, quota=False, iplimit=False, nat=False, label="source"):
    main = tag == "main"
    identity = str(uuid5(NAMESPACE_DNS, f"{label}-{port}"))
    family = "4"
    sni = "www.example.com"
    published = f"{label}.example.org"
    url_host = f"nat-{label}.example.org" if nat else published
    short = "0123456789abcdef"
    key = "A" * 43
    public = "B" * 43
    dest = f"{sni}:443"
    meta = dict(PORT=str(port), PUBLIC_DOMAIN=published, REALITY_DEST=dest, REALITY_SNI=sni,
                UUID=identity, SHORT_ID=short, PBK=public)
    if main:
        meta["PRIVATE_KEY"] = key
    else:
        meta.update(TAG=tag, EXPIRE_EPOCH=str(int(time.time()) + 3600), IP_VERSION=family,
                    PQ_LIMIT_BYTES="100" if quota else "", IP_LIMIT="2" if iplimit else "0",
                    IP_STICKY_SECONDS="120")
    reality = dict(serverNames=[sni], privateKey=key, shortIds=[short], dest=dest)
    stream = dict(realitySettings=reality, security="reality", network="tcp")
    settings = dict(clients=[dict(id=identity, flow="xtls-rprx-vision")])
    inbound = dict(listen="0.0.0.0", port=port, protocol="vless", streamSettings=stream, settings=settings)
    config = dict(inbounds=[inbound], outbounds=[dict(tag="direct"), dict(tag="block")])
    if nat:
        meta.update(LANDING="nat", WG_IF="wg-nat", MARK="2333", TABLE_ID="100", RULE_PRIORITY="31000",
                    SERVER_ADDR=url_host)
        inbound["tag"] = tag
        config["outbounds"][0] = dict(tag="nat", protocol="freedom", streamSettings=dict(sockopt=dict(mark=2333)))
        config["routing"] = dict(rules=[dict(type="field", inboundTag=[tag], outboundTag="nat")])
    query = urlencode(dict(sid=short, pbk=public, sni=sni, security="reality", flow="xtls-rprx-vision"))
    url = f"vless://{identity}@{url_host}:{port}?{query}#{tag}"
    owner = dict(PORT=str(port), OWNER_KIND="manual" if main else "temp", OWNER_TAG="" if main else tag)
    limits = dict(owner, ORIGINAL_LIMIT_BYTES="100", SAVED_USED_BYTES="60", LIMIT_BYTES="40",
                  REBUILD_PENDING="0", RESET_INTERVAL_SECONDS="2592000", NEXT_RESET_EPOCH="9999999999") if quota else None
    slots = dict(owner, IP_VERSION="4", IP_LIMIT="2", IP_STICKY_SECONDS="120") if iplimit else None
    return q.Node(tag, port, meta, config, url, limits, slots)


def packet(nodes, origin="a" * 64, blacklist=(), daily=None):
    return q.encode_json(dict(format=q.FORMAT, origin=origin, profile={"test": "profile"},
                              nodes=[asdict(n) for n in nodes], blacklist=list(blacklist), daily=daily))


DAILY_PROGRAM = (Path(__file__).parent / "fixtures/jieshu_traffic.py").read_bytes()


class DailyKernel:
    def __init__(self):
        self.exists = False
        self.counters = {}
        self.rules = []

    def snapshot(self):
        if not self.exists:
            return []
        rows = [{"table": {"family": "inet", "name": q.TRAFFIC_TABLE}}]
        rows += [{"chain": {"name": name, "type": "filter", "hook": name, "prio": 10, "policy": "accept"}}
                 for name in ("input", "output")]
        rows += [{"counter": {"name": name, "bytes": value}} for name, value in self.counters.items()]
        return rows + [{"rule": rule} for rule in self.rules]

    def apply(self, commands):
        for command in commands:
            parts = command.split()
            if command.startswith("add table "):
                self.exists = True
            elif command.startswith("add chain "):
                continue
            elif command.startswith("add counter "):
                self.counters[parts[-1]] = 0
            elif command.startswith("delete counter "):
                del self.counters[parts[-1]]
            elif command.startswith("flush chain "):
                self.rules = [rule for rule in self.rules if rule["chain"] != parts[-1]]
            elif command.startswith("add rule "):
                chain, field, port, name = parts[4], parts[6], int(parts[7]), parts[10]
                self.rules.append({"chain": chain, "comment": name, "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": field}}, "right": port}},
                    {"counter": name},
                ]})
            else:
                raise AssertionError(command)

    def add(self, key, upload=0, download=0):
        for direction, amount in (("u", upload), ("d", download)):
            name, = [name for name in self.counters if name.startswith(f"t_{key}_") and name.endswith(f"_{direction}")]
            self.counters[name] += amount


def daily_payload(nodes, upload=1000, download=2000):
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).date().isoformat()
    sampled = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec="seconds")
    return {"program_sha256": q.TRAFFIC_SHA256, "users": {
        node.tag: {"tag": node.tag, "port": node.port, "key": q.daily_key(node),
                   "days": {today: {"upload": upload, "download": download}}, "sampled_at": sampled}
        for node in nodes}}


class FakeHost(q.Host):
    def __init__(self, work):
        super().__init__(work)
        self.active_units = set()
        self.enabled_units = set()
        self.fences = set()
        self.actions = []
        self.fail_start = None
        self.fail_publish = False
        self.foreign = {}
        self.restored_slots = []
        self.cidr_rules = None
        self.legacy_rules = set()
        self.daily_kernel = DailyKernel()

    def daily_module(self, program):
        module = super().daily_module(program)
        module.Nft = lambda: self.daily_kernel
        return module

    @contextlib.contextmanager
    def lock(self, *_names):
        yield

    def identity(self):
        return "b" * 64

    def profile(self, _nat):
        return {"test": "profile"}

    def run(self, *args, **_kwargs):
        if args[0] == "ip":
            return SimpleNamespace(returncode=0, stdout='[{"dev":"wg-nat"}]', stderr="")
        if args[0] == "wg":
            return SimpleNamespace(stdout=f"peer\t{int(time.time())}\n")
        if args == ("ss", "-H", "-aun"):
            return SimpleNamespace(stdout="")
        if args == ("nft", "-n", "list", "table", "inet", q.CIDR_TABLE):
            return SimpleNamespace(stdout=q.extend_cidr_state(None, self.cidr_rules).decode())
        if args == ("nft", "-n", "list", "set", "inet", "jsh_ipban", "banned"):
            entries = ", ".join(f"{address.removesuffix('/32')} . {port}" for port, address in self.legacy_rules)
            return SimpleNamespace(stdout=f"set banned {{ type ipv4_addr . inet_service; elements = {{ {entries} }} }}")
        if args == ("nft", "-j", "-a", "list", "chain", "inet", q.CIDR_TABLE, "pre"):
            values = [{"rule": {"handle": handle, "comment": f"jshcidr:{port}:{address}"}}
                      for handle, (port, address) in enumerate(sorted(self.cidr_rules), 1)]
            return SimpleNamespace(stdout=q.encode_json({"nftables": values}).decode())
        raise AssertionError(args)

    def test_config(self, value):
        q.validate_node(value)

    def property(self, unit, name):
        path = Path(q.SYSTEMD) / unit
        if name == "LoadState":
            return "loaded" if path.is_file() else "not-found"
        if name == "FragmentPath":
            return str(path) if path.is_file() else ""
        return {"DropInPaths": "", "User": "root",
                "ExecStart": f"{{ argv[]={q.XRAY} run -config {q.MAIN_FILES['config']} ; }}"}.get(name, "")

    def active(self, unit):
        return unit in self.active_units or unit == "wg-quick@wg-nat.service"

    def enabled(self, unit):
        return unit in self.enabled_units

    def sys(self, action, *units, **_kwargs):
        self.actions.append((action, *units))
        if action == "start":
            for unit in units:
                if unit == self.fail_start:
                    self.fail_start = None
                    raise q.MigrationError("simulated start failure")
                self.active_units.add(unit)
        if action == "stop":
            self.active_units.difference_update(units)
        if action == "enable":
            self.enabled_units.update(units)
        if action == "disable":
            self.enabled_units.difference_update(units)

    def listeners(self, ports):
        listeners = dict(self.foreign)
        for unit in self.active_units:
            config = q.MAIN_FILES["config"] if unit == "xray.service" else f"{q.XRAY_DIR}/{unit.removesuffix('.service')}.json"
            if Path(config).exists():
                port = q.decode_json(Path(config).read_bytes())["inbounds"][0]["port"]
                listeners[port] = {unit}
        return {port: listeners[port] for port in ports if port in listeners}

    def owns(self, unit, pids):
        return pids == {unit}

    def wait_ready(self, nodes):
        by_port = {value.port: value for value in nodes}
        if set(self.inspect_owners(set(by_port), by_port)) != set(by_port):
            raise q.MigrationError("simulated listener check")

    def check_optional_policies(self, _ports):
        pass

    def capture_ip_slots(self, value):
        return [["192.0.2.5", int(time.time()) + 60]] if value.iplimit else []

    def restore_ip_slots(self, value, slots):
        if slots:
            self.restored_slots.append((value.port, slots))

    def native(self, script, *args):
        if script.startswith("for port;"):
            for port in args:
                for path in q.policy_paths(port).values():
                    q.remove_file(path)
        if script.startswith("vr_pq_snapshot_unlocked"):
            limit = q.env_decode(Path(q.policy_paths(args[0])["quota"]).read_bytes())
            return f"active|{limit['ORIGINAL_LIMIT_BYTES']}|{limit['SAVED_USED_BYTES']}|{limit['LIMIT_BYTES']}"
        if script.startswith("vr_il"):
            return "active"
        return ""

    def tables(self):
        tables = set(self.fences)
        if self.cidr_rules is not None:
            tables.add(q.CIDR_TABLE)
        if self.legacy_rules:
            tables.add("jsh_ipban")
        if self.daily_kernel.exists:
            tables.add(q.TRAFFIC_TABLE)
        return tables

    def nft(self, commands):
        if commands == f"delete table inet {q.TRAFFIC_TABLE}":
            self.daily_kernel = DailyKernel()
            return
        prefix = f"add rule inet {q.CIDR_TABLE} pre "
        handles = dict(enumerate(sorted(self.cidr_rules or set()), 1))
        for line in commands.splitlines():
            if line == f"create table inet {q.CIDR_TABLE}":
                self.assert_empty_table()
                self.cidr_rules = set()
            elif line.startswith(f"add chain inet {q.CIDR_TABLE} pre "):
                continue
            elif line.startswith(prefix):
                address, _, port, _, _ = q.CIDR_RULE.fullmatch(line.removeprefix(prefix)).groups()
                self.cidr_rules.add(q.ban_entry(int(port), address))
            elif line.startswith(f"delete rule inet {q.CIDR_TABLE} pre handle "):
                self.cidr_rules.remove(handles[int(line.split()[-1])])
            elif line == f"delete table inet {q.CIDR_TABLE}":
                self.cidr_rules = None
            elif line.startswith(f"table inet {q.CIDR_TABLE} {{"):
                self.assert_empty_table()
                self.cidr_rules = q.cidr_entries(commands)
                break
            else:
                raise AssertionError(line)

    def assert_empty_table(self):
        if self.cidr_rules is not None:
            raise AssertionError("expected no CIDR table")

    def fence(self, table, ports):
        self.actions.append(("fence", *sorted(ports)))
        self.fences.add(table)

    def unfence(self, table):
        self.actions.append(("unfence",))
        self.fences.discard(table)

    def clear_guards(self, table, units):
        if self.fail_publish:
            self.fail_publish = False
            raise q.MigrationError("simulated cleanup failure")
        super().clear_guards(table, units)

    def refresh_subscription(self):
        self.actions.append(("refresh",))


class TransactionTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        root = Path(tmp)
        state, systemd, xray, run = (root / name for name in ("state", "systemd", "xray", "run"))
        program = root / "sbin/vless_traffic"
        for path in (state / "temp", state / "main", state / "quota", state / "iplimit", systemd, xray, run, program.parent):
            path.mkdir(parents=True)
        main = {"meta": str(state / "main/main.env"), "config": str(xray / "config.json"),
                "url": str(root / "main.url")}
        self.enterContext(patch.multiple(q, STATE=str(state), LOCK_DIR=str(run), SYSTEMD=str(systemd), XRAY_DIR=str(xray),
                                         MAIN_FILES=main, MAIN_SUB=str(root / "main.sub"),
                                         MAIN_DEFAULTS=str(root / "defaults"),
                                         CIDR_STATE=str(root / "jsh-cidrban.nft"),
                                         LEGACY_BAN_STATE=str(root / "jsh-ipban.nft"),
                                         TRAFFIC_PROGRAM=str(program),
                                         JOURNAL=str(state / ".qianyi-recovery.json"), LEGACY={},
                                         permit_file=lambda table: run / f"{table}.permit"))
        def fixture_read(path, _maximum=q.MAX_STATE_FILE):
            if str(path) == "/etc/wireguard/wg-nat.env":
                return b"MARK=8080\nTABLE_ID=200\nRULE_PRIORITY=31001\n"
            return Path(path).read_bytes()

        self.enterContext(patch.object(q, "secure_read", fixture_read))
        self.host = FakeHost(run)
        self.defaults = b"PUBLIC_DOMAIN=target.example.org\nPUBLIC_IPV6_DOMAIN=target6.example.org\n"
        Path(q.MAIN_DEFAULTS).write_bytes(self.defaults)
        self.main = node("main", 443, label="target")
        self.old = node("vless-temp-old", 40000, quota=True, iplimit=True, label="target")
        self.keep = node("vless-temp-keep", 40001, label="target")
        (systemd / "xray.service").write_text("[Service]\n")
        self.host.install([self.main, self.old, self.keep])
        self.host.active_units.update(n.unit for n in (self.main, self.old, self.keep))
        self.host.enabled_units.update(self.host.active_units)

    def current(self, port):
        return self.host.read_node(self.host.inventory()[port])

    def assert_clean(self):
        self.assertFalse(Path(q.JOURNAL).exists())
        self.assertFalse(self.host.fences)
        self.assertFalse(list(Path(q.SYSTEMD).glob("*.service.d")))
        self.assertFalse(list(self.host.work.glob("*.permit")))
        self.assertFalse(list(Path(q.STATE).rglob("*.qianyi-new")))
        self.assertFalse(any(q.exists(q.pending_file(path)) for path in q.blacklist_files()))

    def setup_cidr_rules(self, entries):
        self.host.cidr_rules = set(entries)
        state, unit = q.blacklist_files()
        data = q.extend_cidr_state(None, entries)
        state.write_bytes(data)
        unit.write_text(q.CIDR_UNIT_TEXT)
        self.host.enabled_units.add(q.CIDR_UNIT)
        return data

    def setup_daily(self):
        Path(q.TRAFFIC_PROGRAM).write_bytes(DAILY_PROGRAM)
        for name, content in q.TRAFFIC_UNITS.items():
            (Path(q.SYSTEMD) / name).write_text(content)
        self.host.enabled_units.update(q.TRAFFIC_ENABLED)
        self.host.active_units.update(q.TRAFFIC_ENABLED)
        module = self.host.daily_module(DAILY_PROGRAM)
        self.host.collect_daily(module)
        for record, upload, download in ((self.main, 10, 20), (self.old, 100, 200), (self.keep, 500, 600)):
            self.host.daily_kernel.add(q.daily_key(record), upload, download)
        self.host.collect_daily(module)
        return module

    def daily_counts(self, tag):
        state = q.decode_json(q.daily_path().read_bytes())
        today = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).date().isoformat()
        return state["users"][tag]["days"][today]

    def test_replace_443_and_matching_port_keep_disjoint_and_remap_tag(self):
        incoming_main = node("main", 443, quota=True)
        replacing = node("vless-temp-keep", 40000, quota=True, iplimit=True, nat=True)
        additional = node("vless-temp-add", 40002)
        q.apply_bundle(self.host, packet([incoming_main, replacing, additional]))
        self.assertEqual(self.current(443).url, incoming_main.url)
        self.assertIn(b"PUBLIC_DOMAIN=source.example.org\n", Path(q.MAIN_DEFAULTS).read_bytes())
        self.assertIn(b"PUBLIC_IPV6_DOMAIN=target6.example.org\n", Path(q.MAIN_DEFAULTS).read_bytes())
        self.assertEqual(Path(q.MAIN_SUB).read_bytes(), base64.b64encode(incoming_main.url.encode()))
        self.assertEqual(self.current(40001).url, self.keep.url)
        self.assertEqual(self.current(40000).url, replacing.url)
        self.assertNotEqual(self.current(40000).tag, self.keep.tag)
        self.assertEqual(self.current(40000).quota["OWNER_TAG"], self.current(40000).tag)
        self.assertEqual(self.current(40000).meta["MARK"], "8080")
        self.assertEqual(self.current(40000).config["inbounds"][0]["tag"], self.current(40000).tag)
        self.assertEqual(self.current(40002).url, additional.url)
        self.assertNotIn(self.old.unit, self.host.enabled_units)
        self.assertFalse(any(self.keep.unit in action[1:] for action in self.host.actions))
        self.assert_clean()
        origin, _, next_nodes, bans, daily = q.decode_bundle(q.source_bundle(self.host))
        self.assertEqual(origin, self.host.identity())
        self.assertFalse(bans)
        self.assertIsNone(daily)
        self.assertEqual({value.port for value in next_nodes}, {443, 40000, 40001, 40002})
        self.assertEqual(next(value for value in next_nodes if value.port == 40000).quota["LIMIT_BYTES"], "40")

    def test_nat_route_failure_reports_reason_without_target_mutation(self):
        original_run = self.host.run

        def fail_route(*args, **kwargs):
            if args[0] == "ip":
                return SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: Network is unreachable\n")
            return original_run(*args, **kwargs)

        with patch.object(self.host, "run", side_effect=fail_route) as run, \
                patch.object(q.time, "sleep") as retry_sleep, \
                self.assertRaisesRegex(q.MigrationError, "mark=8080.*Network is unreachable.*尚未替换目标节点"):
            q.apply_bundle(self.host, packet([node("main", 443), node("vless-temp-new", 40000, nat=True)]))
        self.assertEqual(sum(call.args[0] == "ip" for call in run.call_args_list), 5)
        self.assertEqual(retry_sleep.call_count, 4)
        self.assertEqual(self.current(443).url, self.main.url)
        self.assertEqual(self.current(40000).url, self.old.url)
        self.assertEqual(self.host.actions, [])
        self.assert_clean()

    def test_nat_route_refresh_is_retried_without_changing_target(self):
        original_run = self.host.run
        failures = [
            SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: Network is unreachable"),
            SimpleNamespace(returncode=0, stdout='[{"dev":"eth0"}]', stderr=""),
        ]
        for initial in failures:
            with self.subTest(initial=initial):
                calls = []

                def refreshing_route(*args, **kwargs):
                    if args[0] == "ip":
                        calls.append(args)
                        if len(calls) == 1:
                            return initial
                    return original_run(*args, **kwargs)

                incoming = node("vless-temp-new", 40000, nat=True)
                with patch.object(self.host, "run", side_effect=refreshing_route), \
                        patch.object(q.time, "sleep") as retry_sleep:
                    self.host.adapt_nat(incoming)
                self.assertEqual(len(calls), 2)
                retry_sleep.assert_called_once_with(0.5)
                self.assertEqual(incoming.meta["MARK"], "8080")
                self.assertEqual(incoming.config["outbounds"][0]["streamSettings"]["sockopt"]["mark"], 8080)
        self.assertEqual(self.host.actions, [])
        self.assertEqual(self.current(40000).url, self.old.url)
        self.assert_clean()

    def test_failed_start_restores_previous_main_limits_and_ip_slots(self):
        new = node("vless-temp-new", 40000)
        self.host.fail_start = new.unit
        with self.assertRaisesRegex(q.MigrationError, "simulated start failure"):
            q.apply_bundle(self.host, packet([node("main", 443), new, node("vless-temp-add", 40002)]))
        self.assertEqual(self.current(443).url, self.main.url)
        self.assertEqual(Path(q.MAIN_DEFAULTS).read_bytes(), self.defaults)
        self.assertEqual(self.current(40000).url, self.old.url)
        self.assertEqual(self.current(40000).quota["LIMIT_BYTES"], "40")
        self.assertEqual(self.host.restored_slots[0][0], 40000)
        self.assertNotIn(40002, self.host.inventory())
        self.assertEqual(self.host.active_units, {n.unit for n in (self.main, self.old, self.keep)})
        self.assert_clean()

    def test_publish_recovery_never_reapplies_old_snapshot(self):
        new = node("vless-temp-new", 40000, quota=True)
        self.host.fail_publish = True
        with self.assertRaisesRegex(q.MigrationError, "清理"):
            q.apply_bundle(self.host, packet([node("main", 443), new]))
        self.assertEqual(q.journal_read()["phase"], "publish")
        self.assertEqual(self.current(40000).url, new.url)
        path = q.policy_paths(40000)["quota"]
        live = copy.deepcopy(new.quota)
        live.update(SAVED_USED_BYTES="70", LIMIT_BYTES="30")
        q.write_file(path, q.env_encode(live))
        q.recover_target(self.host)
        self.assertEqual(self.current(40000).quota["LIMIT_BYTES"], "30")
        self.assert_clean()

    def test_foreign_service_blocks_before_target_mutation(self):
        self.host.foreign[40002] = {"nginx"}
        with self.assertRaisesRegex(q.MigrationError, "其他服务"):
            q.apply_bundle(self.host, packet([node("main", 443), node("vless-temp-new", 40002)]))
        self.assertEqual(self.current(443).url, self.main.url)
        self.assertEqual(self.host.actions, [])
        self.assert_clean()

    def test_same_host_is_rejected(self):
        with self.assertRaisesRegex(q.MigrationError, "machine-id"):
            q.apply_bundle(self.host, packet([node("main", 443)], origin=self.host.identity()))
        self.assertEqual(self.host.actions, [])
        self.assert_clean()

    def test_expired_transfer_node_is_not_installed(self):
        old = node("vless-temp-expiring", 40000)
        old.meta["EXPIRE_EPOCH"] = "1"
        q.apply_bundle(self.host, packet([node("main", 443), old]))
        self.assertEqual(self.current(40000).url, self.old.url)
        self.assert_clean()

    def test_duplicate_ports_and_invalid_main_are_rejected(self):
        with self.assertRaises(q.MigrationError):
            q.decode_bundle(packet([node("main", 443), node("vless-temp-new", 443)]))
        with self.assertRaisesRegex(q.MigrationError, "重复"):
            q.decode_bundle(packet([node("main", 443), node("vless-temp-a", 40000), node("vless-temp-b", 40000)]))

    def test_source_exports_cidr_and_legacy_bans_for_migrated_ports(self):
        wanted = {(40000, "192.0.2.0/24"), (40001, "198.51.100.25/32")}
        self.setup_cidr_rules({(40000, "192.0.2.0/24"), (40024, "203.0.113.2/32")})
        self.host.legacy_rules = {(40001, "198.51.100.25/32")}
        _, _, _, bans, _ = q.decode_bundle(q.source_bundle(self.host))
        self.assertEqual(bans, wanted)
        self.assertEqual(self.host.actions, [])

    def test_migration_merges_bans_and_keeps_other_ports(self):
        old = {(40000, "203.0.113.5/32"), (40001, "192.0.2.0/24")}
        previous = self.setup_cidr_rules(old)
        new = {(40000, "198.51.100.2/32")}
        q.apply_bundle(self.host, packet([node("main", 443), node("vless-temp-new", 40000)],
                                         blacklist={(40000, "203.0.113.5/32")} | new))
        self.assertEqual(self.host.cidr_rules, old | new)
        saved = Path(q.CIDR_STATE).read_bytes()
        self.assertEqual(saved, q.extend_cidr_state(previous, new))
        self.assertTrue(self.host.enabled(q.CIDR_UNIT))
        self.assert_clean()

    def test_migration_adds_native_service_on_previously_empty_target(self):
        ban = (40024, "198.51.100.2/32")
        self.host.legacy_rules = {(40001, "192.0.2.3/32")}
        q.apply_bundle(self.host, packet([node("main", 443), node("vless-temp-new", 40024)], blacklist=[ban]))
        self.assertEqual(self.host.cidr_rules, {ban})
        self.assertEqual(q.cidr_entries(Path(q.CIDR_STATE).read_text()), {ban})
        self.assertEqual(self.host.legacy_rules, {(40001, "192.0.2.3/32")})
        self.assertTrue(self.host.enabled(q.CIDR_UNIT))
        self.assert_clean()

    def test_rollback_restores_previous_blacklist_and_removes_only_added_entries(self):
        old = {(40000, "203.0.113.5/32"), (40001, "192.0.2.0/24")}
        previous = self.setup_cidr_rules(old)
        new = node("vless-temp-new", 40000)
        self.host.fail_start = new.unit
        with self.assertRaisesRegex(q.MigrationError, "simulated start failure"):
            q.apply_bundle(self.host, packet([node("main", 443), new],
                                             blacklist=[(40000, "198.51.100.2/32"), (40000, "198.51.100.3/32")]))
        self.assertEqual(self.host.cidr_rules, old)
        self.assertEqual(Path(q.CIDR_STATE).read_bytes(), previous)
        self.assertTrue(self.host.enabled(q.CIDR_UNIT))
        self.assert_clean()

    def test_rollback_cleans_new_blacklist_service_and_table(self):
        new = node("vless-temp-new", 40024)
        self.host.fail_start = new.unit
        with self.assertRaisesRegex(q.MigrationError, "simulated start failure"):
            q.apply_bundle(self.host, packet([node("main", 443), new], blacklist=[(40024, "198.51.100.2/32")]))
        self.assertIsNone(self.host.cidr_rules)
        self.assertFalse(any(path.exists() for path in q.blacklist_files()))
        self.assertFalse(self.host.enabled(q.CIDR_UNIT))
        self.assert_clean()

    def test_daily_history_replaces_same_identity_and_keeps_target_baselines(self):
        module = self.setup_daily()
        nodes = [copy.deepcopy(self.main), copy.deepcopy(self.old)]
        q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 1000, "download": 2000})
        self.assertEqual(self.daily_counts(self.keep.tag), {"upload": 500, "download": 600})
        self.host.collect_daily(module)
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 1000, "download": 2000})
        self.host.daily_kernel.add(q.daily_key(self.old), 7, 9)
        self.host.collect_daily(module)
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 1007, "download": 2009})
        self.assert_clean()

    def test_daily_history_follows_a_remapped_tag_and_preserves_other_nodes(self):
        self.setup_daily()
        nodes = [node("main", 443), node(self.keep.tag, 40000)]
        q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        remapped = self.current(40000)
        self.assertNotEqual(remapped.tag, self.keep.tag)
        self.assertEqual(self.daily_counts(remapped.tag), {"upload": 1000, "download": 2000})
        self.assertEqual(self.daily_counts(self.keep.tag), {"upload": 500, "download": 600})
        saved = q.decode_json(q.daily_path().read_bytes())["users"][remapped.tag]
        self.assertEqual(saved["key"], q.daily_key(remapped))
        self.assert_clean()

    def test_failed_migration_restores_daily_history_and_recounts_no_old_bytes(self):
        module = self.setup_daily()
        nodes = [node("main", 443), node("vless-temp-new", 40000)]
        self.host.fail_start = nodes[1].unit
        with self.assertRaisesRegex(q.MigrationError, "simulated start failure"):
            q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 100, "download": 200})
        self.assertEqual(self.daily_counts(self.main.tag), {"upload": 10, "download": 20})
        self.host.daily_kernel.add(q.daily_key(self.keep), 3, 4)
        self.host.collect_daily(module)
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 100, "download": 200})
        self.assertEqual(self.daily_counts(self.keep.tag), {"upload": 503, "download": 604})
        self.assert_clean()

    def test_daily_component_is_installed_when_the_target_does_not_have_it(self):
        nodes = [node("main", 443), node("vless-temp-new", 40000)]
        with patch.object(q, "urlopen", return_value=BytesIO(DAILY_PROGRAM)):
            q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        self.assertEqual(Path(q.TRAFFIC_PROGRAM).read_bytes(), DAILY_PROGRAM)
        self.assertEqual(self.daily_counts(nodes[1].tag), {"upload": 1000, "download": 2000})
        self.assertTrue(all(self.host.active(unit) and self.host.enabled(unit) for unit in q.TRAFFIC_ENABLED))
        self.assert_clean()

    def test_failed_install_removes_new_daily_component_and_its_files(self):
        nodes = [node("main", 443), node("vless-temp-new", 40000)]
        self.host.fail_start = nodes[1].unit
        with patch.object(q, "urlopen", return_value=BytesIO(DAILY_PROGRAM)), \
                self.assertRaisesRegex(q.MigrationError, "simulated start failure"):
            q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        self.assertFalse(any(path.exists() for path in q.daily_files()))
        self.assertFalse(q.daily_path().parent.exists())
        self.assertFalse(self.host.daily_kernel.exists)
        self.assert_clean()

    def test_source_samples_unsaved_daily_bytes_and_exports_only_portable_history(self):
        module = self.setup_daily()
        self.host.daily_kernel.add(q.daily_key(self.old), 7, 9)
        state = module.load_state(q.daily_path())
        ancient = (dt.datetime.now(module.TZ).date() - dt.timedelta(days=30)).isoformat()
        state["users"][self.old.tag]["days"][ancient] = {"upload": 999, "download": 999}
        module.save_state(q.daily_path(), state)
        _, _, _, _, daily = q.decode_bundle(q.source_bundle(self.host))
        records = daily["users"]
        self.assertNotIn("last", records[self.old.tag])
        self.assertNotIn(ancient, records[self.old.tag]["days"])
        self.assertEqual(self.daily_counts(self.old.tag), {"upload": 107, "download": 209})
        today = dt.datetime.now(module.TZ).date().isoformat()
        self.assertEqual(records[self.old.tag]["days"][today], {"upload": 107, "download": 209})

    def test_publish_recovery_keeps_daily_bytes_used_after_commit(self):
        module = self.setup_daily()
        nodes = [node("main", 443), node("vless-temp-new", 40000)]
        self.host.fail_publish = True
        with self.assertRaisesRegex(q.MigrationError, "清理"):
            q.apply_bundle(self.host, packet(nodes, daily=daily_payload(nodes)))
        self.host.daily_kernel.add(q.daily_key(nodes[1]), 7, 9)
        self.host.collect_daily(module)
        q.recover_target(self.host)
        self.assertEqual(self.daily_counts(nodes[1].tag), {"upload": 1007, "download": 2009})
        self.assert_clean()


class BlacklistFormatTests(unittest.TestCase):
    def test_native_listing_supports_numeric_protocols_and_counter_values(self):
        data = q.extend_cidr_state(None, {(40024, "198.51.100.2/32")}).decode()
        data = data.replace("priority -150", "priority mangle").replace("{ tcp, udp }", "{ 6, 17 }")
        data = data.replace("ip saddr 198.51.100.2/32", "ip saddr 198.51.100.2")
        data = data.replace("counter drop", "counter packets 7 bytes 421 drop")
        self.assertEqual(q.cidr_entries(data), {(40024, "198.51.100.2/32")})
        with self.assertRaises(q.MigrationError):
            q.cidr_entries(data.replace("th dport 40024", "th dport 22"))

    def test_bundle_rejects_bans_outside_migrated_ports(self):
        with self.assertRaisesRegex(q.MigrationError, "未迁移的端口 22"):
            q.decode_bundle(packet([node("main", 443)], blacklist=[(22, "198.51.100.2/32")]))

    @unittest.skipUnless(os.environ.get("QIANyi_NFT_NETNS") == "1", "requires an isolated nftables namespace")
    def test_kernel_blacklist_listing_and_rollback_handles(self):
        old = (40024, "198.51.100.2/32")
        added = (40024, "203.0.113.0/24")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            host = q.Host(work)
            with patch.multiple(q, BAN_LOCKS=(), CIDR_STATE=str(work / "cidr"),
                                LEGACY_BAN_STATE=str(work / "legacy")):
                self.assertFalse(host.tables(), "the test must run in a fresh network namespace")
                host.nft(q.extend_cidr_state(None, {old, added}).decode())
                self.assertEqual(host.active_cidrs(), {old, added})
                host.remove_blacklist_rules({added})
                self.assertEqual(host.active_cidrs(), {old})
                host.nft("""create table inet jsh_ipban
add set inet jsh_ipban banned { type ipv4_addr . inet_service; }
add element inet jsh_ipban banned { 192.0.2.7 . 40024, 192.0.2.8 . 40025 }""")
                self.assertEqual(host.source_blacklist({40024}), {old, (40024, "192.0.2.7/32")})

    @unittest.skipUnless(os.environ.get("QIANyi_NFT_NETNS") == "1", "requires an isolated nftables namespace")
    def test_kernel_daily_history_uses_local_baselines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "temp").mkdir()
            (root / "main").mkdir()
            item = node("main", 443)
            (root / "main/main.env").write_bytes(q.env_encode(item.meta))
            program = root / "vless_traffic"
            program.write_bytes(DAILY_PROGRAM)
            with patch.multiple(q, STATE=str(root), TRAFFIC_PROGRAM=str(program)):
                host = q.Host(root)
                host.run("ip", "link", "set", "lo", "up")
                module = host.daily_module(DAILY_PROGRAM)
                host.collect_daily(module)

                def transfer():
                    with socket.socket() as server:
                        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        server.bind(("127.0.0.1", 443))
                        server.listen(1)
                        def receive():
                            conn, _ = server.accept()
                            with conn:
                                conn.recv(100)
                        thread = threading.Thread(target=receive)
                        thread.start()
                        with socket.create_connection(("127.0.0.1", 443)) as client:
                            client.sendall(b"x" * 100)
                        thread.join(timeout=3)
                        self.assertFalse(thread.is_alive())

                transfer()
                old = host.collect_daily(module)
                today = dt.datetime.now(module.TZ).date().isoformat()
                self.assertGreater(old["users"]["main"]["days"][today]["upload"], 0)
                records = daily_payload([item], upload=10000, download=20000)["users"]
                plan = {"program": base64.b64encode(DAILY_PROGRAM).decode()}
                host.merge_daily(plan, records)
                sampled = host.collect_daily(module)
                self.assertEqual(sampled["users"]["main"]["days"][today], {"upload": 10000, "download": 20000})
                transfer()
                sampled = host.collect_daily(module)
                self.assertGreater(sampled["users"]["main"]["days"][today]["upload"], 10000)


class SourceEndpointTests(unittest.TestCase):
    def settings(self, connection, argv=(), replies=None):
        with patch.dict(os.environ, {"SSH_CONNECTION": connection}), \
                patch.object(q.sys.stdin, "isatty", return_value=replies is not None), \
                patch("builtins.input", side_effect=replies) as prompt:
            value = q.source_endpoint(q.parse_args(["send", *argv]))
            return value, prompt.call_args_list

    def test_detected_custom_ssh_port_is_default_and_transport_is_ephemeral(self):
        result, prompts = self.settings("192.0.2.1 50000 8.8.8.8 22022", replies=["", ""])
        self.assertEqual(result, ("8.8.8.8", 22022, 0))
        self.assertIn("22022", prompts[1].args[0])

    def test_private_server_address_and_external_mapping_can_be_entered(self):
        result, prompts = self.settings("192.0.2.1 50000 10.0.0.5 22", replies=["203.0.113.10", "2222"])
        self.assertEqual(result, ("203.0.113.10", 2222, 0))
        self.assertNotIn("10.0.0.5", prompts[0].args[0])

    def test_console_uses_22_when_no_ssh_session(self):
        result, prompts = self.settings("", replies=["203.0.113.10", ""])
        self.assertEqual(result, ("203.0.113.10", 22, 0))
        self.assertIn("22", prompts[1].args[0])

    def test_mapped_ipv4_and_noninteractive_cli(self):
        result, prompts = self.settings("192.0.2.1 50000 ::ffff:8.8.8.8 22022")
        self.assertEqual(result, ("8.8.8.8", 22022, 0))
        self.assertEqual(prompts, [])

    def test_explicit_overrides_and_direct_mode_remain_supported(self):
        login = "192.0.2.1 50000 8.8.8.8 22022"
        explicit, prompts = self.settings(login, ["--host", "203.0.113.10", "--ssh-port", "22",
                                                 "--port", "49000"], replies=[])
        self.assertEqual(explicit, ("203.0.113.10", 22, 49000))
        self.assertEqual(prompts, [])
        direct, prompts = self.settings(login, ["--direct"], replies=[""])
        self.assertEqual(direct, ("8.8.8.8", 22022, 48999))
        self.assertEqual(len(prompts), 1)


class SshFrameTests(unittest.TestCase):
    def test_binary_snapshot_round_trips_after_a_bounded_banner(self):
        snapshot = bytes(range(256)) * 1024
        output = BytesIO(b"ssh banner\n")
        output.seek(0, os.SEEK_END)
        q.write_ssh_frame(output, snapshot)
        self.assertEqual(q.read_ssh_frame(BytesIO(output.getvalue())), snapshot)

    def test_truncated_modified_or_extended_frames_are_rejected(self):
        output = BytesIO()
        q.write_ssh_frame(output, b"secret snapshot")
        frame = output.getvalue()
        for invalid in (frame[:-1], frame[:-1] + b"z", frame + b"unexpected",
                        b"x" * q.MAX_SSH_PREAMBLE + b"\n" + frame):
            with self.subTest(frame=invalid[:12]), self.assertRaises(q.MigrationError):
                q.read_ssh_frame(BytesIO(invalid))

    def test_source_workspace_is_cleaned_before_emitting_a_frame(self):
        events = []
        class Output(BytesIO):
            def write(self, data):
                self_test.assertEqual(events, ["legacy checked", "legacy cleaned", "workspace removed"])
                return super().write(data)

        self_test = self
        stream = Output()
        output = SimpleNamespace(isatty=lambda: False, buffer=stream)
        host = SimpleNamespace(legacy=lambda remove=False: events.append("legacy cleaned" if remove else "legacy checked"))
        workspace = SimpleNamespace(cleanup=lambda: events.append("workspace removed"))
        with patch.object(q.sys, "stdout", output), patch.object(q, "source_bundle", return_value=b"snapshot"):
            q.export_ssh(host, workspace)
        self.assertEqual(q.read_ssh_frame(BytesIO(stream.getvalue())), b"snapshot")

    def test_interactive_export_does_not_print_a_snapshot(self):
        with patch.object(q.sys.stdout, "isatty", return_value=True), self.assertRaises(q.MigrationError):
            q.export_ssh(None, None)


class TransportTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_pinned_transfer_proves_source_workspace_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "source"
            work.mkdir()
            workspace = q.Workspace(work)
            context, pin = q.ssl_server(q.Host(work), work)
            body = b"test snapshot"
            token = "a" * 43
            ready, done = queue.Queue(), queue.Queue()
            def serve():
                try:
                    q.serve_packet("127.0.0.1", 0, context, body, token, 10, ready.put, workspace.cleanup)
                    done.put(None)
                except Exception as error:
                    done.put(error)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            port = ready.get(timeout=5)
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with self.assertRaisesRegex(q.MigrationError, "证书指纹不符"):
                    q.fetch_packet(raw, "0" * 64, token, q.sha(body))
            self.assertTrue(work.exists())
            with socket.create_connection(("127.0.0.1", port)) as raw:
                with self.assertRaises(OSError):
                    q.fetch_packet(raw, pin, "b" * 43, q.sha(body))
            self.assertTrue(work.exists())
            with socket.create_connection(("127.0.0.1", port)) as raw:
                self.assertEqual(q.fetch_packet(raw, pin, token, q.sha(body)), body)
                self.assertFalse(work.exists())
            thread.join(timeout=5)
            self.assertIsNone(done.get(timeout=1))
            with self.assertRaises(ConnectionRefusedError):
                socket.create_connection(("127.0.0.1", port), timeout=1)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
    def test_tls_over_unix_socket_like_ssh_forwarding(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            context, pin = q.ssl_server(q.Host(work), work)
            token = "a" * 43
            source, target = socket.socketpair()
            failures = queue.Queue()
            def serve():
                try:
                    with context.wrap_socket(source, server_side=True) as conn:
                        if not q.check_request(conn, token, time.monotonic() + 3):
                            raise AssertionError("unexpected authorization")
                        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx")
                except Exception as error:
                    failures.put(error)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            with target:
                self.assertEqual(q.fetch_packet(target, pin, token, q.sha(b"x")), b"x")
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertTrue(failures.empty())

    def test_bootstrap_checks_hash_and_cleans_on_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = b"import pathlib,sys\npathlib.Path(sys.argv[1]).write_text('ran')\n"
            (root / "sample").write_bytes(sample)
            (root / "curl").write_text(f"#!/bin/sh\nfor out; do :; done\ncp {shlex.quote(str(root / 'sample'))} \"$out\"\n")
            (root / "curl").chmod(0o755)
            environment = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}")
            script = q.BOOTSTRAP.replace("/run/qianyi.XXXXXXXX", str(root / "qianyi.XXXXXXXX"))
            for digest, expected in (("0" * 64, False), (q.sha(sample), True)):
                result = subprocess.run(["bash", "-c", script, "qianyi", q.SOURCE_URL, digest, str(root / "flag")],
                                        capture_output=True, env=environment)
                self.assertEqual(result.returncode == 0, expected, result.stderr)
                self.assertEqual((root / "flag").exists(), expected)
                self.assertFalse(list(root.glob("qianyi.*")))


if __name__ == "__main__":
    unittest.main()
