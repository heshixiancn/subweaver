#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shadowsocks Web 配置管理器
核心能力：
  1. 多个远程订阅聚合（抓取 → 解析 → 合并）
  2. 节点分组（显式成员 + 按订阅源自动归组）
  3. 负载均衡策略：手动顺序 / 延迟优先 / 轮询 / 随机 / 故障转移
  4. 服务端健康检查（TCP 测速），标记节点可达性供策略参考
  5. 每个分组生成独立订阅链接，客户端刷新即更新
"""
import base64
import concurrent.futures
import datetime
import getpass
import hashlib
import io
import json
import os
import random
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import zipfile

import requests
from flask import (Flask, abort, jsonify, request, send_file,
                   send_from_directory, session)

import protocols
import db as store_mod
from mihomo_gateway import MihomoManager, build_config

BASE = os.path.dirname(os.path.abspath(__file__))
# 数据目录：Docker 部署时挂卷到这里（SS_DATA_DIR），本地默认项目根目录
DATA_DIR = os.environ.get("SS_DATA_DIR") or BASE
# SQLite 主存储；旧版 data.json 仅用于一次性迁移
DB_FILE = os.environ.get("SS_DB_FILE") or os.path.join(DATA_DIR, "shadowrocket.db")
LEGACY_DATA_FILE = os.environ.get("SS_DATA_FILE") or os.path.join(DATA_DIR, "data.json")
OUTPUT_DIR = os.environ.get("SS_OUTPUT_DIR") or os.path.join(DATA_DIR, "output")
_store = store_mod.Store(DB_FILE)

MIHOMO_DIR = os.path.join(OUTPUT_DIR, "mihomo")
MIHOMO_API_PORT = int(os.environ.get("SS_MIHOMO_API_PORT", "9090"))
_mihomo_binary = os.environ.get("SS_MIHOMO", "bin/mihomo")
if not os.path.isabs(_mihomo_binary):
    _mihomo_binary = os.path.join(BASE, _mihomo_binary)
_mihomo = MihomoManager(_mihomo_binary, MIHOMO_DIR)

# 分组 SOCKS5 的默认监听地址。容器里必须用 SS_SOCKS_LISTEN=0.0.0.0：
# Docker 的端口转发打到容器 IP，绑回环的话即使 -p 发布了端口，外面也连不进来。
DEFAULT_SOCKS_LISTEN = os.environ.get("SS_SOCKS_LISTEN") or "127.0.0.1"
# 容器部署时，界面/复制出来的地址不可能是容器内网 IP，用这个显式指定宿主机地址。
SOCKS_ADVERTISE = (os.environ.get("SS_SOCKS_ADVERTISE") or "").strip()

_lock = threading.RLock()
_rr_counters = {}          # 轮询策略内存计数器 {group_id: n}
app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0   # 前端迭代频繁：静态资源一律不缓存，避免改版后浏览器拿旧页面


@app.after_request
def _no_cache_html(resp):
    """HTML 主页禁止缓存（订阅链接/token 会变）；其他静态资源交给上面的 max_age=0"""
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


# Shadowrocket DNS 默认值：全局 DNS 覆写（支持 system / IP / https: DoH / tls: DoT / quic: DoQ / h3:）
DEFAULT_SR_DNS = {"servers": "system, 223.5.5.5, 119.29.29.29",
                  "direct": "", "fallback": "", "local_for_proxy": False, "hosts": []}


def norm_sr_dns(raw):
    """规范化 DNS 设置。hosts 每行：{domain, mode: dns|ip, value}
    mode=dns → [Host] 写 `domain = server:值`（该域名用指定 DNS 解析）
    mode=ip  → [Host] 写 `domain = 值`（直接固定映射，不走 DNS）"""
    raw = raw if isinstance(raw, dict) else {}

    def _txt(v):
        return " ".join(str(v or "").replace("\n", " ").split())

    hosts = []
    for h in (raw.get("hosts") or [])[:200]:
        if not isinstance(h, dict):
            continue
        dom, val = _txt(h.get("domain")), _txt(h.get("value"))
        mode = "ip" if str(h.get("mode") or "").strip() == "ip" else "dns"
        if mode == "ip" and val.lower().startswith("server:"):
            mode = "dns"
            val = val[len("server:"):].strip()   # 已带前缀则纠正模式并去掉，避免写成 server:server:
        # 域名/取值不得含配置分隔符，防止写入配置段时串行
        if not dom or not val or any(c in dom for c in " ,=\t") or any(c in val for c in ",=\t"):
            continue
        hosts.append({"domain": dom, "mode": mode, "value": val})
    return {"servers": _txt(raw.get("servers")) or DEFAULT_SR_DNS["servers"],
            "direct": _txt(raw.get("direct")),
            "fallback": _txt(raw.get("fallback")),
            "local_for_proxy": bool(raw.get("local_for_proxy")),
            "hosts": hosts}

DEFAULT_RULES = """[bypass_all]
[bypass_list]
GEOIP,CN
DOMAIN-SUFFIX,local
DOMAIN-SUFFIX,lan
DOMAIN-SUFFIX,qq.com
DOMAIN-SUFFIX,weixin.qq.com
DOMAIN-SUFFIX,tencent.com
DOMAIN-SUFFIX,taobao.com
DOMAIN-SUFFIX,tmall.com
DOMAIN-SUFFIX,jd.com
DOMAIN-SUFFIX,alicdn.com
DOMAIN-SUFFIX,aliyuncs.com
DOMAIN-SUFFIX,126.com
DOMAIN-SUFFIX,163.com
DOMAIN-KEYWORD,baidu
DOMAIN-KEYWORD,alipay
[proxy_list]
"""

STRATEGIES = [
    {"key": "manual", "name": "手动顺序", "desc": "按节点列表顺序输出，优先级完全由你决定"},
    {"key": "latency", "name": "延迟优先", "desc": "按测速延迟从低到高排序，最快的排最前"},
    {"key": "round_robin", "name": "轮询", "desc": "每次请求轮换节点顺序，把流量分散到不同节点"},
    {"key": "random", "name": "随机", "desc": "每次请求随机打乱节点顺序"},
    {"key": "failover", "name": "故障转移", "desc": "只输出健康节点并按延迟排序，宕机节点自动剔除"},
]

COMMON_METHODS = [
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "aes-256-cfb", "rc4-md5",
]

DEFAULT_SURGE_RULES = """# Shadowrocket / Surge 规则：自上而下匹配，最后一条 FINAL 为兜底出口
# 动作可写：DIRECT（直连）/ REJECT（拦截）/ PROXY（走默认出口）/ 或直接写你的分组名
# 支持类型：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6 / GEOIP / USER-AGENT / RULE-SET
DOMAIN-SUFFIX,cn,DIRECT
DOMAIN-KEYWORD,baidu,DIRECT
DOMAIN-SUFFIX,qq.com,DIRECT
DOMAIN-SUFFIX,tencent.com,DIRECT
DOMAIN-SUFFIX,taobao.com,DIRECT
DOMAIN-SUFFIX,tmall.com,DIRECT
DOMAIN-SUFFIX,alicdn.com,DIRECT
DOMAIN-SUFFIX,jd.com,DIRECT
DOMAIN-SUFFIX,bilibili.com,DIRECT
DOMAIN-SUFFIX,163.com,DIRECT
DOMAIN-SUFFIX,126.com,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,PROXY
"""

DEFAULT_DATA = {
    "password_hash": None,
    "nodes": [],
    "subscriptions": [],
    "groups": [
        {"id": "g_default", "name": "全部节点", "strategy": "latency",
         "members": [], "auto_sources": [], "is_default": True},
    ],
    "settings": {"auto_health": False, "health_interval_minutes": 30, "health_timeout": 3,
                 "sr_final_group": "", "sr_udp_relay": True,
                 "sr_test_url": "http://www.gstatic.com/generate_204",
                 "sr_interval": 300, "sr_tolerance": 50,
                 "sr_dns": {"servers": DEFAULT_SR_DNS["servers"], "direct": "",
                            "fallback": "", "local_for_proxy": False, "hosts": []},
                 # 静态托管发布地址前缀（仅用于界面预览完整链接，可留空）
                 "publish_base": "",
                 # require_login 为 False 时关闭登录页与鉴权（本机/可信内网自用）
                 "require_login": True},
    "rules": DEFAULT_RULES,
    "surge_rules": DEFAULT_SURGE_RULES,
}


# ---------------------------------------------------------------- data layer
def load_data():
    with _lock:
        if _store.is_empty() and os.path.exists(LEGACY_DATA_FILE):
            # 一次性迁移：旧 data.json → SQLite，原文件改名保留为备份
            counts = _store.migrate_from_json(LEGACY_DATA_FILE)
            os.replace(LEGACY_DATA_FILE, LEGACY_DATA_FILE + ".migrated")
            print(f"[db] 已从 data.json 迁移：{counts[0]} 节点 / "
                  f"{counts[1]} 订阅 / {counts[2]} 分组 → {DB_FILE}", flush=True)
        data = _store.load_all()
        changed = False
        if not data.get("secret_key"):
            data["secret_key"] = secrets.token_hex(32)
            changed = True
        if not data.get("publish_token"):
            data["publish_token"] = secrets.token_urlsafe(16)
            changed = True
        if not data.get("groups"):
            data["groups"] = [dict(DEFAULT_DATA["groups"][0])]
            changed = True
        st = data.get("settings") or {}
        for k, v in DEFAULT_DATA["settings"].items():
            st.setdefault(k, v)
        data["settings"] = st
        for g in data["groups"]:
            g.setdefault("members", [])
            g.setdefault("auto_sources", [])
            g.setdefault("strategy", "manual")
            g.pop("skip_dead", None)        # 「自动剔除不可用」功能已按用户要求移除，顺带清掉历史残留
            g.setdefault("socks5_enabled", True)
            g.setdefault("socks5_listen", DEFAULT_SOCKS_LISTEN)
            g.setdefault("socks5_port", 0)
            g.setdefault("test_url", "")
            g.setdefault("interval", 0)
            g.setdefault("tolerance", 50)
            g.setdefault("active_node", "")
        for n in data["nodes"]:
            n.setdefault("alive", None)
            n.setdefault("latency_ms", None)
            n.setdefault("type", "ss")          # 老数据里都是 ss 节点
            # 迁移：早期解析器漏读 URI 里的 peer=（Shadowrocket 的 SNI 别名），
            # 导致 REALITY 类节点 SNI 为空、连不上。有 uri 的按其重新补 SNI。
            if not n.get("sni") and n.get("uri"):
                try:
                    fixed = protocols.parse_uri(n["uri"])
                except Exception:
                    fixed = None
                if fixed and fixed.get("sni"):
                    n["sni"] = fixed["sni"]
                    changed = True
        data["surge_rules"] = data.get("surge_rules") or DEFAULT_SURGE_RULES
        if not data.get("rules"):
            data["rules"] = DEFAULT_RULES
        if changed or _store.is_empty():
            save_data_obj(data)
        app.secret_key = data["secret_key"]
        return data


def save_data_obj(data):
    _store.save_all(data)


def save_data(data):
    with _lock:
        save_data_obj(data)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return salt + "$" + h.hex()


def verify_password(password, stored):
    if not stored or "$" not in stored:
        return False
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(hash_password(password, salt), stored)


# ------------------------------------------------------------ ss:// 处理
def _b64_pad(s):
    return s + "=" * (-len(s) % 4)


def make_ss_uri(node):
    """生成节点链接：优先使用原始 URI，保证全协议零信息损失"""
    return protocols.make_uri(node)


def parse_ss_uri(uri):
    """解析单条节点链接（已支持 Shadowrocket 全部协议，实现见 protocols.py）"""
    return protocols.parse_uri(uri)


SUB_UA = "Shadowrocket/2.2.35 (iPhone; iOS 17.5)"


def fetch_subscription(url):
    """抓取订阅并解析全部协议节点。
    兼容三种下发形态：明文 URI 列表 / base64 包裹 / Clash 风格 YAML。"""
    resp = requests.get(url, timeout=20, headers={"User-Agent": SUB_UA})
    resp.raise_for_status()
    text = resp.text or ""
    nodes = protocols.parse_lines(text, allow_http=False)
    if not nodes:                                   # 兜底：机场按 YAML 下发
        nodes = protocols.parse_clash_yaml(text)
    return nodes


def _node_fingerprint(node):
    """Stable identity for a proxy across subscription refreshes."""
    uri = (node.get("uri") or "").strip()
    if uri:
        # A provider may change only the display remark after a refresh.
        return urllib.parse.urldefrag(uri)[0]
    ignore = {"id", "name", "source", "source_name", "source_ids", "uri",
              "alive", "latency_ms", "probe", "last_check"}
    return json.dumps({k: v for k, v in node.items() if k not in ignore},
                      ensure_ascii=False, sort_keys=True, default=str)


def _prepare_refreshed_nodes(data, sub_id, nodes):
    old = { _node_fingerprint(n): n for n in data["nodes"]
            if n.get("source") == sub_id }
    out = []
    for node in nodes:
        previous = old.get(_node_fingerprint(node))
        node.update({"id": previous.get("id") if previous else secrets.token_hex(4),
                     "source": sub_id, "alive": None, "latency_ms": None})
        node["source_name"] = next((s.get("name") for s in data["subscriptions"]
                                     if s.get("id") == sub_id), node.get("source_name", ""))
        node["source_ids"] = list(dict.fromkeys((previous or {}).get("source_ids", []) + [sub_id]))
        out.append(node)
    return out


# ------------------------------------------------------------- health check
# hysteria / hysteria2 / tuic 都跑在 QUIC（UDP）上，拿 TCP 去连永远连不上，
# 必须单独区分，否则会被误报成「不可达」。
UDP_TYPES = {"hysteria", "hysteria2", "tuic"}

PROBE_STATES = {
    "ok":        "可用（仅端口可达，该协议的协议级验证内核不支持）",
    "refused":   "不可用（服务器在线，但该端口无服务）",
    "timeout":   "无法确认（无应答：可能被网络阻断，也可能已失效）",
    "dns":       "不可用（域名解析失败）",
    "udp":       "无法确认（QUIC/UDP 协议，TCP 探测不适用）",
    "error":     "无法确认（探测出错）",
    "deep":      "可用（内核真实协议握手 + 代理请求成功）",
    "deep_fail": "不可用（真实协议握手或代理请求失败）",
}
# 内核不支持的协议 → 只做端口层回退探测
_DEEP_LOCK = threading.Lock()


def check_node(node, timeout=3):
    """裸 TCP 连通性探测，返回 (state, latency_ms)。

    ok       TCP 握手成功 —— 端口开放（注意：仅代表端口活着，
             不代表协议与密码正确）
    refused  明确收到 RST —— 服务器在线但该端口无服务，可判定失效
    timeout  完全无应答 —— 无法区分「被网络阻断」与「节点已失效」
    dns      域名解析失败
    udp      QUIC/UDP 协议，TCP 探测无意义，不做判定
    """
    if node.get("type") in UDP_TYPES:
        return "udp", None
    t0 = time.time()
    try:
        with socket.create_connection((node["server"], int(node["port"])),
                                      timeout=timeout):
            return "ok", int((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return "refused", None
    except socket.gaierror:
        return "dns", None
    except Exception:
        # 含 timeout：无应答时不再武断判定为「已死」
        return "timeout", None


def _merge_shallow_probe(node, state, latency):
    """把浅层 TCP 探测结果与已有结论合并，返回 (alive, probe, latency_ms)。

    原则：浅层 TCP 探测**不能推翻**深度测速（真实协议握手）的结论 ——
    本机网络对境外 TCP 大面积无应答，若无脑覆盖，会把真实可用的节点
    标成「不可用/待确认」，用户看到的全是红点。
      · refused / dns  明确失效：任何时候都可信，直接采纳
      · ok             TCP 通：仅对从未深度测过的节点采纳；
                       深度测过且判失败的（协议/密钥/SNI 问题）不被推翻
      · timeout / udp / error  无法判定：保留原结论
    """
    prev_probe = node.get("probe")
    deep_tested = isinstance(prev_probe, str) and prev_probe.startswith("deep")

    if state in ("refused", "dns"):
        return False, state, None
    if state == "ok":
        if deep_tested and prev_probe != "deep":
            return node.get("alive"), prev_probe, node.get("latency_ms")
        return True, state, latency
    if deep_tested:
        return node.get("alive"), prev_probe, node.get("latency_ms")
    return None, state, None


def run_health_check(node_ids=None):
    """连通性探测，结果写回数据。

    alive 语义（三态）：
      True   探测通过
      False  明确失败（端口被拒 / 域名解析失败）
      None   无法判定（无应答 / QUIC 协议未做探测）
    深度测速结果优先，不会被浅层探测降级（见 _merge_shallow_probe）。
    """
    data = load_data()
    timeout = data.get("settings", {}).get("health_timeout", 3)
    targets = [n for n in data["nodes"] if node_ids is None or n["id"] in node_ids]
    if not targets:
        return {"total": 0, "alive": 0, "dead": 0, "unknown": 0,
                "states": {}, "results": []}
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_node, n, timeout): n for n in targets}
        for fut in concurrent.futures.as_completed(futures):
            node = futures[fut]
            try:
                state, latency = fut.result()
            except Exception:
                state, latency = "error", None
            alive, probe, lat = _merge_shallow_probe(node, state, latency)
            node["alive"], node["probe"], node["latency_ms"] = alive, probe, lat
            node["checked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            results.append({"id": node["id"], "name": node["name"],
                            "probe": state, "alive": alive,
                            "latency_ms": lat})
    save_data(data)
    regen_outputs(data)
    alive = sum(1 for r in results if r["alive"] is True)
    dead = sum(1 for r in results if r["alive"] is False)
    states = {}
    for r in results:
        states[r["probe"]] = states.get(r["probe"], 0) + 1
    return {"total": len(results), "alive": alive, "dead": dead,
            "unknown": len(results) - alive - dead,
            "states": states, "state_labels": PROBE_STATES, "results": results}


def _probe_counts(nodes):
    """节点集合的探测统计。alive 为三态，故 unknown 单列。"""
    alive = sum(1 for n in nodes if n.get("alive") is True)
    dead = sum(1 for n in nodes if n.get("alive") is False)
    probed = sum(1 for n in nodes if n.get("probe") is not None)
    port_only = sum(1 for n in nodes if n.get("probe") == "ok")   # 仅端口验证
    return {"alive_count": alive, "dead_count": dead,
            "unknown_count": len(nodes) - alive - dead,
            "port_only_count": port_only, "tested_count": probed}


_LAN_HOST_CACHE = {"host": "", "at": 0.0}


def _lan_host():
    """本机对局域网暴露的地址（走默认路由的那张网卡）。

    通配绑定 0.0.0.0 只表示「监听所有网卡」，不能当客户端地址用；
    展示和复制时要换成真实网卡 IP。UDP connect 不会真的发包，只让内核选路，
    因此在离线环境下失败也安全（返回空由调用方兜底）。
    """
    now = time.time()
    if _LAN_HOST_CACHE["host"] and now - _LAN_HOST_CACHE["at"] < 30:
        return _LAN_HOST_CACHE["host"]
    host = ""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            host = probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        host = ""
    if host.startswith("127."):
        host = ""
    _LAN_HOST_CACHE.update({"host": host, "at": now})
    return host


def _client_host(listen):
    """把绑定地址翻译成「客户端该填哪个地址」。

    通配（0.0.0.0 / :: / *）→ SS_SOCKS_ADVERTISE（容器部署时指定），
    否则本机局域网 IP；拿不到就退回 127.0.0.1。
    其余情况原样返回（显式绑定的地址本来就是可连接的）。
    """
    listen = str(listen or "").strip()
    if listen in ("0.0.0.0", "::", "*", "[::]", ""):
        if SOCKS_ADVERTISE:
            return SOCKS_ADVERTISE
        return _lan_host() or "127.0.0.1"
    return listen


# ------------------------------------------------- deep check（真实协议测速）
# 用 mihomo 内核把节点池完整加载一遍（含 TLS/Reality/QUIC 真实握手），
# 再通过它的 REST API 逐节点发起真实代理请求 —— 结果与客户端体验一致，
# 不再受「TCP 探测摸不到 QUIC」的限制。
import subprocess  # noqa: E402  (deep check 专用)

MIHOMO_BIN = os.environ.get("SS_MIHOMO") or os.path.join(BASE, "bin", "mihomo")
_FP_ALLOWED = {"chrome", "firefox", "safari", "ios", "android", "edge",
               "360", "qq", "random"}
_FP_FIX = {"safair": "safari"}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _mihomo_net_opts(node, p):
    net = node.get("network") or "tcp"
    if net == "ws":
        p["network"] = "ws"
        opts = {"path": node.get("ws_path") or "/"}
        if node.get("ws_host"):
            opts["headers"] = {"Host": node["ws_host"]}
        p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": node.get("grpc_service") or ""}


def node_to_mihomo(node):
    """节点 dict → mihomo 代理配置 dict；不支持的协议（如 ssr）返回 None。"""
    t = node.get("type")
    name = node.get("name") or f"{node.get('server')}:{node.get('port')}"

    def _alpn():
        raw = node.get("alpn") or ""
        return [x for x in re.split(r"[,，\s]+", raw) if x] or None

    try:
        if t == "ss":
            return {"name": name, "type": "ss", "server": node["server"],
                    "port": int(node["port"]),
                    "cipher": node.get("method") or "aes-128-gcm",
                    "password": node.get("password") or "", "udp": True}
        if t == "vmess":
            p = {"name": name, "type": "vmess", "server": node["server"],
                 "port": int(node["port"]), "uuid": node.get("uuid", ""),
                 "alterId": int(node.get("aid") or 0),
                 "cipher": node.get("cipher") or "auto", "udp": True}
            if node.get("tls"):
                p["tls"] = True
            if node.get("sni"):
                p["servername"] = node["sni"]
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            _mihomo_net_opts(node, p)
            return p
        if t == "vless":
            p = {"name": name, "type": "vless", "server": node["server"],
                 "port": int(node["port"]), "uuid": node.get("uuid", ""),
                 "udp": True}
            if node.get("tls") or node.get("reality"):
                p["tls"] = True
            if node.get("flow"):
                p["flow"] = node["flow"]
            if node.get("sni"):
                p["servername"] = node["sni"]
            if node.get("reality"):
                ro = {"public-key": node.get("pbk", "")}
                if node.get("sid"):
                    ro["short-id"] = node["sid"]
                p["reality-opts"] = ro
            fp = _FP_FIX.get(node.get("fp") or "", node.get("fp") or "")
            p["client-fingerprint"] = fp if fp in _FP_ALLOWED else "chrome"
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            _mihomo_net_opts(node, p)
            return p
        if t == "trojan":
            p = {"name": name, "type": "trojan", "server": node["server"],
                 "port": int(node["port"]),
                 "password": node.get("password") or "", "udp": True}
            if node.get("sni"):
                p["sni"] = node["sni"]
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            _mihomo_net_opts(node, p)
            return p
        if t == "hysteria":
            p = {"name": name, "type": "hysteria", "server": node["server"],
                 "port": int(node["port"]),
                 "auth-str": node.get("auth") or "",
                 "up": int(node.get("up") or 100),
                 "down": int(node.get("down") or 100)}
            if node.get("sni"):
                p["sni"] = node["sni"]
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            return p
        if t == "hysteria2":
            p = {"name": name, "type": "hysteria2", "server": node["server"],
                 "port": int(node["port"]),
                 "password": node.get("password") or ""}
            if node.get("obfs"):
                p["obfs"] = "salamander"
                if node.get("obfs_pw"):
                    p["obfs-password"] = node["obfs_pw"]
            if node.get("ports"):
                p["ports"] = node["ports"]
            if node.get("sni"):
                p["sni"] = node["sni"]
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            return p
        if t == "tuic":
            p = {"name": name, "type": "tuic", "server": node["server"],
                 "port": int(node["port"]),
                 "congestion-controller": node.get("congestion") or "bbr",
                 "udp-relay-mode": node.get("udp_mode") or "native"}
            if node.get("uuid"):
                p["uuid"] = node["uuid"]
            if node.get("password"):
                p["password"] = node["password"]
            if node.get("token"):
                p["token"] = node["token"]
            if node.get("sni"):
                p["sni"] = node["sni"]
            if _alpn():
                p["alpn"] = _alpn()
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            return p
        if t == "anytls":
            p = {"name": name, "type": "anytls", "server": node["server"],
                 "port": int(node["port"]),
                 "password": node.get("password") or "", "udp": True}
            if node.get("sni"):
                p["sni"] = node["sni"]
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            return p
        if t in ("socks5", "http"):
            p = {"name": name, "type": t, "server": node["server"],
                 "port": int(node["port"])}
            if node.get("username"):
                p["username"] = node["username"]
            if node.get("password"):
                p["password"] = node["password"]
            if node.get("tls") or node.get("insecure"):
                p["tls"] = True
            if node.get("sni"):
                p["sni"] = node["sni"]
            return p
        if t == "socks5-tls":
            p = {"name": name, "type": "socks5", "server": node["server"],
                 "port": int(node["port"]), "tls": True, "udp": True}
            if node.get("username"):
                p["username"] = node["username"]
            if node.get("password"):
                p["password"] = node["password"]
            if node.get("sni"):
                p["sni"] = node["sni"]
            if node.get("insecure"):
                p["skip-cert-verify"] = True
            return p
        if t == "snell":
            return {"name": name, "type": "snell", "server": node["server"],
                    "port": int(node["port"]), "psk": node.get("password") or "",
                    "version": _to_int(node.get("version"), 4) or 4, "udp": True}
        if t == "ssh":
            p = {"name": name, "type": "ssh", "server": node["server"],
                 "port": int(node["port"]),
                 "username": node.get("username") or "root"}
            if node.get("password"):
                p["password"] = node["password"]
            if node.get("privkey"):
                p["private-key"] = node["privkey"]
            if node.get("key_pass"):
                p["private-key-passphrase"] = node["key_pass"]
            return p
        if t == "wireguard":
            p = {"name": name, "type": "wireguard", "server": node["server"],
                 "port": int(node["port"]),
                 "ip": (node.get("wg_addr") or "172.16.0.2/32").split("/")[0],
                 "private-key": node.get("wg_privkey", ""),
                 "public-key": node.get("wg_pubkey", ""),
                 "allowed-ips": [x for x in re.split(r"[,，\s]+",
                                 node.get("wg_allowed") or "0.0.0.0/0") if x],
                 "udp": True}
            if node.get("wg_psk"):
                p["pre-shared-key"] = node["wg_psk"]
            if node.get("wg_mtu"):
                p["mtu"] = _to_int(node["wg_mtu"], 1420) or 1420
            return p
    except Exception:
        return None
    return None    # ssr / brook / juicity / gost / http2 / http3 / 未知协议：仅做 TCP 存活检测


def deep_check(node_ids=None):
    """测速（唯一入口）：mihomo 加载节点池 → REST API 逐节点真实代理请求。

    结果写回：
      可用    alive=True,  probe='deep',       latency_ms=真实握手毫秒
      不可用  alive=False, probe='deep_fail'
    内核不支持的协议（ssr / brook / juicity / gost / naive / http3）降级为
    端口层探测，如实标注「仅端口可达 / 不可用 / 无法确认」，不假装是实测通过。
    """
    if not _DEEP_LOCK.acquire(blocking=False):
        return {"ok": False, "error": "测速正在进行中，请稍候再试"}
    try:
        return _deep_check_locked(node_ids)
    finally:
        _DEEP_LOCK.release()


def _port_fallback_check(node_ids=None):
    """无 mihomo 内核（如 Docker 未内置）时的全部端口层探测。
    如实标注 probe=ok/refused/dns/timeout/udp，不伪装成内核实测。"""
    data = load_data()
    targets = [n for n in data["nodes"] if node_ids is None or n["id"] in node_ids]
    out, now = [], time.strftime("%Y-%m-%d %H:%M:%S")
    if targets:
        timeout = data.get("settings", {}).get("health_timeout", 3)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(check_node, n, timeout): n for n in targets}
            for fut in concurrent.futures.as_completed(futs):
                node = futs[fut]
                try:
                    state, latency = fut.result()
                except Exception:
                    state, latency = "error", None
                node["probe"] = state
                node["alive"] = (True if state == "ok"
                                 else False if state in ("refused", "dns")
                                 else None)
                node["latency_ms"] = latency
                node["checked_at"] = now
                out.append({"id": node["id"], "name": node["name"], "probe": state,
                            "alive": node["alive"], "latency_ms": latency})
    save_data(data)
    regen_outputs(data)
    alive = sum(1 for r in out if r["alive"] is True)
    dead = sum(1 for r in out if r["alive"] is False)
    port_only = sum(1 for r in out if r["probe"] == "ok")
    states = {}
    for r in out:
        states[r["probe"]] = states.get(r["probe"], 0) + 1
    return {"ok": True, "total": len(out), "alive": alive, "dead": dead,
            "unknown": len(out) - alive - dead, "port_only": port_only,
            "skipped": len(out), "states": states,
            "state_labels": PROBE_STATES, "results": out}


def _deep_check_locked(node_ids=None):
    if not os.path.exists(MIHOMO_BIN):
        # 无内核（如 Docker 部署未内置 mihomo）：全部走端口层探测
        return _port_fallback_check(node_ids)
    data = load_data()
    targets = [n for n in data["nodes"] if node_ids is None or n["id"] in node_ids]
    if not targets:
        return {"ok": True, "total": 0, "alive": 0, "dead": 0, "unknown": 0,
                "skipped": 0, "port_only": 0, "states": {}, "results": []}
    test_url = (data.get("settings", {}).get("sr_test_url")
                or "http://www.gstatic.com/generate_204")
    seen, proxies, name_by_id = {}, [], {}
    fallback = []                                   # 内核不支持 → 端口层回退
    for n in targets:
        mp = node_to_mihomo(n)
        if not mp:
            fallback.append(n)
            continue
        k = seen.get(mp["name"], 0)
        seen[mp["name"]] = k + 1
        if k:
            mp["name"] = f"{mp['name']} #{k + 1}"
        name_by_id[n["id"]] = mp["name"]
        proxies.append(mp)

    results, ready = {}, False
    if proxies:
        api_port = _free_port()
        run_dir = os.path.join(OUTPUT_DIR, "mihomo-run")
        os.makedirs(run_dir, exist_ok=True)
        conf_path = os.path.join(run_dir, "deep-test.json")
        with open(conf_path, "w", encoding="utf-8") as f:
            json.dump({"mixed-port": 0,
                       "external-controller": f"127.0.0.1:{api_port}",
                       "mode": "global", "log-level": "silent", "ipv6": False,
                       "proxies": proxies, "rules": []}, f, ensure_ascii=False)

        proc = subprocess.Popen([MIHOMO_BIN, "-f", conf_path, "-d", run_dir],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sess = requests.Session()
        sess.trust_env = False          # 绝不走系统代理访问本地内核
        api = f"http://127.0.0.1:{api_port}"
        try:
            for _ in range(50):
                if proc.poll() is not None:
                    break
                try:
                    if sess.get(api + "/version", timeout=1).ok:
                        ready = True
                        break
                except Exception:
                    time.sleep(0.2)
            if ready:
                def probe_one(nid, name):
                    try:
                        r = sess.get(f"{api}/proxies/{urllib.parse.quote(name, safe='')}/delay",
                                     params={"timeout": 5000, "url": test_url}, timeout=9)
                        if r.ok:
                            return nid, int(r.json().get("delay") or 0)
                    except Exception:
                        pass
                    return nid, None

                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                    futs = [ex.submit(probe_one, n["id"], name_by_id[n["id"]])
                            for n in targets if n["id"] in name_by_id]
                    for fut in concurrent.futures.as_completed(futs):
                        nid, delay = fut.result()
                        results[nid] = delay
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()

    out, now = [], time.strftime("%Y-%m-%d %H:%M:%S")
    if proxies and not ready:
        return {"ok": False, "error": "内核启动失败，未能完成真实测速"}
    for n in targets:
        if n["id"] not in name_by_id:
            continue
        delay = results.get(n["id"])
        n["alive"] = delay is not None
        n["latency_ms"] = delay
        n["probe"] = "deep" if delay is not None else "deep_fail"
        n["checked_at"] = now
        out.append({"id": n["id"], "name": n["name"], "probe": n["probe"],
                    "alive": n["alive"], "latency_ms": n["latency_ms"]})

    # 端口层回退：内核不支持的协议，只确认端口是否可达
    if fallback:
        timeout = data.get("settings", {}).get("health_timeout", 3)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(check_node, n, timeout): n for n in fallback}
            for fut in concurrent.futures.as_completed(futs):
                node = futs[fut]
                try:
                    state, latency = fut.result()
                except Exception:
                    state, latency = "error", None
                node["probe"] = state
                node["alive"] = (True if state == "ok"
                                 else False if state in ("refused", "dns")
                                 else None)
                node["latency_ms"] = latency
                node["checked_at"] = now
                out.append({"id": node["id"], "name": node["name"], "probe": state,
                            "alive": node["alive"], "latency_ms": latency})

    save_data(data)
    regen_outputs(data)
    alive = sum(1 for r in out if r["alive"] is True)
    dead = sum(1 for r in out if r["alive"] is False)
    port_only = sum(1 for r in out if r["probe"] == "ok")
    states = {}
    for r in out:
        states[r["probe"]] = states.get(r["probe"], 0) + 1
    return {"ok": True, "total": len(out), "alive": alive, "dead": dead,
            "unknown": len(out) - alive - dead, "port_only": port_only,
            "skipped": len(fallback), "states": states,
            "state_labels": PROBE_STATES, "results": out}


def health_worker():
    """后台自动测速线程：与手动测速同一套判定（内核实测，不支持协议回退端口探测）"""
    while True:
        try:
            data = load_data()
            st = data.get("settings", {})
            if st.get("auto_health") and st.get("health_interval_minutes", 0) > 0:
                if not deep_check().get("ok"):
                    run_health_check()          # 内核缺席时退化为端口探测
                # 内核实测要拉起内核，间隔下限 5 分钟，避免频繁占用
                time.sleep(max(300, int(st["health_interval_minutes"]) * 60))
            else:
                time.sleep(30)
        except Exception:
            time.sleep(60)


# ---------------------------------------------------------- grouping / LB
def group_member_nodes(data, group):
    """分组实际包含的节点 = 显式成员 + 来自指定订阅源的节点；默认分组包含全部节点"""
    if group.get("is_default"):
        return list(data["nodes"])
    auto = set(group.get("auto_sources") or [])
    explicit = list(group.get("members") or [])
    member_ids = set(explicit)
    for n in data["nodes"]:
        if n.get("source") in auto or auto.intersection(n.get("source_ids") or []):
            member_ids.add(n["id"])
    nodes = [n for n in data["nodes"] if n["id"] in member_ids]
    order = {nid: i for i, nid in enumerate(explicit)}   # 显式成员保留人工顺序
    nodes.sort(key=lambda n: order.get(n["id"], len(order)))
    return nodes


def apply_strategy(nodes, group):
    """按分组策略排序/过滤，返回 (节点列表, 说明文本)"""
    strategy = group.get("strategy", "manual")
    total = len(nodes)
    note = ""

    if strategy == "failover":
        alive = [n for n in nodes if n.get("alive") is not False]
        if alive and len(alive) < total:
            nodes = alive
            note = f"故障转移：输出 {len(nodes)}/{total} 个健康节点，已剔除 {total - len(nodes)} 个不可达节点"
        elif alive and total:
            nodes = alive
            note = f"故障转移：全部 {total} 个节点均可用"
        else:
            note = f"故障转移：暂无健康节点，已回退输出全部 {total} 个节点"
        nodes = sorted(nodes, key=lambda n: (n.get("latency_ms") is None,
                                             n.get("latency_ms") or 99999))
    elif strategy == "latency":
        nodes = sorted(nodes, key=lambda n: (n.get("latency_ms") is None,
                                             n.get("latency_ms") or 99999))
        note = "延迟优先排序"
    elif strategy == "round_robin":
        k = 0
        if nodes:
            with _lock:
                k = _rr_counters.get(group["id"], 0)
                _rr_counters[group["id"]] = (k + 1) % len(nodes)
            nodes = nodes[k:] + nodes[:k]
        note = f"轮询起始位 {k}"
    elif strategy == "random":
        nodes = list(nodes)
        random.shuffle(nodes)
        note = "随机排序"
    else:
        note = "手动顺序"

    return nodes, note


def build_uris_for_group(data, group):
    nodes = group_member_nodes(data, group)
    nodes, note = apply_strategy(nodes, group)
    return [make_ss_uri(n) for n in nodes], nodes, note


def build_mihomo_config(data):
    """Translate the page model into a persistent mihomo gateway config."""
    groups = []
    for group in data.get("groups", []):
        copy = dict(group)
        copy["_mihomo_members"] = group_member_nodes(data, group)
        groups.append(copy)
    view = dict(data)
    view["groups"] = groups
    return build_config(view, node_to_mihomo, MIHOMO_DIR, MIHOMO_API_PORT)


def refresh_mihomo_if_running(data):
    """Apply model changes immediately when the managed gateway is active."""
    if not _mihomo.status().get("running"):
        return
    _mihomo.write_config(build_mihomo_config(data))
    _mihomo.start()


# --------------------------------------------------------- Shadowrocket conf
SR_TEST_URL = "http://www.gstatic.com/generate_204"
SR_STRATEGY_MAP = {
    # 我们的策略 → Shadowrocket(Surge 兼容) 策略组类型
    "manual":      ("select", ""),
    "latency":     ("url-test", f"url={SR_TEST_URL}, interval=600, tolerance=50"),
    "round_robin": ("load-balance", f"url={SR_TEST_URL}, interval=600"),
    "random":      ("load-balance", f"url={SR_TEST_URL}, interval=600"),
    "failover":    ("fallback", f"url={SR_TEST_URL}, interval=600"),
}


def _sr_policy_name(name, used):
    """Shadowrocket 策略名不能包含逗号/等号/换行，且全局唯一"""
    name = re.sub(r'[,="\r\n]', " ", str(name or "")).strip() or "Node"
    base, i = name, 2
    while name.lower() in used:
        name = f"{base} {i}"
        i += 1
    used.add(name.lower())
    return name


def parse_acl_rules(text):
    """把 ACL 文本解析为 (default_proxy, [(type, value, action)])。
    default_proxy: [bypass_all] 时 True（规则条目直连，其余走代理）；
                   [proxy_all] 时 False（规则条目走代理，其余直连）。
    action ∈ {DIRECT, PROXY, REJECT}"""
    mode, section, entries = None, None, []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        low = line.lower()
        if low.startswith("["):
            if low == "[bypass_all]":
                mode, section = "proxy", None
            elif low == "[proxy_all]":
                mode, section = "direct", None
            elif low == "[bypass_list]":
                section = "bypass"
            elif low == "[proxy_list]":
                section = "proxy"
            continue
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) < 2:
            continue
        typ, val = parts[0].upper(), parts[1]
        if len(parts) >= 3 and parts[2].upper() in ("DIRECT", "PROXY", "REJECT"):
            action = parts[2].upper()
        elif section == "bypass":
            action = "DIRECT"
        elif section == "proxy":
            action = "PROXY"
        else:
            continue
        entries.append((typ, val, action))
    if mode is None:
        mode = "proxy"
    return mode, entries


def _resolve_final_group(data):
    """Shadowrocket [Rule] FINAL 指向的分组：设置指定 > 第一个非默认分组 > 默认分组"""
    want = (data["settings"] or {}).get("sr_final_group")
    groups = data["groups"]
    return (next((g for g in groups if g["id"] == want), None)
            or next((g for g in groups if not g.get("is_default")), None)
            or (groups[0] if groups else None))


def _resolve_policy(token, name_map, default_policy):
    """把规则里的动作解析为配置中的策略名。
    DIRECT / REJECT 原样保留；PROXY 解析为默认出口；分组名解析为该分组的策略名"""
    t = (token or "").strip()
    u = t.upper()
    if u in ("DIRECT", "REJECT", "REJECT-DROP", "PASS"):
        return u
    if u in ("PROXY", ""):
        return default_policy
    return name_map.get(t.lower(), default_policy)


def _build_surge_rules(data, gid_names, default_policy):
    """Surge 风格规则文本 → 配置中的 [Rule] 行；自动补 FINAL"""
    name_map = {g["name"].strip().lower(): gid_names[g["id"]] for g in data["groups"]}
    lines, has_final = [], False
    for raw in (data.get("surge_rules") or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) < 2:
            continue
        typ = parts[0].upper()
        if typ in ("FINAL", "MATCH"):
            lines.append("FINAL," + _resolve_policy(parts[1], name_map, default_policy))
            has_final = True
            continue
        # 表单认不出的写法（自定义类型等）原样透传，避免被悄悄改写
        if typ not in RULE_TYPE_LABEL:
            lines.append(",".join(parts))
            continue
        if len(parts) < 3:
            continue
        policy = _resolve_policy(parts[2], name_map, default_policy)
        lines.append(",".join([typ, parts[1], policy] + parts[3:]))
    if not has_final:
        lines.append(f"FINAL,{default_policy}")
    return lines


# 表单模式支持匹配的类型（值 → 中文标签）。未在此列出的行原样保留为「原文行」
RULE_TYPE_LABEL = {
    "DOMAIN":        "域名精确",
    "DOMAIN-SUFFIX": "域名后缀",
    "DOMAIN-KEYWORD": "域名关键字",
    "IP-CIDR":       "IP 段",
    "IP-CIDR6":      "IPv6 段",
    "GEOIP":         "国家/地区",
    "USER-AGENT":    "User-Agent",
    "URL-REGEX":     "URL 正则",
    "PROCESS-NAME":  "进程名",
    "RULE-SET":      "规则集",
    "DEST-PORT":     "目标端口",
    "SRC-IP":        "来源 IP",
    "PROTOCOL":      "协议",
    "FINAL":         "兜底匹配",
}
RULE_ACTIONS = ["PROXY", "DIRECT", "REJECT"]
_FINAL_TYPES = ("FINAL", "MATCH")


def parse_rule_rows(text):
    """规则文本 → 结构化行，**无损**：
    能识别的变成 rule/final 行，注释与不认识的写法变成 raw 行原样保留，
    因此表单模式与文本模式来回切换不会丢内容、也不改变匹配顺序。"""
    rows = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            rows.append({"kind": "raw", "text": raw.rstrip()})
            continue
        parts = [p.strip() for p in line.split(",")]
        typ = parts[0].upper()
        if typ in _FINAL_TYPES:
            rows.append({"kind": "final",
                         "action": parts[1] if len(parts) > 1 and parts[1] else "PROXY"})
            continue
        if typ not in RULE_TYPE_LABEL or len(parts) < 3 or not parts[1]:
            rows.append({"kind": "raw", "text": raw.rstrip()})
            continue
        rows.append({"kind": "rule", "type": typ, "value": parts[1],
                     "action": parts[2], "extra": [p for p in parts[3:] if p]})
    return rows


def rule_rows_to_text(rows):
    """结构化行 → 规则文本（与 parse_rule_rows 互逆）"""
    out = []
    for r in (rows or []):
        k = (r or {}).get("kind")
        if k == "raw":
            out.append(r.get("text", ""))
        elif k == "final":
            out.append("FINAL," + (r.get("action") or "PROXY"))
        elif k == "rule":
            seg = [str(r.get("type") or "DOMAIN-SUFFIX").upper(),
                   str(r.get("value") or "").strip(),
                   (r.get("action") or "PROXY").strip()]
            seg += [str(e).strip() for e in (r.get("extra") or []) if str(e).strip()]
            out.append(",".join(seg))
    return "\n".join(out)


def _sr_group_options(data, g):
    """策略组测速参数：分组级覆盖 > 全局设置 > 默认值"""
    st = data.get("settings") or {}
    url = g.get("test_url") or st.get("sr_test_url") or "http://www.gstatic.com/generate_204"
    interval = g.get("interval") or st.get("sr_interval") or 300
    tolerance = g.get("tolerance") or st.get("sr_tolerance") or 50
    try:
        interval, tolerance = int(interval), int(tolerance)
    except (TypeError, ValueError):
        interval, tolerance = 300, 50
    return url, interval, tolerance


def build_shadowrocket_conf(data):
    """生成 Shadowrocket 配置文件（Surge 兼容格式）
    [Proxy] 支持全部协议；[Proxy Group] 按分组的负载均衡策略生成；
    [Rule] 来自「规则」页的 Surge 风格规则。"""
    used = set()
    node_names = {}
    proxy_lines = []
    udp = bool((data["settings"] or {}).get("sr_udp_relay", True))
    for n in data["nodes"]:
        nm = _sr_policy_name(n["name"], used)
        node_names[n["id"]] = nm
        proxy_lines.append(protocols.conf_line(n, nm, udp=udp))

    gid_names = {}
    for g in data["groups"]:
        gid_names[g["id"]] = _sr_policy_name(g["name"], used)

    group_lines = []
    for g in data["groups"]:
        head, _ = SR_STRATEGY_MAP.get(g.get("strategy", "manual"),
                                      SR_STRATEGY_MAP["manual"])
        members = group_member_nodes(data, g)
        mnames = [node_names[m["id"]] for m in members] or ["DIRECT"]
        line = f"{gid_names[g['id']]} = {head}, " + ", ".join(mnames)
        if head in ("url-test", "fallback", "load-balance"):
            url, interval, tolerance = _sr_group_options(data, g)
            params = [f"url={url}", f"interval={interval}"]
            if head == "url-test":
                params.append(f"tolerance={tolerance}")
            line += ", " + ", ".join(params)
        group_lines.append(line)

    final_group = _resolve_final_group(data)
    final_name = gid_names.get(final_group["id"], "DIRECT") if final_group else "DIRECT"
    rule_lines = _build_surge_rules(data, gid_names, final_name)

    # DNS 设置（[General] 覆写 + [Host] 指定域名 DNS / 固定映射）
    dns = norm_sr_dns((data["settings"] or {}).get("sr_dns"))
    dns_general = [f"dns-server = {dns['servers']}"]
    if dns["direct"]:
        dns_general.append(f"direct-dns-server = {dns['direct']}")
    if dns["fallback"]:
        dns_general.append(f"fallback-dns-server = {dns['fallback']}")
    if dns["local_for_proxy"]:
        # 让本地 [Host] 映射与解析对代理连接也生效（默认代理域名在节点端解析）
        dns_general.append("use-local-host-item-for-proxy = true")
    host_lines = [f"{h['domain']} = " + (f"server:{h['value']}" if h["mode"] == "dns" else h["value"])
                  for h in dns["hosts"]]

    # WireGuard 节点单独生成 [WireGuard] 接口段（Surge 兼容格式）
    wg_lines = []
    for n in data["nodes"]:
        if n.get("type") != "wireguard":
            continue
        sec = "wgin-" + (n.get("id") or "x")
        kv = [f"interface-private-key={n.get('wg_privkey', '')}"]
        if n.get("wg_addr"):
            kv.append(f"interface-address={n['wg_addr']}")
        if n.get("wg_dns"):
            kv.append(f"dns={n['wg_dns']}")
        if n.get("wg_mtu"):
            kv.append(f"mtu={n['wg_mtu']}")
        peer = [f"peer = public-key={n.get('wg_pubkey', '')}",
                f"endpoint={protocols._wrap_host(n['server'])}:{n['port']}",
                f"allowed-ips={n.get('wg_allowed') or '0.0.0.0/0'}"]
        if n.get("wg_psk"):
            peer.append(f"preshared-key={n['wg_psk']}")
        if n.get("wg_keepalive"):
            peer.append(f"keepalive={n['wg_keepalive']}")
        wg_lines.append(f"{sec} = " + ", ".join(kv) + ", " + ", ".join(peer))

    sections = [
        "# Shadowrocket 配置文件（由配置中心自动生成，客户端重新下载配置即更新）",
        f"# 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')}  节点 {len(proxy_lines)} 个 / 策略组 {len(group_lines)} 个",
        "",
        "[General]",
        "loglevel = notify",
        "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, "
        "100.64.0.0/10, localhost, *.local",
        "bypass-tun = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, "
        "172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32, fe80::/10",
        *dns_general,
        "proxy-test-url = " + (data["settings"] or {}).get(
            "sr_test_url", "http://www.gstatic.com/generate_204"),
        "",
        "[Proxy]",
        *(proxy_lines or ["# 暂无节点"]),
        "",
        "[Proxy Group]",
        *(group_lines or ["# 暂无分组"]),
        "",
    ]
    if wg_lines:
        sections += ["[WireGuard]", *wg_lines, ""]
    if host_lines:
        sections += ["[Host]", *host_lines, ""]
    sections += ["[Rule]", *rule_lines, ""]
    return "\n".join(sections)


def build_surge_gateway_conf(data, only_group=None):
    """Surge config consuming the local SOCKS5 ports exposed by mihomo."""
    lines = ["# SubWeaver -> mihomo SOCKS5 网关", "[General]", "loglevel = notify", "", "[Proxy]"]
    names, used = [], set()
    for i, g in enumerate(data.get("groups", [])):
        if only_group and g.get("id") != only_group.get("id"):
            continue
        if not g.get("socks5_enabled", True):
            continue
        if not group_member_nodes(data, g):
            continue            # 空分组没有监听器，写进配置只会是个连不上的死端口
        name = _sr_policy_name(g.get("name"), used)
        names.append(name)
        port = int(g.get("socks5_port") or (18080 + i))
        # 客户端要填的是能连上的地址：通配绑定（0.0.0.0）换成局域网 IP
        host = _client_host(g.get("socks5_listen"))
        lines.append(f"{name} = socks5, {host}, {port}")
    # 分组级配置中，代理名称可能与分组名称相同；策略组必须使用独立名称，
    # 否则 Surge 会把同名代理与策略组解析为冲突项。
    policy_name = "SubWeaver"
    lines += ["", "[Proxy Group]", policy_name + " = select, " + (", ".join(names) if names else "DIRECT"),
              "", "[Rule]", "FINAL," + policy_name, ""]
    return "\n".join(lines)


def regen_outputs(data):
    """生成订阅文件（全部 + 每个分组），可直接部署到任何静态服务器"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    def write_pair(path_base, uris):
        text = "\n".join(uris) + ("\n" if uris else "")
        with open(path_base + ".txt", "w", encoding="utf-8") as f:
            f.write(text)
        with open(path_base + ".b64", "w", encoding="utf-8") as f:
            f.write(base64.b64encode(text.encode()).decode())

    # 清理已删除的分组遗留文件
    for name in os.listdir(OUTPUT_DIR):
        if name.startswith("group-") and name.endswith((".txt", ".b64")):
            os.remove(os.path.join(OUTPUT_DIR, name))

    all_uris = [make_ss_uri(n) for n in data["nodes"]]
    write_pair(os.path.join(OUTPUT_DIR, "subscription"), all_uris)

    index = []
    for g in data["groups"]:
        uris, nodes, note = build_uris_for_group(data, g)
        safe = re.sub(r"[^\w\-]+", "_", g["name"]) or g["id"]
        write_pair(os.path.join(OUTPUT_DIR, f"group-{safe}"), uris)
        index.append({"id": g["id"], "name": g["name"], "strategy": g["strategy"],
                      "nodes": len(uris), "note": note})

    with open(os.path.join(OUTPUT_DIR, "rules.acl"), "w", encoding="utf-8") as f:
        f.write(data["rules"])
    with open(os.path.join(OUTPUT_DIR, "shadowrocket.conf"), "w", encoding="utf-8") as f:
        f.write(build_shadowrocket_conf(data))
    with open(os.path.join(OUTPUT_DIR, "pubinfo.json"), "w", encoding="utf-8") as f:
        json.dump({"token": data["publish_token"], "total_nodes": len(all_uris),
                   "groups": index}, f, ensure_ascii=False, indent=2)


# ------------------------------------------------ 静态托管发布包（上传即用）
# 打包成一 upload 就能用的静态目录：订阅文件 + 完整配置 + 手机友好的落地页。
# 落地页里的链接由浏览器按 location 自己拼绝对地址，所以换域名/换目录都不用重新导出。
PUBLISH_LANDING = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f4f5f7">
<title>Shadowrocket 订阅</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:22px 16px 40px;background:#f4f5f7;color:#1c1c1e;
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC","Segoe UI",sans-serif}
.wrap{max-width:720px;margin:0 auto}
h1{font-size:21px;letter-spacing:-.4px;margin:0 0 4px}
.meta{color:rgba(60,60,67,.6);font-size:13px;margin:0 0 16px}
.notice{background:rgba(255,159,10,.14);border:1px solid rgba(255,159,10,.3);
  border-radius:12px;padding:10px 13px;font-size:12.5px;color:#8a5a00;margin-bottom:16px}
.card{background:#fff;border:1px solid rgba(22,32,58,.08);border-radius:14px;
  padding:13px 15px;margin-bottom:11px;box-shadow:0 1px 2px rgba(22,32,58,.04)}
.card .top{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.card .t{font-weight:600;font-size:14.5px}
.card .d{color:rgba(60,60,67,.6);font-size:12.5px}
.card code{display:block;margin:8px 0 10px;padding:7px 9px;background:#f6f7f9;
  border:1px solid rgba(22,32,58,.07);border-radius:9px;font-size:11.5px;
  color:rgba(60,60,67,.8);word-break:break-all;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.ops{display:flex;gap:8px;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:5px;border:0;cursor:pointer;
  padding:8px 14px;border-radius:9px;font-size:13px;font-weight:500;text-decoration:none;
  font-family:inherit}
.btn.p{background:#007aff;color:#fff}
.btn.g{background:#eef0f3;color:#1c1c1e}
.hint{color:rgba(60,60,67,.55);font-size:12px;margin-top:20px;line-height:1.75}
.hint b{color:rgba(60,60,67,.75)}
.hint code{background:#eef0f3;border-radius:5px;padding:1px 5px;font-size:11.5px}
</style>
</head>
<body>
<div class="wrap">
  <h1>Shadowrocket 订阅</h1>
  <p class="meta">生成于 @@STAMP@@ · @@NODES@@ 个节点 · @@GROUPS@@ 个分组</p>
  <div class="notice">链接包含节点凭据，拿到链接即可使用。请勿公开分享或提交到公开仓库。</div>
  <div id="list"></div>
  <div class="hint">
    <b>导入方式</b><br>
    1. iPhone 上用 Safari 打开本页，点「导入」直接唤起 Shadowrocket 添加订阅<br>
    2. 或点「复制链接」后去 Shadowrocket → 首页 → 右上角 + → 类型选「订阅」粘贴<br>
    3. 要分组和分流规则：用「完整配置」那条，Shadowrocket → 底部「配置」→ 右上角 + → 粘贴<br>
    4. 自动更新：设置 → 服务器订阅 → 打开「打开时更新」；本机改动后重新导出并覆盖上传本目录
  </div>
</div>
<script>
var FILES = @@FILES@@;
function abs(f){ return new URL(f, location.href).href; }
function b64(s){ return btoa(unescape(encodeURIComponent(s))); }
function sr(u, r){ return 'shadowrocket://add/sub://' + b64(u) + '?remark=' + encodeURIComponent(r); }
function isIOS(){
  var ua = navigator.userAgent;
  return /iPhone|iPad|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}
function copy(t, btn){
  var done = function(){ var o = btn.textContent; btn.textContent = '已复制';
    setTimeout(function(){ btn.textContent = o; }, 1500); };
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(done, function(){ legacy(t, done); });
  } else { legacy(t, done); }
}
function legacy(t, done){
  try {
    var ta = document.createElement('textarea');
    ta.value = t; ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;opacity:0';
    document.body.appendChild(ta); ta.select(); ta.setSelectionRange(0, t.length);
    document.execCommand('copy'); ta.remove(); done();
  } catch (e) { prompt('请长按全选后复制：', t); }
}
var list = document.getElementById('list');
FILES.forEach(function(f){
  var url = abs(f.file);
  var el = document.createElement('div');
  el.className = 'card';
  el.innerHTML = '<div class="top"><span class="t"></span><span class="d"></span></div>'
    + '<code></code><div class="ops"></div>';
  el.querySelector('.t').textContent = f.label;
  el.querySelector('.d').textContent = f.desc;
  el.querySelector('code').textContent = url;
  var ops = el.querySelector('.ops');
  if (f.kind !== 'rule') {
    var a = document.createElement('a');
    a.className = 'btn p'; a.textContent = '导入'; a.href = sr(url, f.label);
    a.onclick = function(ev){
      if (!isIOS()) { ev.preventDefault(); copy(url, a); }
    };
    ops.appendChild(a);
  }
  var b = document.createElement('button');
  b.className = 'btn g'; b.textContent = '复制链接';
  b.onclick = function(){ copy(url, b); };
  ops.appendChild(b);
  list.appendChild(el);
});
</script>
</body>
</html>
"""

PUBLISH_README = """Shadowrocket 订阅发布包
生成时间：@@STAMP@@
内容：@@NODES@@ 个节点 / @@GROUPS@@ 个分组

【怎么用】
1. 把本目录里的所有文件原样上传到任意静态托管：
   GitHub Pages / Cloudflare Pages / Vercel / 对象存储（OSS/COS/R2）/ 自建 Nginx 都行
2. 手机浏览器打开你上传后的地址（.../index.html），页面会列出全部链接
3. 点「导入」直接唤起 Shadowrocket；也可以点「复制链接」手动添加订阅
4. 想带分组和分流规则：用 shadowrocket.conf（在 Shadowrocket「配置」页粘贴链接）
5. 自动更新：Shadowrocket → 设置 → 服务器订阅 → 打开「打开时更新」

【注意】
- 这些链接包含节点凭据，拿到链接即可使用你的节点。请勿公开分享，也不要提交到公开仓库。
- 节点或规则有改动后，需要重新导出本包并覆盖上传。
- index.html 里的链接是打开页面时按当前域名自动拼的，换域名/换目录都不用重新导出。

【文件说明】
@@FILELIST@@
"""


def _publish_slug(name, idx):
    """分组名 → 文件名安全片段：HK → hk；纯中文名 → g<序号>"""
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(name or "")).strip("-").lower()
    return s if len(s) >= 2 else "g%d" % (idx + 1)


def _export_items(data):
    """发布包清单（轻量，不含内容）：文件名 / 名称 / 说明 / 类型"""
    items = [{"file": "subscription.b64", "label": "全部节点（Base64）",
              "desc": "%d 个节点 · Shadowrocket 订阅格式，推荐" % len(data["nodes"]),
              "kind": "sub"},
             {"file": "subscription.txt", "label": "全部节点（明文）",
              "desc": "%d 个节点 · 每行一条 ss:// 链接" % len(data["nodes"]),
              "kind": "sub"}]
    for i, g in enumerate(data["groups"]):
        uris, _nodes, note = build_uris_for_group(data, g)
        slug = _publish_slug(g["name"], i)
        strat = next((s["name"] for s in STRATEGIES if s["key"] == g["strategy"]),
                     g["strategy"])
        desc = "%s · %d 节点%s" % (strat, len(uris), (" · " + note) if note else "")
        items.append({"file": "group-%s.b64" % slug, "label": "分组 · %s" % g["name"],
                      "desc": desc, "kind": "sub"})
        items.append({"file": "group-%s.txt" % slug, "label": "分组 · %s（明文）" % g["name"],
                      "desc": desc, "kind": "sub"})
    items.append({"file": "shadowrocket.conf", "label": "完整配置",
                  "desc": "节点 + 分组 + 分流规则，带策略与 DNS 设置", "kind": "conf"})
    items.append({"file": "rules.acl", "label": "规则文件",
                  "desc": "ACL 格式，ShadowsocksX-NG 等客户端使用", "kind": "rule"})
    return items


def build_publish_bundle(data):
    """生成发布包全部文件：{文件名: bytes}"""
    out = {}
    all_uris = [make_ss_uri(n) for n in data["nodes"]]
    text = "\n".join(all_uris) + ("\n" if all_uris else "")
    out["subscription.txt"] = text.encode()
    out["subscription.b64"] = base64.b64encode(text.encode())
    for i, g in enumerate(data["groups"]):
        uris, _nodes, _note = build_uris_for_group(data, g)
        slug = _publish_slug(g["name"], i)
        t = "\n".join(uris) + ("\n" if uris else "")
        out["group-%s.txt" % slug] = t.encode()
        out["group-%s.b64" % slug] = base64.b64encode(t.encode())
    out["shadowrocket.conf"] = build_shadowrocket_conf(data).encode()
    out["rules.acl"] = data["rules"].encode()

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    items = _export_items(data)
    landing = (PUBLISH_LANDING
               .replace("@@STAMP@@", stamp)
               .replace("@@NODES@@", str(len(data["nodes"])))
               .replace("@@GROUPS@@", str(len(data["groups"])))
               .replace("@@FILES@@", json.dumps(items, ensure_ascii=False)))
    out["index.html"] = landing.encode()
    out["manifest.json"] = json.dumps(
        {"generated_at": stamp, "node_count": len(data["nodes"]),
         "group_count": len(data["groups"]), "files": items},
        ensure_ascii=False, indent=2).encode()
    filelist = "\n".join("  %-26s %s" % (it["file"], it["desc"]) for it in items)
    out["README.txt"] = (PUBLISH_README
                         .replace("@@STAMP@@", stamp)
                         .replace("@@NODES@@", str(len(data["nodes"])))
                         .replace("@@GROUPS@@", str(len(data["groups"])))
                         .replace("@@FILELIST@@", filelist)).encode()
    return out


# ------------------------------------------------------------------- auth
def auth_disabled(data):
    """settings.require_login 显式为 False 时关闭登录：不显示登录页、API 直接放行。
    默认（含旧数据未迁移的 None）保持开启。"""
    return (data.get("settings") or {}).get("require_login") is False


def auth_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        data = load_data()
        if auth_disabled(data):
            return fn(*args, **kwargs)
        if not data.get("password_hash"):
            return jsonify({"error": "未初始化，请先设置管理密码", "need_setup": True}), 401
        if not session.get("auth"):
            return jsonify({"error": "未登录", "need_login": True}), 401
        return fn(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------- api
@app.route("/")
def index():
    # 首页禁止缓存：避免浏览器继续跑改动前的旧前端
    resp = send_from_directory(app.static_folder, "index.html")
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/status")
def api_status():
    data = load_data()
    disabled = auth_disabled(data)
    return jsonify({"need_setup": (not disabled) and not bool(data.get("password_hash")),
                    "auth_enabled": not disabled,
                    "logged_in": disabled or bool(session.get("auth")),
                    "node_count": len(data["nodes"]),
                    "group_count": len(data["groups"])})


@app.route("/api/setup", methods=["POST"])
def api_setup():
    data = load_data()
    if data.get("password_hash"):
        return jsonify({"error": "已初始化"}), 400
    password = (request.json or {}).get("password", "")
    if len(password) < 4:
        return jsonify({"error": "密码至少 4 位"}), 400
    data["password_hash"] = hash_password(password)
    save_data(data)
    session["auth"] = True
    session.permanent = True
    regen_outputs(data)
    return jsonify({"ok": True})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = load_data()
    if verify_password((request.json or {}).get("password", ""),
                       data.get("password_hash")):
        session["auth"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"error": "密码错误"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------- nodes
@app.route("/api/nodes", methods=["GET"])
@auth_required
def api_nodes():
    data = load_data()
    out = []
    for n in data["nodes"]:
        n = dict(n)
        n["type"] = n.get("type", "ss")
        n["uri"] = protocols.make_uri(n)        # 供前端一键复制
        out.append(n)
    return jsonify({"nodes": out})


def _to_int(v, default=0):
    try:
        return int(str(v).strip() or default)
    except (TypeError, ValueError):
        return default


def _node_from_form(n):
    """手工填写表单 → 统一节点结构。校验失败返回错误字符串"""
    t = (n.get("type") or "ss").strip().lower()
    if t not in protocols.TYPES:
        return "不支持的协议类型：" + t
    server = str(n.get("server") or "").strip()
    if not server or not n.get("port"):
        return "服务器与端口为必填项"
    port = _to_int(n.get("port"))
    if not 0 < port < 65536:
        return "端口不合法"
    node = {"type": t, "server": server, "port": port, "uri": "",
            "name": (n.get("name") or "").strip() or f"{server}:{port}"}

    def g(k, d=""):
        v = n.get(k)
        return v if v not in (None, "") else d

    if t == "ss":
        if not n.get("password"):
            return "Shadowsocks 需要填写密码"
        node.update({"method": g("method", "aes-256-gcm"), "password": str(n["password"]),
                     "plugin": g("plugin"), "plugin_opts": g("plugin_opts")})
    elif t == "ssr":
        node.update({"method": g("method", "none"), "password": g("password"),
                     "protocol": g("protocol", "origin"),
                     "protocol_param": g("protocol_param"), "obfs": g("obfs", "plain"),
                     "obfs_param": g("obfs_param")})
    elif t == "vmess":
        if not n.get("uuid"):
            return "VMess 需要填写 UUID"
        node.update({"uuid": str(n["uuid"]).strip(), "aid": _to_int(n.get("aid")),
                     "method": g("method", "auto"), "network": g("network", "tcp"),
                     "tls": bool(n.get("tls")), "sni": g("sni"), "alpn": g("alpn"),
                     "fp": g("fp"), "insecure": bool(n.get("insecure")),
                     "ws_path": g("ws_path"), "ws_host": g("ws_host"),
                     "grpc_service": g("grpc_service"), "grpc_mode": g("grpc_mode", "gun")})
    elif t == "vless":
        if not n.get("uuid"):
            return "VLESS 需要填写 UUID"
        node.update({"uuid": str(n["uuid"]).strip(), "encryption": "none",
                     "flow": g("flow"), "network": g("network", "tcp"),
                     "tls": bool(n.get("tls")) or bool(n.get("reality")),
                     "reality": bool(n.get("reality")), "pbk": g("pbk"), "sid": g("sid"),
                     "sni": g("sni"), "alpn": g("alpn"), "fp": g("fp"),
                     "insecure": bool(n.get("insecure")),
                     "ws_path": g("ws_path"), "ws_host": g("ws_host"),
                     "grpc_service": g("grpc_service"), "grpc_mode": g("grpc_mode", "gun")})
    elif t == "trojan":
        node.update({"password": g("password"), "sni": g("sni"),
                     "network": g("network", "tcp"), "ws_path": g("ws_path"),
                     "ws_host": g("ws_host"), "alpn": g("alpn"),
                     "insecure": bool(n.get("insecure"))})
    elif t == "hysteria2":
        node.update({"password": g("password"), "sni": g("sni"), "alpn": g("alpn"),
                     "obfs": g("obfs"), "obfs_pw": g("obfs_pw"), "ports": g("ports"),
                     "insecure": bool(n.get("insecure")), "tls": True})
    elif t == "hysteria":
        node.update({"auth": g("auth"), "up": g("up", "100"), "down": g("down", "100"),
                     "sni": g("sni"), "alpn": g("alpn"), "obfs": g("obfs"),
                     "insecure": bool(n.get("insecure"))})
    elif t == "tuic":
        node.update({"uuid": g("uuid"), "password": g("password"), "token": g("token"),
                     "sni": g("sni"), "alpn": g("alpn", "h3"),
                     "congestion": g("congestion"), "udp_mode": g("udp_mode"),
                     "insecure": bool(n.get("insecure")), "tls": True})
    elif t == "anytls":
        node.update({"password": g("password"), "sni": g("sni"), "alpn": g("alpn"),
                     "insecure": bool(n.get("insecure"))})
    elif t == "socks5":
        node.update({"username": g("username"), "password": g("password")})
    elif t == "socks5-tls":
        node.update({"username": g("username"), "password": g("password"),
                     "sni": g("sni"), "insecure": bool(n.get("insecure"))})
    elif t == "http":
        node.update({"username": g("username"), "password": g("password"),
                     "tls": bool(n.get("tls"))})
    elif t in ("http2", "http3"):
        if not n.get("username") or not n.get("password"):
            return f"{protocols.TYPE_LABEL[t]}（NaiveProxy）需要填写用户名与密码"
        node.update({"username": str(n["username"]), "password": str(n["password"]),
                     "sni": g("sni"), "tls": True, "insecure": bool(n.get("insecure"))})
    elif t == "snell":
        if not n.get("password"):
            return "Snell 需要填写 PSK 密码"
        node.update({"password": str(n["password"]),
                     "version": _to_int(n.get("snell_version"), 4) or 4})
    elif t == "ssh":
        if not n.get("username"):
            return "SSH 需要填写用户名"
        node.update({"username": str(n["username"]), "password": g("password"),
                     "privkey": g("privkey"), "key_pass": g("key_pass")})
    elif t == "brook":
        if not n.get("password"):
            return "Brook 需要填写密码"
        node.update({"password": str(n["password"])})
    elif t == "juicity":
        node.update({"password": g("password"), "sni": g("sni"),
                     "insecure": bool(n.get("insecure"))})
    elif t == "gost":
        node.update({"username": g("username"), "password": g("password"),
                     "tls": bool(n.get("tls"))})
    elif t == "wireguard":
        if not n.get("wg_privkey") or not n.get("wg_pubkey"):
            return "WireGuard 需要填写本端私钥与对端公钥"
        node.update({"wg_privkey": str(n["wg_privkey"]).strip(),
                     "wg_pubkey": str(n["wg_pubkey"]).strip(),
                     "wg_psk": g("wg_psk"),
                     "wg_addr": g("wg_addr", "172.16.0.2/32") or "172.16.0.2/32",
                     "wg_allowed": g("wg_allowed", "0.0.0.0/0") or "0.0.0.0/0",
                     "wg_dns": g("wg_dns"), "wg_mtu": g("wg_mtu"),
                     "wg_keepalive": g("wg_keepalive")})
    return node


@app.route("/api/nodes", methods=["POST"])
@auth_required
def api_add_node():
    data = load_data()
    n = request.json or {}
    if n.get("uri"):
        node = protocols.parse_uri(str(n["uri"]).strip())
        if not node:
            return jsonify({"error": "无法识别该链接，请确认协议是否受支持"}), 400
        if n.get("name"):
            node["name"] = str(n["name"]).strip()
            node["uri"] = ""           # 名称已改，让生成器按字段重建链接
    else:
        node = _node_from_form(n)
        if isinstance(node, str):
            return jsonify({"error": node}), 400
    node.update({"id": secrets.token_hex(4), "source": "custom",
                 "alive": None, "latency_ms": None})
    data["nodes"].append(node)
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "node": node})


@app.route("/api/nodes/<node_id>", methods=["DELETE"])
@auth_required
def api_del_node(node_id):
    data = load_data()
    data["nodes"] = [n for n in data["nodes"] if n["id"] != node_id]
    for g in data["groups"]:
        g["members"] = [m for m in g.get("members", []) if m != node_id]
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True})


@app.route("/api/nodes/<node_id>", methods=["PUT"])
@auth_required
def api_edit_node(node_id):
    """修改节点：按表单字段重建（保留 id 与来源，分组归属不变），测速结果清零待重测。

    注意：订阅节点的修改会在下次刷新订阅时被源内容覆盖。
    """
    data = load_data()
    idx = next((i for i, n in enumerate(data["nodes"]) if n["id"] == node_id), None)
    if idx is None:
        return jsonify({"error": "节点不存在"}), 404
    old = data["nodes"][idx]
    body = request.json or {}
    if body.get("uri"):
        node = protocols.parse_uri(str(body["uri"]).strip())
        if not node:
            return jsonify({"error": "无法识别该链接，请确认协议是否受支持"}), 400
        if body.get("name"):
            node["name"] = str(body["name"]).strip()
    else:
        node = _node_from_form(body)
        if isinstance(node, str):
            return jsonify({"error": node}), 400
    node["uri"] = node.get("uri") or ""      # 字段已变，让链接生成器按新字段重建
    node["source"] = old.get("source", "custom")
    if old.get("added_at"):
        node["added_at"] = old["added_at"]
    node.update({"id": node_id, "probe": None, "alive": None,
                 "latency_ms": None, "checked_at": ""})
    data["nodes"][idx] = node
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "node": node})


def _import_from_text(text):
    """文本导入：返回 (节点列表, 解析失败的行数)。支持明文/base64 包裹。"""
    content = protocols.decode_subscription_text(text)
    candidates = [l.strip() for l in content.replace("\r", "").split("\n")
                  if "://" in l]
    nodes = protocols.parse_lines(content)
    return nodes, max(0, len(candidates) - len(nodes))


@app.route("/api/nodes/import", methods=["POST"])
@auth_required
def api_import_nodes():
    data = load_data()
    text = (request.json or {}).get("text", "")
    stripped = (text or "").strip()
    # 粘贴的是单个订阅链接时，直接抓取解析
    if stripped.startswith(("http://", "https://")) and "\n" not in stripped:
        try:
            nodes = fetch_subscription(stripped)
        except Exception as e:
            return jsonify({"error": f"订阅抓取失败: {e}"}), 502
        failed = 0 if nodes else 1
    else:
        nodes, failed = _import_from_text(text)
    for n in nodes:
        n.update({"id": secrets.token_hex(4), "source": "custom",
                  "alive": None, "latency_ms": None})
    data["nodes"].extend(nodes)
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "added": len(nodes), "failed": failed})


@app.route("/api/nodes/parse", methods=["POST"])
@auth_required
def api_parse_sub_text():
    text = (request.json or {}).get("text", "")
    parsed, failed = _import_from_text(text)
    return jsonify({"nodes": parsed, "count": len(parsed), "failed": failed})


@app.route("/api/methods")
def api_methods():
    return jsonify({"methods": COMMON_METHODS, "strategies": STRATEGIES,
                    "types": protocols.TYPES,
                    "type_labels": protocols.TYPE_LABEL})


# ------------------------------------------------------------ subscriptions
@app.route("/api/subs", methods=["GET"])
@auth_required
def api_subs():
    data = load_data()
    return jsonify({"subscriptions": data["subscriptions"],
                    "nodes": data["nodes"], "groups": data["groups"]})


@app.route("/api/subs", methods=["POST"])
@auth_required
def api_add_sub():
    data = load_data()
    s = request.json or {}
    url = (s.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "请填写有效的订阅 URL"}), 400
    existing = next((x for x in data["subscriptions"]
                     if (x.get("url") or "").strip() == url), None)
    if existing:
        return jsonify({"error": "该订阅地址已存在", "duplicate": True,
                        "subscription": existing}), 409
    sub = {"id": secrets.token_hex(4), "name": (s.get("name") or "未命名订阅").strip(),
           "url": url, "last_update": None, "node_count": 0, "error": None}
    data["subscriptions"].append(sub)
    gid = s.get("auto_group")            # 可选：抓取后自动归入某分组
    if gid:
        g = next((x for x in data["groups"] if x["id"] == gid), None)
        if g and sub["id"] not in g["auto_sources"]:
            g["auto_sources"].append(sub["id"])
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "subscription": sub})


@app.route("/api/subs/<sub_id>/refresh", methods=["POST"])
@auth_required
def api_refresh_sub(sub_id):
    data = load_data()
    sub = next((s for s in data["subscriptions"] if s["id"] == sub_id), None)
    if not sub:
        return jsonify({"error": "订阅不存在"}), 404
    try:
        nodes = fetch_subscription(sub["url"])
    except Exception as e:
        sub["error"] = str(e)
        save_data(data)
        return jsonify({"error": f"抓取失败: {e}"}), 502
    # Never replace a healthy subscription with an empty result. Empty
    # responses usually mean an upstream format change or transient failure.
    if not nodes:
        sub["error"] = "订阅返回为空，已保留上次节点"
        save_data(data)
        return jsonify({"error": sub["error"], "preserved": True,
                        "node_count": int(sub.get("node_count") or 0)}), 502
    nodes = _prepare_refreshed_nodes(data, sub_id, nodes)
    data["nodes"] = [n for n in data["nodes"] if n.get("source") != sub_id]
    data["nodes"].extend(nodes)
    sub.update({"last_update": time.strftime("%Y-%m-%d %H:%M"),
                "node_count": len(nodes), "error": None})
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "node_count": len(nodes)})


@app.route("/api/subs/refresh_all", methods=["POST"])
@auth_required
def api_refresh_all_subs():
    data = load_data()
    summary = []
    for sub in list(data["subscriptions"]):
        try:
            nodes = fetch_subscription(sub["url"])
            if not nodes:
                sub["error"] = "订阅返回为空，已保留上次节点"
                summary.append({"name": sub["name"], "nodes": int(sub.get("node_count") or 0),
                                "ok": False, "error": sub["error"], "preserved": True})
                continue
            nodes = _prepare_refreshed_nodes(data, sub["id"], nodes)
            data["nodes"] = [n for n in data["nodes"] if n.get("source") != sub["id"]]
            data["nodes"].extend(nodes)
            sub.update({"last_update": time.strftime("%Y-%m-%d %H:%M"),
                        "node_count": len(nodes), "error": None})
            summary.append({"name": sub["name"], "nodes": len(nodes), "ok": True})
        except Exception as e:
            sub["error"] = str(e)
            summary.append({"name": sub["name"], "nodes": 0, "ok": False,
                            "error": str(e)})
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "summary": summary})


@app.route("/api/subs/<sub_id>", methods=["PUT"])
@auth_required
def api_edit_sub(sub_id):
    """编辑订阅源：名称 / 订阅地址 / 自动归组"""
    data = load_data()
    sub = next((s for s in data["subscriptions"] if s["id"] == sub_id), None)
    if not sub:
        return jsonify({"error": "订阅不存在"}), 404
    s = request.json or {}
    url = (s.get("url") or "").strip()
    if url and not url.startswith(("http://", "https://")):
        return jsonify({"error": "请填写有效的订阅 URL"}), 400
    url_changed = bool(url) and url != sub["url"]
    if url:
        sub["url"] = url
    name_changed = False
    if (s.get("name") or "").strip():
        new_name = s["name"].strip()
        name_changed = new_name != sub["name"]
        sub["name"] = new_name
    if name_changed:            # 同步已有节点的来源名，无需等下次刷新
        for n in data["nodes"]:
            if n.get("source") == sub_id:
                n["source_name"] = sub["name"]
    if "auto_group" in s:       # 自动归组：先全摘再挂新组
        for g in data["groups"]:
            g["auto_sources"] = [x for x in g.get("auto_sources", []) if x != sub_id]
        gid = s.get("auto_group")
        if gid:
            g = next((x for x in data["groups"] if x["id"] == gid), None)
            if g:
                g.setdefault("auto_sources", [])
                if sub_id not in g["auto_sources"]:
                    g["auto_sources"].append(sub_id)
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True, "subscription": sub, "url_changed": url_changed})


@app.route("/api/subs/<sub_id>", methods=["DELETE"])
@auth_required
def api_del_sub(sub_id):
    data = load_data()
    data["subscriptions"] = [s for s in data["subscriptions"] if s["id"] != sub_id]
    data["nodes"] = [n for n in data["nodes"] if n.get("source") != sub_id]
    for g in data["groups"]:
        g["auto_sources"] = [s for s in g.get("auto_sources", []) if s != sub_id]
    save_data(data)
    regen_outputs(data)
    return jsonify({"ok": True})


# ----------------------------------------------------------------- groups
@app.route("/api/groups", methods=["GET"])
@auth_required
def api_groups():
    data = load_data()
    out = []
    live_ids = {n["id"] for n in data["nodes"]}
    for index, g in enumerate(data["groups"]):
        nodes = group_member_nodes(data, g)
        sname = next((s["name"] for s in STRATEGIES if s["key"] == g["strategy"]),
                     g["strategy"])
        socks_enabled = g.get("socks5_enabled", True)
        socks_port = int(g.get("socks5_port") or (18080 + index))
        socks_listen = g.get("socks5_listen") or DEFAULT_SOCKS_LISTEN
        # 空分组不会生成监听器（build_config 里直接 continue），此时给出地址会误导
        socks_active = bool(socks_enabled and nodes)
        dangling = len([m for m in (g.get("members") or []) if m not in live_ids])
        out.append({**g, "node_count": len(nodes), "strategy_name": sname,
                    "socks5_enabled": socks_enabled,
                    "socks5_active": socks_active,
                    "member_dangling": dangling,
                    # 展示/复制用客户端实际能连的地址：通配绑定换成局域网 IP
                    "socks5_address": f"{_client_host(socks_listen)}:{socks_port}" if socks_active else "",
                    **_probe_counts(nodes)})
    return jsonify({"groups": out, "strategies": STRATEGIES})


@app.route("/api/groups", methods=["POST"])
@auth_required
def api_add_group():
    data = load_data()
    g = request.json or {}
    name = (g.get("name") or "").strip()
    if not name:
        return jsonify({"error": "请填写分组名称"}), 400
    try:
        requested_port = int(g.get("socks5_port") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "SOCKS5 端口必须是数字"}), 400
    if requested_port and not 1024 <= requested_port <= 65535:
        return jsonify({"error": "SOCKS5 端口范围应为 1024-65535"}), 400
    used_ports = {int(x.get("socks5_port") or 18080 + i)
                  for i, x in enumerate(data["groups"])
                  if x.get("socks5_enabled", True)}
    effective_port = requested_port or 18080 + len(data["groups"])
    if effective_port in used_ports:
        return jsonify({"error": f"SOCKS5 端口 {effective_port} 已被其他分组使用"}), 409
    group = {"id": secrets.token_hex(4), "name": name,
             "strategy": g.get("strategy") or "manual",
             "members": g.get("members") or [],
             "auto_sources": g.get("auto_sources") or [],
             "socks5_enabled": bool(g.get("socks5_enabled", True)),
             "socks5_listen": g.get("socks5_listen") or DEFAULT_SOCKS_LISTEN,
             "socks5_port": requested_port,
             "test_url": g.get("test_url") or "",
             "interval": int(g.get("interval") or 0),
             "tolerance": int(g.get("tolerance") or 50)}
    data["groups"].append(group)
    save_data(data)
    regen_outputs(data)
    refresh_mihomo_if_running(data)
    return jsonify({"ok": True, "group": group})


@app.route("/api/groups/<gid>", methods=["PUT"])
@auth_required
def api_update_group(gid):
    data = load_data()
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if not g:
        return jsonify({"error": "分组不存在"}), 404
    payload = request.json or {}
    for k in ("name", "strategy", "members", "auto_sources", "active_node",
              "socks5_enabled", "socks5_listen", "socks5_port", "test_url",
              "interval", "tolerance"):
        if k in payload:
            g[k] = payload[k]
    if "members" in payload:
        valid = {n.get("id") for n in data["nodes"]}
        g["members"] = list(dict.fromkeys(
            mid for mid in (payload.get("members") or []) if mid in valid))
    if "auto_sources" in payload:
        valid_sources = {s.get("id") for s in data["subscriptions"]}
        g["auto_sources"] = list(dict.fromkeys(
            sid for sid in (payload.get("auto_sources") or []) if sid in valid_sources))
    if "active_node" in payload:
        valid_node_ids = {n.get("id") for n in group_member_nodes(data, g)}
        g["active_node"] = payload.get("active_node") if payload.get("active_node") in valid_node_ids else ""
    if "socks5_port" in payload:
        try:
            port = int(payload.get("socks5_port") or 0)
        except (TypeError, ValueError):
            return jsonify({"error": "SOCKS5 端口必须是数字"}), 400
        if port and not 1024 <= port <= 65535:
            return jsonify({"error": "SOCKS5 端口范围应为 1024-65535"}), 400
    if g.get("socks5_enabled", True):
        group_index = next((i for i, x in enumerate(data["groups"])
                            if x["id"] == gid), 0)
        effective_port = int(g.get("socks5_port") or (18080 + group_index))
        used = {int(x.get("socks5_port") or (18080 + i))
                for i, x in enumerate(data["groups"])
                if x["id"] != gid and x.get("socks5_enabled", True)}
        if effective_port in used:
            return jsonify({"error": f"SOCKS5 端口 {effective_port} 已被其他分组使用"}), 409
    g["strategy"] = g.get("strategy") or "manual"
    save_data(data)
    regen_outputs(data)
    refresh_mihomo_if_running(data)
    return jsonify({"ok": True, "group": g})


@app.route("/api/groups/<gid>", methods=["DELETE"])
@auth_required
def api_del_group(gid):
    data = load_data()
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if g and g.get("is_default"):
        return jsonify({"error": "默认分组不可删除"}), 400
    data["groups"] = [x for x in data["groups"] if x["id"] != gid]
    save_data(data)
    regen_outputs(data)
    refresh_mihomo_if_running(data)
    return jsonify({"ok": True})


@app.route("/api/groups/<gid>/preview")
@auth_required
def api_group_preview(gid):
    data = load_data()
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if not g:
        return jsonify({"error": "分组不存在"}), 404
    nodes = group_member_nodes(data, g)
    ordered, note = apply_strategy(nodes, g)
    detail = [{"name": n["name"], "server": n["server"], "port": n["port"],
               "type": n.get("type"),
               "alive": n.get("alive"), "probe": n.get("probe"),
               "latency_ms": n.get("latency_ms")}
              for n in ordered]
    return jsonify({"ok": True, "note": note, "count": len(ordered),
                    "strategy": g.get("strategy"), "nodes": detail,
                    "uris": [make_ss_uri(n) for n in ordered]})


# ---------------------------------------------------------------- health
@app.route("/api/health/check", methods=["POST"])
@auth_required
def api_health_check():
    payload = request.json or {}
    ids = payload.get("node_ids") or None
    if payload.get("source_id"):
        ids = [n["id"] for n in load_data()["nodes"]
               if n.get("source") == payload["source_id"]]
    return jsonify({"ok": True, **run_health_check(ids)})


@app.route("/api/health/deep", methods=["POST"])
@auth_required
def api_health_deep():
    payload = request.json or {}
    ids = payload.get("node_ids") or None
    if payload.get("source_id"):
        ids = [n["id"] for n in load_data()["nodes"]
               if n.get("source") == payload["source_id"]]
    r = deep_check(ids)
    return jsonify(r), (200 if r.get("ok", True) else 500)


# ---------------------------------------------------------- mihomo gateway
@app.route("/api/mihomo/status")
@auth_required
def api_mihomo_status():
    return jsonify(_mihomo.status())


@app.route("/api/mihomo/config/preview")
@auth_required
def api_mihomo_config_preview():
    data = load_data()
    return jsonify({"config": build_mihomo_config(data), "status": _mihomo.status()})


@app.route("/api/mihomo/reload", methods=["POST"])
@auth_required
def api_mihomo_reload():
    data = load_data()
    config = build_mihomo_config(data)
    _mihomo.write_config(config)
    ok = _mihomo.start()
    return jsonify({"ok": ok, "status": _mihomo.status(),
                    "listeners": config.get("listeners", [])}), (200 if ok else 503)


@app.route("/api/mihomo/stop", methods=["POST"])
@auth_required
def api_mihomo_stop():
    _mihomo.stop()
    return jsonify({"ok": True, "status": _mihomo.status()})


@app.route("/api/surge/gateway.conf")
@auth_required
def api_surge_gateway_conf():
    return build_surge_gateway_conf(load_data()), 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=subweaver-mihomo.conf",
    }


@app.route("/api/settings", methods=["GET", "PUT"])
@auth_required
def api_settings():
    data = load_data()
    if request.method == "PUT":
        payload = request.json or {}
        for k in ("auto_health", "health_interval_minutes", "health_timeout",
                  "sr_final_group", "sr_udp_relay",
                  "sr_test_url", "sr_interval", "sr_tolerance",
                  "publish_base",
                  "require_login"):
            if k in payload:
                data["settings"][k] = payload[k]
        if "sr_dns" in payload:
            data["settings"]["sr_dns"] = norm_sr_dns(payload["sr_dns"])
        save_data(data)
        regen_outputs(data)
    return jsonify({"settings": data["settings"],
                    "has_password": bool(data.get("password_hash"))})


@app.route("/api/password", methods=["PUT"])
@auth_required
def api_password():
    """在页面里直接改管理密码（命令行 ./set-password.sh 是等价入口）"""
    password = str((request.json or {}).get("password") or "")
    if len(password) < 4:
        return jsonify({"error": "密码至少 4 位"}), 400
    data = load_data()
    data["password_hash"] = hash_password(password)
    save_data(data)
    session["auth"] = True
    session.permanent = True
    return jsonify({"ok": True})


# ---------------------------------------------------------------- rules
@app.route("/api/rules", methods=["GET", "PUT"])
@auth_required
def api_rules():
    data = load_data()
    if request.method == "PUT":
        payload = request.json or {}
        # 表单模式提交 rule_rows，文本模式提交 surge_rules；两者等价，统一落到 surge_rules
        if "rule_rows" in payload:
            data["surge_rules"] = rule_rows_to_text(payload.get("rule_rows"))
        elif "surge_rules" in payload:
            data["surge_rules"] = payload["surge_rules"]
        if "rules" in payload:                      # 兼容旧的 ACL 字段
            data["rules"] = payload["rules"]
        save_data(data)
        regen_outputs(data)
    text = data.get("surge_rules", "")
    return jsonify({"surge_rules": text,
                    "rule_rows": parse_rule_rows(text),
                    "rule_types": RULE_TYPE_LABEL,
                    "rule_actions": RULE_ACTIONS,
                    "rules": data.get("rules", ""),
                    "default_surge_rules": DEFAULT_SURGE_RULES})


# ---------------------------------------------------------------- publish
def _sr_import_link(url, remark):
    """Shadowrocket 一键导入链接（点按即导入订阅）"""
    b64 = base64.b64encode(url.encode()).decode()
    return (f"shadowrocket://add/sub://{b64}"
            f"?remark={urllib.parse.quote(remark or 'subscription')}")


def _surge_import_link(url):
    """Surge iOS/macOS 一键安装远程配置。"""
    return "surge:///install-config?url=" + urllib.parse.quote(url, safe="")


def _type_counts(nodes):
    counts = {}
    for n in nodes:
        t = n.get("type", "ss")
        counts[t] = counts.get(t, 0) + 1
    return counts


def _publish_payload():
    data = load_data()
    token = data["publish_token"]
    base = request.host_url.rstrip("/")
    groups = []
    for i, g in enumerate(data["groups"]):
        nodes = group_member_nodes(data, g)
        sub_url = f"{base}/sub/{token}/g/{g['id']}.txt"
        groups.append({
            "id": g["id"], "name": g["name"], "strategy": g["strategy"],
            "strategy_name": next((s["name"] for s in STRATEGIES
                                   if s["key"] == g["strategy"]), g["strategy"]),
            "node_count": len(nodes),
            "type_counts": _type_counts(nodes),
            **_probe_counts(nodes),
            "sub_url": sub_url,
            "raw_url": f"{base}/sub/{token}/g/{g['id']}.raw",
            "import_url": _sr_import_link(sub_url, g["name"]),
            "surge_url": f"{base}/sub/{token}/g/{g['id']}.surge.conf",
            "surge_import_url": _surge_import_link(
                f"{base}/sub/{token}/g/{g['id']}.surge.conf"),
            "slug": _publish_slug(g["name"], i),
        })
    st = data["settings"] or {}
    final_group = _resolve_final_group(data)
    return {"token": token, "node_count": len(data["nodes"]),
            "type_counts": _type_counts(data["nodes"]),
            "sub_url": f"{base}/sub/{token}/sub.txt",
            "raw_url": f"{base}/sub/{token}/sub.raw",
            "acl_url": f"{base}/sub/{token}/rules.acl",
            "conf_url": f"{base}/sub/{token}/shadowrocket.conf",
            "surge_gateway_url": f"{base}/surge/{token}/gateway.conf",
            "surge_gateway_import_url": _surge_import_link(
                f"{base}/surge/{token}/gateway.conf"),
            "import_url": _sr_import_link(f"{base}/sub/{token}/sub.txt", "全部节点"),
            "sr_final_group": final_group["id"] if final_group else "",
            "sr_udp_relay": bool(st.get("sr_udp_relay", True)),
            "sr_test_url": st.get("sr_test_url", "http://www.gstatic.com/generate_204"),
            "sr_interval": st.get("sr_interval", 300),
            "sr_tolerance": st.get("sr_tolerance", 50),
            "sr_dns": norm_sr_dns(st.get("sr_dns")),
            # 静态托管导出：清单供界面展示；publish_base 是用户填的托管地址前缀（可空）
            "publish_base": (st.get("publish_base") or "").strip(),
            "export_url": f"{base}/api/export.zip",
            "export_files": _export_items(data),
            "groups_url": f"{base}/sub/{token}/groups", "groups": groups}


@app.route("/api/publish", methods=["GET"])
@auth_required
def api_publish():
    return jsonify(_publish_payload())


@app.route("/api/publish/rotate", methods=["POST"])
@auth_required
def api_rotate_token():
    data = load_data()
    data["publish_token"] = secrets.token_urlsafe(16)
    save_data(data)
    regen_outputs(data)
    return jsonify(_publish_payload())


@app.route("/api/export.zip")
@auth_required
def api_export_zip():
    """下载静态托管发布包：解压后原样上传到任意静态托管即可用（含手机落地页）"""
    data = load_data()
    bundle = build_publish_bundle(data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in bundle.items():
            z.writestr(name, content)
    buf.seek(0)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name="shadowrocket-publish-%s.zip" % stamp)


# ------------------------------------------------------- public endpoints
def _check_token(token):
    data = load_data()
    if not secrets.compare_digest(token, data["publish_token"]):
        abort(404)
    return data


def _sub_response(uris, encode=True):
    text = "\n".join(uris) + ("\n" if uris else "")
    if encode:
        text = base64.b64encode(text.encode()).decode()
    return text, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/sub/<token>/sub.txt")
def public_sub(token):
    data = _check_token(token)
    return _sub_response([make_ss_uri(n) for n in data["nodes"]])


@app.route("/sub/<token>/sub.raw")
def public_sub_raw(token):
    data = _check_token(token)
    return _sub_response([make_ss_uri(n) for n in data["nodes"]], encode=False)


@app.route("/sub/<token>/g/<gid>.txt")
def public_group_sub(token, gid):
    data = _check_token(token)
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if not g:
        abort(404)
    uris, _, _ = build_uris_for_group(data, g)
    return _sub_response(uris)


@app.route("/sub/<token>/g/<gid>.raw")
def public_group_raw(token, gid):
    data = _check_token(token)
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if not g:
        abort(404)
    uris, _, _ = build_uris_for_group(data, g)
    return _sub_response(uris, encode=False)


@app.route("/sub/<token>/g/<gid>.surge.conf")
def public_group_surge_conf(token, gid):
    data = _check_token(token)
    g = next((x for x in data["groups"] if x["id"] == gid), None)
    if not g:
        abort(404)
    return build_surge_gateway_conf(data, g), 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"inline; filename={_publish_slug(g['name'], 0)}.surge.conf",
        "Cache-Control": "no-cache",
    }


@app.route("/surge/<token>/gateway.conf")
def public_surge_gateway_conf(token):
    data = _check_token(token)
    return build_surge_gateway_conf(data), 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "inline; filename=subweaver-gateway.conf",
        "Cache-Control": "no-cache",
    }


@app.route("/sub/<token>/groups")
def public_group_index(token):
    data = _check_token(token)
    base = request.host_url.rstrip("/")
    out = []
    for g in data["groups"]:
        nodes = group_member_nodes(data, g)
        out.append({"id": g["id"], "name": g["name"], "strategy": g["strategy"],
                    "nodes": len(nodes),
                    "sub_url": f"{base}/sub/{token}/g/{g['id']}.txt"})
    return jsonify({"groups": out, "total_nodes": len(data["nodes"])})


@app.route("/sub/<token>/rules.acl")
def public_rules(token):
    data = _check_token(token)
    return data["rules"], 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/sub/<token>/shadowrocket.conf")
def public_shadowrocket_conf(token):
    data = _check_token(token)
    return build_shadowrocket_conf(data), 200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=shadowrocket.conf",
    }


@app.route("/sub/<token>/subscription-profile")
def public_sr_profile(token):
    """给旧版订阅器的兼容别名：返回完整 Shadowrocket conf"""
    return public_shadowrocket_conf(token)


def _cli_set_password(argv):
    """命令行改密：python app.py --set-password [新密码]
    只替换 password_hash，节点 / 分组 / 订阅数据完全不受影响。"""
    if len(argv) > 1:
        new_password = argv[1]
        from_arg = True
    else:
        new_password = getpass.getpass("新管理密码: ")
        if new_password != getpass.getpass("再输入一次确认: "):
            print("✗ 两次输入不一致，未做任何修改")
            return 1
        from_arg = False
    if len(new_password) < 4:
        print("✗ 密码至少 4 位，未做任何修改")
        return 1
    data = load_data()
    data["password_hash"] = hash_password(new_password)
    save_data(data)
    print(f"✓ 管理密码已更新（节点 {len(data['nodes'])} 个 / 分组 {len(data['groups'])} 个 / "
          f"订阅源 {len(data['subscriptions'])} 个保持不变）")
    if from_arg:
        print("  提示：密码是明写在命令里的，建议执行 history -c 清一下 shell 历史")
    return 0


def _cli_set_auth(argv):
    """命令行开关登录：python app.py --auth off / --auth on"""
    if len(argv) < 2 or argv[1].lower() not in ("on", "off", "true", "false", "1", "0"):
        print("用法：python app.py --auth on|off")
        return 1
    enable = argv[1].lower() in ("on", "true", "1")
    data = load_data()
    data["settings"]["require_login"] = enable
    save_data(data)
    if enable and not data.get("password_hash"):
        print("✓ 已开启登录保护 —— 但当前还没有管理密码，")
        print("  下次打开页面会要求你先设置一个，或执行 ./set-password.sh 预设")
    else:
        print("✓ 已" + ("开启" if enable else "关闭") + "登录保护（无需重启，刷新页面即生效）")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--set-password", "set-password", "--password"):
        raise SystemExit(_cli_set_password(sys.argv[1:]))
    if len(sys.argv) > 1 and sys.argv[1] in ("--auth", "--login", "--require-login"):
        raise SystemExit(_cli_set_auth(sys.argv[1:]))
    port = int(os.environ.get("PORT", "5017"))
    # HOST 默认 127.0.0.1（仅本机）；设为 0.0.0.0 或本机局域网 IP 可让手机等设备访问
    host = os.environ.get("HOST", "127.0.0.1")
    _d = load_data()
    regen_outputs(_d)
    # mihomo 是本服务的数据面：Web 服务启动时同步生成并拉起，避免只启动
    # Flask 而页面显示的 SOCKS5 端口实际没有进程监听。
    try:
        _mihomo.write_config(build_mihomo_config(_d))
        if not _mihomo.start():
            print(f"[mihomo] 启动失败：{_mihomo.last_error}", flush=True)
    except Exception as exc:
        print(f"[mihomo] 配置/启动异常：{exc}", flush=True)
    threading.Thread(target=health_worker, daemon=True).start()
    print(f"\n  配置页面: http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}\n")
    app.run(host=host, port=port, debug=False, threaded=True)
