# -*- coding: utf-8 -*-
"""
多协议节点解析 / 生成模块
---------------------------------------------------------------
解析（订阅导入、链接导入）支持：
    ss / ssr / vmess / vless / trojan / hysteria / hysteria2(hy2)
    / tuic / anytls / socks5 / http / https
生成：
  1) 各协议标准 URI（用于 URI 订阅，Shadowrocket 原生支持）
  2) Shadowrocket 配置文件的 [Proxy] 行（Surge 兼容语法 + SR 扩展）

节点统一结构：
    {type, name, server, port, uri, ...协议字段}
"""
import base64
import json
import re
import urllib.parse

# Shadowrocket / Surge 支持的协议（用于展示与校验）
# 顺序对齐 Shadowrocket「选择类型」面板；Subscribe/Lua 非服务端节点，不在此列
TYPES = ["ss", "ssr", "vmess", "vless", "gost", "socks5", "socks5-tls",
         "http", "http2", "http3", "trojan", "hysteria", "hysteria2",
         "anytls", "tuic", "juicity", "ssh", "wireguard", "snell", "brook"]

TYPE_LABEL = {
    "ss": "Shadowsocks", "ssr": "ShadowsocksR", "vmess": "VMess",
    "vless": "VLESS", "trojan": "Trojan", "hysteria": "Hysteria",
    "hysteria2": "Hysteria2", "tuic": "TUIC", "anytls": "AnyTLS",
    "socks5": "Socks5", "socks5-tls": "Socks5 Over TLS", "http": "HTTP(S)",
    "http2": "HTTP2 (Naive)", "http3": "HTTP3 (Naive)", "juicity": "Juicity",
    "ssh": "SSH", "wireguard": "WireGuard", "snell": "Snell",
    "brook": "Brook", "gost": "Relay (GOST)",
}

# 订阅里能出现的 scheme → 协议
SCHEME_MAP = {
    "ss": "ss", "ssr": "ssr", "vmess": "vmess", "vless": "vless",
    "trojan": "trojan", "hysteria": "hysteria", "hysteria2": "hysteria2",
    "hy2": "hysteria2", "tuic": "tuic", "anytls": "anytls",
    "socks": "socks5", "socks5": "socks5",
    "juicity": "juicity", "snell": "snell", "brook": "brook",
    "ssh": "ssh", "wireguard": "wireguard", "gost": "gost",
    "http2": "http2", "http3": "http3",
    "naive+https": "http2", "naive+h3": "http3",
}


# ------------------------------------------------------------ base64 helpers
def _b64_pad(s):
    s = re.sub(r"[\s]+", "", s or "")
    return s + "=" * (-len(s) % 4)


def _b64d(s):
    """宽容 base64 解码：urlsafe / 标准 都试"""
    s = _b64_pad(s)
    if not s:
        return None
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s).decode("utf-8")
        except Exception:
            continue
    return None


def _b64e(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _qs(query):
    """query 字符串 → dict（同名取第一个，保留空值）"""
    if not query:
        return {}
    return {k: v[0] for k, v in
            urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _int(v, default=0):
    try:
        return int(re.sub(r"[^\d]", "", str(v)) or default)
    except Exception:
        return default


def _split_body(uri, scheme):
    """去掉 scheme:// 与 #fragment，返回 (body, name)"""
    body = uri[len(scheme) + 3:]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urllib.parse.unquote(frag).strip()
    return body, name


def _split_userinfo(body):
    """userinfo@rest → (userinfo, rest)；rest 里再拆掉 path/query"""
    if "@" in body:
        userinfo, rest = body.rsplit("@", 1)
    else:
        userinfo, rest = "", body
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    elif "/" in rest:
        rest, query = rest.split("/", 1)
    if "/" in rest:
        rest = rest.split("/", 1)[0]
    return urllib.parse.unquote(userinfo), rest.strip(), query


def _hostport(hp):
    """host:port / [v6]:port → (host, port)"""
    hp = (hp or "").strip()
    if hp.startswith("["):
        host, _, tail = hp.partition("]")
        return host.lstrip("["), _int(tail.lstrip(":"))
    if hp.count(":") == 1:
        host, port = hp.rsplit(":", 1)
        return host, _int(port)
    if hp.count(":") > 1:                       # 裸 IPv6，无端口
        return hp, 0
    return hp, 0


def _wrap_host(host):
    """IPv6 加方括号"""
    host = (host or "").strip()
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _strip_insecure(params):
    return bool(params.pop("allowInsecure", "") or params.pop("insecure", "")
                or params.pop("allow_insecure", ""))


# ------------------------------------------------------------------ ss / ssr
def _parse_ss(uri):
    body, name = _split_body(uri, "ss")
    plugin, plugin_opts = "", ""
    if "@" in body:                                     # SIP002
        userinfo, rest = body.split("@", 1)
        query = ""
        if "?" in rest:
            rest, query = rest.split("?", 1)
        hostpart = rest.rstrip("/")
        q = _qs(query)
        plugin = q.get("plugin", "")
        if ";" in plugin:                               # obfs-local;obfs=http;...
            plugin, _, po = plugin.partition(";")
            plugin_opts = po
        plugin_opts = q.get("plugin_opts", plugin_opts)
        if not plugin:
            plugin = q.get("plugin", "")
        decoded = _b64d(userinfo)
        if decoded and ":" in decoded:
            method, password = decoded.split(":", 1)
        else:                                           # 2022 明文 userinfo
            ui = urllib.parse.unquote(userinfo)
            if ":" not in ui:
                return None
            method, password = ui.split(":", 1)
    else:                                               # 传统整体 base64
        decoded = _b64d(body)
        if not decoded:
            return None
        m = re.match(r"^(?P<method>[^:]+):(?P<password>.+)@(?P<host>.+):(?P<port>\d+)$",
                     decoded)
        if not m:
            return None
        method, password = m.group("method"), m.group("password")
        hostpart = f"{m.group('host')}:{m.group('port')}"
    server, port = _hostport(hostpart)
    if not server or not port:
        return None
    return {"type": "ss", "name": name or f"{server}:{port}", "server": server,
            "port": port, "method": method.strip().lower(), "password": password,
            "plugin": plugin, "plugin_opts": plugin_opts}


def _parse_ssr(uri):
    body, name = _split_body(uri, "ssr")
    decoded = _b64d(body)
    if not decoded:
        return None
    main, _, query = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        return None
    server, port, protocol, method, obfs = parts[0], parts[1], parts[2], parts[3], parts[4]
    password = _b64d(":".join(parts[5:])) or ""
    q = _qs(query)
    remarks = _b64d(q.get("remarks", "")) or name
    obfs_param = _b64d(q.get("obfsparam", "")) or ""
    protocol_param = _b64d(q.get("protoparam", "")) or ""
    return {"type": "ssr", "name": remarks or f"{server}:{port}", "server": server,
            "port": _int(port), "method": method.lower(), "password": password,
            "protocol": protocol or "origin", "protocol_param": protocol_param,
            "obfs": obfs or "plain", "obfs_param": obfs_param}


# ------------------------------------------------------------ vmess / vless
def _parse_vmess(uri):
    body, name = _split_body(uri, "vmess")
    decoded = _b64d(body)
    cfg = None
    if decoded:
        try:
            cfg = json.loads(decoded)
        except Exception:
            cfg = None
    if isinstance(cfg, dict) and cfg.get("add"):         # v2rayN 标准 JSON
        net = (cfg.get("net") or "tcp").lower()
        node = {
            "type": "vmess", "name": cfg.get("ps") or name,
            "server": str(cfg.get("add", "")).strip("[]"),
            "port": _int(cfg.get("port")), "uuid": str(cfg.get("id", "")),
            "aid": _int(cfg.get("aid")), "method": cfg.get("scy") or "auto",
            "network": net, "tls": str(cfg.get("tls", "")).lower() in ("tls", "reality"),
            "sni": cfg.get("sni") or cfg.get("host") or "", "alpn": cfg.get("alpn") or "",
            "fp": cfg.get("fp") or "", "type_head": cfg.get("type") or "none",
            "ws_path": cfg.get("path") or "", "ws_host": cfg.get("host") or "",
            "grpc_service": "", "grpc_mode": "gun",
        }
        if net == "grpc":
            node["grpc_service"] = cfg.get("path") or ""
            node["grpc_mode"] = cfg.get("type") or "gun"
        elif net == "http":
            node["ws_path"], node["ws_host"] = cfg.get("path") or "/", cfg.get("host") or ""
        node["name"] = node["name"] or f"{node['server']}:{node['port']}"
        return node if node["server"] and node["port"] else None
    # URI 形式：vmess://uuid@host:port?...（部分客户端导出）
    userinfo, hp, query = _split_userinfo(_strip_scheme(uri))
    if not userinfo or "@" not in _strip_scheme(uri):
        return None
    server, port = _hostport(hp)
    q = _qs(query)
    insecure = _strip_insecure(q)
    net = (q.get("type") or "tcp").lower()
    return {"type": "vmess", "name": name or f"{server}:{port}", "server": server,
            "port": port, "uuid": urllib.parse.unquote(userinfo), "aid": 0,
            "method": q.get("encryption") or "auto", "network": net,
            "tls": (q.get("security") or "").lower() in ("tls", "reality"),
            "sni": q.get("sni", "") or q.get("peer", ""), "fp": q.get("fp", ""),
            "alpn": q.get("alpn", ""), "insecure": insecure,
            "ws_path": q.get("path", ""), "ws_host": q.get("host", ""),
            "grpc_service": q.get("serviceName", ""),
            "grpc_mode": q.get("mode", "gun")}


def _strip_scheme(uri):
    return uri.split("://", 1)[1] if "://" in uri else uri


def _parse_vless(uri):
    body, name = _split_body(uri, "vless")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port or not userinfo:
        return None
    q = _qs(query)
    insecure = _strip_insecure(q)
    net = (q.get("type") or "tcp").lower()
    sec = (q.get("security") or "").lower()
    node = {
        "type": "vless", "name": name or f"{server}:{port}", "server": server,
        "port": port, "uuid": urllib.parse.unquote(userinfo),
        "network": net, "tls": sec in ("tls", "reality", "xtls"),
        "reality": sec == "reality" or bool(q.get("pbk")),
        # SNI 取值优先级：sni= → peer=（Shadowrocket 的别名，REALITY 机场常用）→ ws 的 host=
        "sni": (q.get("sni", "") or q.get("peer", "")
                or (q.get("host", "") if net == "ws" else "")),
        "fp": q.get("fp", ""), "alpn": q.get("alpn", ""),
        "flow": q.get("flow", ""), "encryption": q.get("encryption", "none") or "none",
        "pbk": q.get("pbk", ""), "sid": q.get("sid", ""), "spx": q.get("spx", ""),
        "insecure": insecure,
        "ws_path": q.get("path", "") or "/", "ws_host": q.get("host", ""),
        "grpc_service": q.get("serviceName", ""), "grpc_mode": q.get("mode", "gun"),
        "header_type": q.get("headerType", ""),
    }
    if net in ("tcp", "raw", ""):
        node["ws_path"] = ""
    return node


# ------------------------------------------ trojan / hysteria / hysteria2
def _parse_trojan(uri):
    body, name = _split_body(uri, "trojan")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    node = {"type": "trojan", "name": name or f"{server}:{port}", "server": server,
            "port": port, "password": userinfo,
            "network": (q.get("type") or "tcp").lower(),
            "sni": q.get("sni", "") or q.get("peer", "") or server,
            "alpn": q.get("alpn", ""), "fp": q.get("fp", ""),
            "insecure": _strip_insecure(q),
            "ws_path": q.get("path", "") or "/", "ws_host": q.get("host", ""),
            "grpc_service": q.get("serviceName", ""), "grpc_mode": q.get("mode", "gun")}
    return node


def _parse_hysteria(uri):
    scheme = "hysteria" if uri.lower().startswith("hysteria://") else "hysteria2"
    body, name = _split_body(uri, scheme)
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    if scheme == "hysteria":
        return {"type": "hysteria", "name": name or f"{server}:{port}", "server": server,
                "port": port, "auth": q.get("auth") or userinfo,
                "up": q.get("upmbps", "0") or "0", "down": q.get("downmbps", "0") or "0",
                "sni": q.get("peer", "") or q.get("sni", ""),
                "obfs": q.get("obfsParam", ""), "alpn": q.get("alpn", ""),
                "ports": q.get("mport", ""), "insecure": _strip_insecure(q),
                "protocol": q.get("protocol", "udp")}
    # hysteria2
    return {"type": "hysteria2", "name": name or f"{server}:{port}", "server": server,
            "port": port,
            "password": urllib.parse.unquote(q.get("auth", "") or userinfo),
            "sni": q.get("sni", "") or q.get("peer", ""), "alpn": q.get("alpn", ""),
            "obfs": q.get("obfs", ""), "obfs_pw": q.get("obfs-password", ""),
            "ports": q.get("mport", ""), "pin": q.get("pinSHA256", ""),
            "insecure": _strip_insecure(q)}


# ------------------------------------------------------------------- tuic等
def _parse_tuic(uri):
    body, name = _split_body(uri, "tuic")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    if ":" in userinfo:
        uuid, password = userinfo.split(":", 1)
        token = ""
    else:
        uuid, password, token = "", "", userinfo
    return {"type": "tuic", "name": name or f"{server}:{port}", "server": server,
            "port": port, "uuid": uuid, "password": password, "token": token,
            "sni": q.get("sni", "") or q.get("peer", ""), "alpn": q.get("alpn", "h3") or "h3",
            "congestion": q.get("congestion_control", ""),
            "udp_mode": q.get("udp_relay_mode", ""),
            "insecure": _strip_insecure(q),
            "disable_sni": _bool(q.get("disable_sni", "")),
            "ports": q.get("mport", "")}


def _parse_anytls(uri):
    body, name = _split_body(uri, "anytls")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    return {"type": "anytls", "name": name or f"{server}:{port}", "server": server,
            "port": port, "password": userinfo, "sni": q.get("sni", "") or q.get("peer", ""),
            "alpn": q.get("alpn", ""), "fp": q.get("fp", ""),
            "insecure": _strip_insecure(q)}


def _parse_socks(uri):
    scheme = "socks5" if uri.lower().startswith("socks5://") else "socks"
    body, name = _split_body(uri, scheme)
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    username, password = "", ""
    if userinfo:
        decoded = _b64d(userinfo)
        if decoded and ":" in decoded:
            username, password = decoded.split(":", 1)
        elif ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
    # ?tls=1 → Socks5 Over TLS（Shadowrocket 的 Socks5 Over TLS 类型）
    if _bool(q.get("tls", "")):
        return {"type": "socks5-tls", "name": name or f"{server}:{port}",
                "server": server, "port": port, "username": username,
                "password": password, "sni": q.get("sni", "") or q.get("peer", ""),
                "insecure": _strip_insecure(q)}
    return {"type": "socks5", "name": name or f"{server}:{port}", "server": server,
            "port": port, "username": username, "password": password}


def _parse_http_node(uri):
    scheme = "https" if uri.lower().startswith("https://") else "http"
    body, name = _split_body(uri, scheme)
    userinfo, hp, _ = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    username, password = "", ""
    if userinfo and ":" in userinfo:
        username, password = userinfo.split(":", 1)
    return {"type": "http", "name": name or f"{server}:{port}", "server": server,
            "port": port, "username": username, "password": password,
            "tls": scheme == "https"}


# ----------------------------- Shadowrocket 扩展协议（链接格式非严格标准化，尽力解析）
def _parse_snell(uri):
    body, name = _split_body(uri, "snell")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    return {"type": "snell", "name": name or f"{server}:{port}", "server": server,
            "port": port, "password": urllib.parse.unquote(userinfo or q.get("psk", "")),
            "version": _int(q.get("version"), 4) or 4}


def _parse_brook(uri):
    body, name = _split_body(uri, "brook")
    userinfo, hp, _ = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    return {"type": "brook", "name": name or f"{server}:{port}", "server": server,
            "port": port, "password": urllib.parse.unquote(userinfo)}


def _parse_juicity(uri):
    body, name = _split_body(uri, "juicity")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    return {"type": "juicity", "name": name or f"{server}:{port}", "server": server,
            "port": port, "password": urllib.parse.unquote(userinfo),
            "sni": q.get("sni", "") or q.get("peer", ""),
            "insecure": _strip_insecure(q)}


def _parse_ssh(uri):
    body, name = _split_body(uri, "ssh")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port or not userinfo:
        return None
    username, password = "", ""
    if ":" in userinfo:
        username, password = userinfo.split(":", 1)
    else:
        username = userinfo
    return {"type": "ssh", "name": name or f"{server}:{port}", "server": server,
            "port": port, "username": urllib.parse.unquote(username),
            "password": urllib.parse.unquote(password)}


def _parse_gost(uri):
    body, name = _split_body(uri, "gost")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    username, password = "", ""
    if userinfo and ":" in userinfo:
        username, password = userinfo.split(":", 1)
    elif userinfo:
        username = userinfo
    return {"type": "gost", "name": name or f"{server}:{port}", "server": server,
            "port": port, "username": username, "password": password,
            "tls": _bool(q.get("tls", "")) or "tls" in (name or "").lower()}


def _parse_naive(uri):
    # naive+https / http2 / http3（NaiveProxy HTTP2 / HTTP3）
    scheme = uri.split("://", 1)[0].lower()
    body, name = _split_body(uri, scheme)
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port or ":" not in (userinfo or ""):
        return None
    username, password = userinfo.split(":", 1)
    q = _qs(query)
    return {"type": "http3" if scheme in ("http3", "naive+h3") else "http2",
            "name": name or f"{server}:{port}", "server": server, "port": port,
            "username": urllib.parse.unquote(username),
            "password": urllib.parse.unquote(password),
            "sni": q.get("sni", ""), "tls": True, "insecure": _strip_insecure(q)}


def _parse_wireguard(uri):
    body, name = _split_body(uri, "wireguard")
    userinfo, hp, query = _split_userinfo(body)
    server, port = _hostport(hp)
    if not server or not port:
        return None
    q = _qs(query)
    return {"type": "wireguard", "name": name or f"{server}:{port}", "server": server,
            "port": port,
            "wg_privkey": urllib.parse.unquote(q.get("private-key", "") or userinfo or ""),
            "wg_pubkey": urllib.parse.unquote(q.get("public-key", "")
                                              or q.get("peer-public-key", "")),
            "wg_psk": urllib.parse.unquote(q.get("preshared-key", "")
                                           or q.get("pre-shared-key", "")),
            "wg_allowed": q.get("allowed-ips", "") or "0.0.0.0/0",
            "wg_addr": q.get("address", "") or "172.16.0.2/32",
            "wg_dns": q.get("dns", ""), "wg_mtu": q.get("mtu", ""),
            "wg_keepalive": q.get("keepalive", "")}


# ------------------------------------------------------------------- dispatcher
_PARSERS = {
    "ss": _parse_ss, "ssr": _parse_ssr, "vmess": _parse_vmess, "vless": _parse_vless,
    "trojan": _parse_trojan, "hysteria": _parse_hysteria, "hysteria2": _parse_hysteria,
    "tuic": _parse_tuic, "anytls": _parse_anytls,
    "socks": _parse_socks, "socks5": _parse_socks, "http": _parse_http_node,
    "https": _parse_http_node,
    "snell": _parse_snell, "brook": _parse_brook, "juicity": _parse_juicity,
    "ssh": _parse_ssh, "gost": _parse_gost, "wireguard": _parse_wireguard,
    "http2": _parse_naive, "http3": _parse_naive,
    "naive+https": _parse_naive, "naive+h3": _parse_naive,
}


def parse_uri(uri, allow_http=True):
    """解析单条节点链接 → 节点 dict（失败返回 None）"""
    uri = (uri or "").strip()
    if "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in _PARSERS:
        return None
    if scheme in ("http", "https") and not allow_http:
        return None
    try:
        node = _PARSERS[scheme](uri)
    except Exception:
        return None
    if not node or not node.get("server") or not node.get("port"):
        return None
    node["uri"] = uri
    node.setdefault("name", f"{node['server']}:{node['port']}")
    return node


def decode_subscription_text(text):
    """订阅响应体 → 明文文本（自动处理 base64 包裹）"""
    content = text or ""
    if "://" not in content:
        content = urllib.parse.unquote(_b64d(content) or content)
    return content


def parse_lines(text, allow_http=True):
    """从订阅文本中提取所有可识别节点链接（自动兼容 base64 包裹）"""
    nodes = []
    for raw in decode_subscription_text(text).replace("\r", "").split("\n"):
        line = raw.strip()
        if "://" in line:
            n = parse_uri(line, allow_http=allow_http)
            if n:
                nodes.append(n)
    return nodes


# --------------------------------------------------------------- URI 生成
def make_uri(node):
    """生成节点链接。优先用原始 URI，保证零信息损失"""
    original = (node.get("uri") or "").strip()
    if original:
        return original
    return _rebuild_uri(node)


def _rebuild_uri(node):
    t = node.get("type", "ss")
    host = _wrap_host(node.get("server", ""))
    port = node.get("port", 0)
    name = node.get("name", "")
    tag = "#" + urllib.parse.quote(name, safe="") if name else ""
    q = []

    if t == "ss":
        method, pw = node.get("method", ""), node.get("password", "")
        if str(method).startswith("2022-"):
            userinfo = f"{urllib.parse.quote(method)}:{urllib.parse.quote(pw)}"
        else:
            userinfo = _b64e(f"{method}:{pw}")
        if node.get("plugin"):
            opts = node.get("plugin_opts") or ""
            plugin = node["plugin"] + (f";{opts}" if opts else "")
            q.append("plugin=" + urllib.parse.quote(plugin, safe=""))
        uri = f"ss://{userinfo}@{host}:{port}"
        return uri + ("?" + "&".join(q) if q else "") + tag

    if t == "ssr":
        main = ":".join([str(node.get("server", "")), str(port),
                         node.get("protocol", "origin"), node.get("method", "none"),
                         node.get("obfs", "plain"), _b64e(node.get("password", ""))])
        q.append("remarks=" + _b64e(name))
        if node.get("obfs_param"):
            q.append("obfsparam=" + _b64e(node["obfs_param"]))
        if node.get("protocol_param"):
            q.append("protoparam=" + _b64e(node["protocol_param"]))
        return "ssr://" + _b64e(f"{main}/?{'&'.join(q)}")

    if t == "vmess":
        net = node.get("network", "tcp")
        cfg = {"v": "2", "ps": name, "add": node.get("server", ""), "port": str(port),
               "id": node.get("uuid", ""), "aid": str(node.get("aid", 0)),
               "scy": node.get("method", "auto"), "net": net,
               "type": node.get("type_head", "none"),
               "host": node.get("ws_host", ""), "path": node.get("ws_path", ""),
               "tls": "tls" if node.get("tls") else "", "sni": node.get("sni", ""),
               "alpn": node.get("alpn", ""), "fp": node.get("fp", "")}
        if net == "grpc":
            cfg["path"] = node.get("grpc_service", "")
            cfg["type"] = node.get("grpc_mode", "gun")
        return "vmess://" + _b64e(json.dumps(cfg, ensure_ascii=False))

    if t == "vless":
        if node.get("network"):
            q.append("type=" + node["network"])
        if node.get("encryption"):
            q.append("encryption=" + node["encryption"])
        if node.get("flow"):
            q.append("flow=" + node["flow"])
        if node.get("tls") or node.get("reality"):
            q.append("security=" + ("reality" if node.get("reality") or node.get("pbk") else "tls"))
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("fp"):
            q.append("fp=" + node["fp"])
        if node.get("alpn"):
            q.append("alpn=" + urllib.parse.quote(str(node["alpn"]), safe=""))
        if node.get("pbk"):
            q.append("pbk=" + urllib.parse.quote(str(node["pbk"]), safe=""))
        if node.get("sid"):
            q.append("sid=" + urllib.parse.quote(str(node["sid"]), safe=""))
        if node.get("insecure"):
            q.append("allowInsecure=1")
        net = node.get("network", "")
        if net == "ws":
            q.append("path=" + urllib.parse.quote(node.get("ws_path") or "/", safe=""))
            if node.get("ws_host"):
                q.append("host=" + urllib.parse.quote(str(node["ws_host"]), safe=""))
        elif net in ("grpc", "gun"):
            if node.get("grpc_service"):
                q.append("serviceName=" + urllib.parse.quote(str(node["grpc_service"]), safe=""))
            if node.get("grpc_mode"):
                q.append("mode=" + str(node["grpc_mode"]))
        return (f"vless://{urllib.parse.quote(str(node.get('uuid','')), safe='')}"
                f"@{host}:{port}" + ("?" + "&".join(q) if q else "") + tag)

    if t == "trojan":
        q.append("sni=" + urllib.parse.quote(str(node.get("sni") or node.get("server", "")), safe=""))
        if node.get("network") and node["network"] != "tcp":
            q.append("type=" + node["network"])
        if node.get("ws_path"):
            q.append("path=" + urllib.parse.quote(str(node["ws_path"]), safe=""))
        if node.get("ws_host"):
            q.append("host=" + urllib.parse.quote(str(node["ws_host"]), safe=""))
        if node.get("alpn"):
            q.append("alpn=" + urllib.parse.quote(str(node["alpn"]), safe=""))
        if node.get("fp"):
            q.append("fp=" + node["fp"])
        if node.get("insecure"):
            q.append("allowInsecure=1")
        return (f"trojan://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}?" + "&".join(q) + tag)

    if t == "hysteria":
        q += ["auth=" + urllib.parse.quote(str(node.get("auth", "")), safe=""),
              "upmbps=" + str(node.get("up", 0)), "downmbps=" + str(node.get("down", 0))]
        if node.get("sni"):
            q.append("peer=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("obfs"):
            q.append("obfsParam=" + urllib.parse.quote(str(node["obfs"]), safe=""))
        if node.get("insecure"):
            q.append("insecure=1")
        return f"hysteria://{host}:{port}?" + "&".join(q) + tag

    if t == "hysteria2":
        q = []
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("alpn"):
            q.append("alpn=" + urllib.parse.quote(str(node["alpn"]), safe=""))
        if node.get("obfs"):
            q.append("obfs=" + node["obfs"])
            if node.get("obfs_pw"):
                q.append("obfs-password=" + urllib.parse.quote(str(node["obfs_pw"]), safe=""))
        if node.get("insecure"):
            q.append("insecure=1")
        if node.get("ports"):
            q.append("mport=" + str(node["ports"]))
        return (f"hysteria2://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}" + ("?" + "&".join(q) if q else "") + tag)

    if t == "tuic":
        q = []
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        q.append("alpn=" + str(node.get("alpn") or "h3"))
        if node.get("congestion"):
            q.append("congestion_control=" + node["congestion"])
        if node.get("udp_mode"):
            q.append("udp_relay_mode=" + node["udp_mode"])
        if node.get("insecure"):
            q.append("allow_insecure=1")
        auth = (f"{urllib.parse.quote(str(node.get('uuid','')), safe='')}:"
                f"{urllib.parse.quote(str(node.get('password','')), safe='')}"
                if node.get("uuid") else str(node.get("token", "")))
        return f"tuic://{auth}@{host}:{port}?" + "&".join(q) + tag

    if t == "anytls":
        q = []
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("alpn"):
            q.append("alpn=" + urllib.parse.quote(str(node["alpn"]), safe=""))
        if node.get("fp"):
            q.append("fp=" + node["fp"])
        if node.get("insecure"):
            q.append("insecure=1")
        return (f"anytls://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}" + ("?" + "&".join(q) if q else "") + tag)

    if t == "socks5":
        auth = ""
        if node.get("username"):
            auth = _b64e(f"{node['username']}:{node.get('password','')}") + "@"
        return f"socks5://{auth}{host}:{port}{tag}"

    if t == "http":
        scheme = "https" if node.get("tls") else "http"
        auth = ""
        if node.get("username"):
            auth = (f"{urllib.parse.quote(str(node['username']), safe='')}:"
                    f"{urllib.parse.quote(str(node.get('password','')), safe='')}@")
        return f"{scheme}://{auth}{host}:{port}{tag}"

    if t == "socks5-tls":
        auth = ""
        if node.get("username"):
            auth = _b64e(f"{node['username']}:{node.get('password','')}") + "@"
        q = ["tls=1"]
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("insecure"):
            q.append("insecure=1")
        return f"socks5://{auth}{host}:{port}?" + "&".join(q) + tag

    if t == "http2" or t == "http3":
        auth = ""
        if node.get("username"):
            auth = (f"{urllib.parse.quote(str(node['username']), safe='')}:"
                    f"{urllib.parse.quote(str(node.get('password','')), safe='')}@")
        q = []
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("insecure"):
            q.append("insecure=1")
        return (f"{t}://{auth}{host}:{port}"
                + ("?" + "&".join(q) if q else "") + tag)

    if t == "snell":
        q = []
        if node.get("version"):
            q.append(f"version={node['version']}")
        return (f"snell://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}" + ("?" + "&".join(q) if q else "") + tag)

    if t == "brook":
        return (f"brook://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}{tag}")

    if t == "juicity":
        q = []
        if node.get("sni"):
            q.append("sni=" + urllib.parse.quote(str(node["sni"]), safe=""))
        if node.get("insecure"):
            q.append("insecure=1")
        return (f"juicity://{urllib.parse.quote(str(node.get('password','')), safe='')}"
                f"@{host}:{port}" + ("?" + "&".join(q) if q else "") + tag)

    if t == "ssh":
        auth = ""
        if node.get("username"):
            auth = urllib.parse.quote(str(node["username"]), safe="")
            if node.get("password"):
                auth += ":" + urllib.parse.quote(str(node["password"]), safe="")
            auth += "@"
        return f"ssh://{auth}{host}:{port}{tag}"

    if t == "gost":
        auth = ""
        if node.get("username"):
            auth = (f"{urllib.parse.quote(str(node['username']), safe='')}:"
                    f"{urllib.parse.quote(str(node.get('password','')), safe='')}@")
        q = []
        if node.get("tls"):
            q.append("tls=1")
        return (f"gost://{auth}{host}:{port}"
                + ("?" + "&".join(q) if q else "") + tag)

    if t == "wireguard":
        q = []
        for k, src in (("private-key", "wg_privkey"), ("public-key", "wg_pubkey"),
                       ("preshared-key", "wg_psk"), ("address", "wg_addr"),
                       ("allowed-ips", "wg_allowed"), ("dns", "wg_dns"),
                       ("mtu", "wg_mtu"), ("keepalive", "wg_keepalive")):
            if node.get(src):
                q.append(f"{k}=" + urllib.parse.quote(str(node[src]), safe=""))
        return (f"wireguard://{host}:{port}"
                + ("?" + "&".join(q) if q else "") + tag)

    return ""


# --------------------------------------------------- Shadowrocket 配置行生成
def _q_str(v):
    """配置值里的引号转义"""
    return str(v).replace('"', "'")


def conf_line(node, name, udp=True):
    """生成 Shadowrocket 配置文件中 [Proxy] 段的一行（Surge 兼容语法）"""
    t = node.get("type", "ss")
    host, port = node.get("server", ""), node.get("port", 0)
    parts = []
    udp_tail = ["udp-relay=true"] if udp and t not in ("http",) else []

    def tls_params(node):
        out = []
        if node.get("tls") or node.get("reality") or t in ("tuic",):
            out.append("tls=true")
        if node.get("sni"):
            out.append(f"sni={_q_str(node['sni'])}")
        if node.get("alpn"):
            out.append(f"alpn={_q_str(node['alpn'])}")
        if node.get("reality") or node.get("pbk"):
            if node.get("pbk"):
                out.append(f"reality-public-key={_q_str(node['pbk'])}")
            if node.get("sid") is not None and node.get("pbk"):
                out.append(f"reality-short-id={_q_str(node.get('sid', ''))}")
        if node.get("fp"):
            out.append(f"client-fingerprint={_q_str(node['fp'])}")
        elif node.get("reality") or node.get("pbk"):
            out.append("client-fingerprint=chrome")
        if node.get("insecure"):
            out.append("skip-cert-verify=true")
        return out

    def transport_params(node):
        net = (node.get("network") or "").lower()
        out = []
        if net == "ws":
            out.append("ws=true")
            out.append(f"ws-path={_q_str(node.get('ws_path') or '/')}")
            if node.get("ws_host"):
                out.append(f'ws-headers=Host:"{_q_str(node["ws_host"])}"')
        elif net in ("grpc", "gun"):
            out.append("transport=grpc")
            if node.get("grpc_service"):
                out.append(f"grpc-service-name={_q_str(node['grpc_service'])}")
        elif net == "h2":
            out.append("transport=h2")
            if node.get("ws_path"):
                out.append(f"h2-path={_q_str(node['ws_path'])}")
        return out

    if t == "ss":
        parts = [f"{name} = ss, {host}, {port}",
                 f"encrypt-method={node.get('method', 'none')}",
                 f'password="{_q_str(node.get("password", ""))}"']
        plugin = (node.get("plugin") or "")
        if "obfs" in plugin:
            kv = dict(p.split("=", 1) for p in (node.get("plugin_opts") or "").split(";")
                      if "=" in p)
            if kv.get("obfs"):
                parts.append(f"obfs={kv['obfs']}")
            if kv.get("obfs-host"):
                parts.append(f"obfs-host={kv['obfs-host']}")
        parts += udp_tail

    elif t == "ssr":
        parts = [f"{name} = ssr, {host}, {port}",
                 f"encrypt-method={node.get('method', 'none')}",
                 f'password="{_q_str(node.get("password", ""))}"',
                 f"protocol={node.get('protocol', 'origin')}"]
        if node.get("protocol_param"):
            parts.append(f'protocol-param="{_q_str(node["protocol_param"])}"')
        parts.append(f"obfs={node.get('obfs', 'plain')}")
        if node.get("obfs_param"):
            parts.append(f'obfs-param="{_q_str(node["obfs_param"])}"')
        parts += udp_tail

    elif t == "vmess":
        parts = [f"{name} = vmess, {host}, {port}",
                 f"username={node.get('uuid', '')}",
                 "vmess-aead=" + ("true" if _int(node.get("aid")) == 0 else "false")]
        parts += transport_params(node) + tls_params(node) + udp_tail

    elif t == "vless":
        parts = [f"{name} = vless, {host}, {port}",
                 f"username={node.get('uuid', '')}",
                 f"encryption={node.get('encryption') or 'none'}"]
        if node.get("flow"):
            parts.append(f"flow={node['flow']}")
        parts += transport_params(node) + tls_params(node) + udp_tail

    elif t == "trojan":
        parts = [f"{name} = trojan, {host}, {port}",
                 f'password="{_q_str(node.get("password", ""))}"']
        parts += transport_params(node) + tls_params(node) + udp_tail

    elif t == "hysteria2":
        parts = [f"{name} = hysteria2, {host}, {port}",
                 f'password="{_q_str(node.get("password", ""))}"']
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("alpn"):
            parts.append(f"alpn={_q_str(node['alpn'])}")
        if node.get("obfs"):
            parts.append(f"obfs={node['obfs']}")
            if node.get("obfs_pw"):
                parts.append(f'obfs-password="{_q_str(node["obfs_pw"])}"')
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        if node.get("ports"):
            parts.append(f'port-hopping="{_q_str(node["ports"]).replace(",", ";")}"')
        parts += udp_tail

    elif t == "hysteria":
        parts = [f"{name} = hysteria, {host}, {port}",
                 f'auth-str="{_q_str(node.get("auth", ""))}"',
                 f"up={_int(node.get('up')) or 100}", f"down={_int(node.get('down')) or 100}"]
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("alpn"):
            parts.append(f"alpn={_q_str(node['alpn'])}")
        if node.get("obfs"):
            parts.append(f"obfs={node['obfs']}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        parts += udp_tail

    elif t == "tuic":
        kind = "tuic" if node.get("token") else "tuic-v5"
        parts = [f"{name} = {kind}, {host}, {port}"]
        if node.get("uuid"):
            parts.append(f"uuid={node['uuid']}")
        if node.get("password"):
            parts.append(f'password="{_q_str(node["password"])}"')
        if node.get("token"):
            parts.append(f"token={node['token']}")
        parts.append(f"alpn={node.get('alpn') or 'h3'}")
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("congestion"):
            parts.append(f"congestion-controller={node['congestion']}")
        if node.get("udp_mode"):
            parts.append(f"udp-relay-mode={node['udp_mode']}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        parts += udp_tail

    elif t == "anytls":
        parts = [f"{name} = anytls, {host}, {port}",
                 f'password="{_q_str(node.get("password", ""))}"']
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("alpn"):
            parts.append(f"alpn={_q_str(node['alpn'])}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        parts += udp_tail

    elif t == "socks5":
        parts = [f"{name} = socks5, {host}, {port}"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
            parts.append(f'password="{_q_str(node.get("password", ""))}"')
        parts += udp_tail

    elif t == "socks5-tls":
        parts = [f"{name} = socks5-tls, {host}, {port}"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
            parts.append(f'password="{_q_str(node.get("password", ""))}"')
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        parts += udp_tail

    elif t == "http2" or t == "http3":
        parts = [f"{name} = {t}, {host}, {port}", "tls=true"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
            parts.append(f'password="{_q_str(node.get("password", ""))}"')
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")

    elif t == "snell":
        parts = [f"{name} = snell, {host}, {port}",
                 f'psk="{_q_str(node.get("password", ""))}"',
                 f"version={node.get('version') or 4}"] + udp_tail

    elif t == "ssh":
        parts = [f"{name} = ssh, {host}, {port}"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
        if node.get("password"):
            parts.append(f'password="{_q_str(node["password"])}"')
        if node.get("privkey"):
            parts.append(f'private-key="{_q_str(node["privkey"])}"')
        if node.get("key_pass"):
            parts.append(f'private-key-passphrase="{_q_str(node["key_pass"])}"')

    elif t == "brook":
        parts = [f"{name} = brook, {host}, {port}",
                 f'password="{_q_str(node.get("password", ""))}"'] + udp_tail

    elif t == "juicity":
        parts = [f"{name} = juicity, {host}, {port}",
                 f'password="{_q_str(node.get("password", ""))}"']
        if node.get("sni"):
            parts.append(f"sni={_q_str(node['sni'])}")
        if node.get("insecure"):
            parts.append("skip-cert-verify=true")
        parts += udp_tail

    elif t == "gost":
        kind = "relay-tls" if node.get("tls") else "relay"
        parts = [f"{name} = {kind}, {host}, {port}"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
            parts.append(f'password="{_q_str(node.get("password", ""))}"')

    elif t == "wireguard":
        sec = "wgin-" + (node.get("id") or _b64e(name)[:6] or "x")
        parts = [f"{name} = wireguard, section-name={sec}"]

    elif t == "http":
        kind = "https" if node.get("tls") else "http"
        parts = [f"{name} = {kind}, {host}, {port}"]
        if node.get("username"):
            parts.append(f'username="{_q_str(node["username"])}"')
            parts.append(f'password="{_q_str(node.get("password", ""))}"')

    else:                                               # 兜底：无法识别时按 ss 处理
        parts = [f"{name} = ss, {host}, {port}",
                 f"encrypt-method={node.get('method', 'none')}",
                 f'password="{_q_str(node.get("password", ""))}"'] + udp_tail

    return ", ".join(p for p in parts if p)


# ------------------------------------------------------ Clash YAML 兜底解析
# 部分机场在识别到 Clash 客户端 UA 时只下发 YAML，这里做兼容解析
def clash_proxy_to_node(p):
    """Clash / Clash.Meta 的单个 proxy 字典 → 统一节点结构"""
    if not isinstance(p, dict):
        return None
    t = str(p.get("type") or "").lower()
    t = {"shadowsocks": "ss", "hy2": "hysteria2", "socks": "socks5",
         "https": "http", "trojan-go": "trojan"}.get(t, t)
    if t not in TYPES:
        return None
    server, port = p.get("server"), p.get("port")
    if not server or not port:
        return None
    node = {"type": t, "name": p.get("name") or f"{server}:{port}",
            "server": str(server).strip("[]"), "port": _int(port),
            "uri": "", "insecure": bool(p.get("skip-cert-verify"))}
    sni = p.get("servername") or p.get("sni") or p.get("peer") or ""
    if sni:
        node["sni"] = str(sni)

    if t == "ss":
        node.update({"method": p.get("cipher", "none"), "password": p.get("password", ""),
                     "plugin": p.get("plugin") or ""})
        po = p.get("plugin-opts") or {}
        if po:
            if po.get("mode"):
                node["plugin"] = node["plugin"] or "obfs"
                opts = [f"obfs={po['mode']}"]
                if po.get("host"):
                    opts.append(f"obfs-host={po['host']}")
                node["plugin_opts"] = ";".join(opts)
    elif t == "ssr":
        node.update({"method": p.get("cipher", "none"), "password": p.get("password", ""),
                     "protocol": p.get("protocol", "origin"),
                     "protocol_param": p.get("protocol-param", ""),
                     "obfs": p.get("obfs", "plain"),
                     "obfs_param": p.get("obfs-param", "")})
    elif t == "vmess":
        node.update({"uuid": p.get("uuid", ""), "aid": _int(p.get("alterId")),
                     "method": p.get("cipher", "auto"),
                     "tls": bool(p.get("tls")), "network": (p.get("network") or "tcp").lower()})
        node.update(_clash_transport(p))
    elif t == "vless":
        ro = p.get("reality-opts") or {}
        node.update({"uuid": p.get("uuid", ""), "flow": p.get("flow", ""),
                     "encryption": "none", "tls": True,
                     "fp": p.get("client-fingerprint", ""),
                     "network": (p.get("network") or "tcp").lower(),
                     "reality": bool(ro), "pbk": ro.get("public-key", ""),
                     "sid": ro.get("short-id", "")})
        node.update(_clash_transport(p))
    elif t == "trojan":
        node.update({"password": p.get("password", ""),
                     "network": (p.get("network") or "tcp").lower()})
        node.update(_clash_transport(p))
    elif t == "hysteria2":
        node.update({"password": p.get("password", ""), "obfs": p.get("obfs", ""),
                     "obfs_pw": p.get("obfs-password", ""),
                     "up": p.get("up", ""), "down": p.get("down", ""),
                     "ports": p.get("ports", ""), "tls": True})
    elif t == "hysteria":
        node.update({"auth": p.get("auth-str") or p.get("auth", ""),
                     "up": p.get("up", ""), "down": p.get("down", ""),
                     "obfs": p.get("obfs", "")})
    elif t == "tuic":
        node.update({"uuid": p.get("uuid", ""), "password": p.get("password", ""),
                     "token": p.get("token", ""),
                     "congestion": p.get("congestion-controller", ""),
                     "udp_mode": p.get("udp-relay-mode", ""), "tls": True})
        alpn = p.get("alpn")
        node["alpn"] = ",".join(alpn) if isinstance(alpn, list) else (alpn or "h3")
    elif t == "anytls":
        node.update({"password": p.get("password", "")})
    elif t == "snell":
        node.update({"password": p.get("psk") or p.get("password", ""),
                     "version": _int(p.get("version"), 4) or 4})
    elif t == "ssh":
        node.update({"username": p.get("username", ""), "password": p.get("password", ""),
                     "privkey": p.get("private-key", ""),
                     "key_pass": p.get("private-key-passphrase", "")})
    elif t == "brook":
        node.update({"password": p.get("password", "")})
    elif t == "juicity":
        node.update({"password": p.get("password", ""),
                     "insecure": bool(p.get("skip-cert-verify"))})
    elif t == "wireguard":
        node.update({"wg_privkey": p.get("private-key", ""),
                     "wg_pubkey": p.get("public-key", ""),
                     "wg_psk": p.get("pre-shared-key", ""),
                     "wg_addr": str(p.get("ip") or "172.16.0.2/32"),
                     "wg_allowed": ",".join(p.get("allowed-ips") or []) or "0.0.0.0/0",
                     "wg_mtu": p.get("mtu", "")})
    elif t in ("socks5", "http"):
        if t == "socks5" and p.get("tls"):
            node["type"] = "socks5-tls"
            if sni:
                node["sni"] = str(sni)
        node.update({"username": p.get("username", ""), "password": p.get("password", ""),
                     "tls": bool(p.get("tls"))})
    return node


def _clash_transport(p):
    out = {}
    net = (p.get("network") or "tcp").lower()
    if net == "ws":
        ws = p.get("ws-opts") or {}
        out["ws_path"] = ws.get("path") or "/"
        out["ws_host"] = (ws.get("headers") or {}).get("Host", "") or ""
    elif net == "grpc":
        g = p.get("grpc-opts") or {}
        out["grpc_service"] = g.get("grpc-service-name") or ""
        out["grpc_mode"] = g.get("grpc-mode") or "gun"
    elif net == "h2":
        h2 = p.get("h2-opts") or {}
        out["ws_path"] = h2.get("path") or "/"
        host = h2.get("host")
        out["ws_host"] = (host[0] if isinstance(host, list) and host else host) or ""
    return out


def parse_clash_yaml(text):
    """解析 Clash 风格 YAML 的 proxies 列表（解析失败返回 []）"""
    try:
        import yaml
    except Exception:
        return []
    try:
        doc = yaml.safe_load(text or "")
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for p in (doc.get("proxies") or []):
        n = clash_proxy_to_node(p)
        if n:
            out.append(n)
    return out
