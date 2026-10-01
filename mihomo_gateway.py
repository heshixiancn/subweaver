"""Persistent mihomo gateway used by the Web UI.

The application remains the source of truth.  This module only translates the
current node/group model into a mihomo config and owns the optional process.
JSON is valid YAML, so no YAML dependency is required to write the config.
"""
import json
import os
import secrets
import socket
import subprocess
import threading


STRATEGY_TYPES = {
    "manual": "select",
    "latency": "url-test",
    "round_robin": "load-balance",
    "random": "load-balance",
    "failover": "fallback",
}


def _safe_name(value, used):
    base = " ".join(str(value or "Node").replace("\n", " ").split()) or "Node"
    name, index = base, 2
    while name in used:
        name = f"{base} #{index}"
        index += 1
    used.add(name)
    return name


def build_config(data, node_to_mihomo, config_dir, api_port=9090):
    settings = data.get("settings") or {}
    used = set()
    proxies = []
    node_names = {}
    for node in data.get("nodes", []):
        proxy = node_to_mihomo(node)
        if not proxy:
            continue
        name = _safe_name(node.get("name"), used)
        proxy["name"] = name
        proxies.append(proxy)
        node_names[node.get("id")] = name

    groups = []
    listeners = []
    for index, group in enumerate(data.get("groups", [])):
        members = []
        # group_member_nodes is resolved by the caller and stored temporarily
        # in _mihomo_members to keep this module independent of app.py.
        for node in group.get("_mihomo_members", []):
            if node.get("id") in node_names:
                members.append(node_names[node["id"]])
        if not members:
            continue
        group_name = _safe_name(group.get("name"), used)
        kind = STRATEGY_TYPES.get(group.get("strategy"), "select")
        item = {"name": group_name, "type": kind, "proxies": members}
        if kind == "select" and group.get("active_node"):
            selected_id = group.get("active_node")
            selected_name = node_names.get(selected_id)
            if selected_name in members:
                item["selected"] = selected_name
        if kind != "select":
            item.update({
                "url": group.get("test_url") or settings.get("mihomo_test_url") or "http://www.gstatic.com/generate_204",
                "interval": int(group.get("interval") or settings.get("mihomo_interval") or 300),
            })
        if kind == "url-test":
            item["tolerance"] = int(group.get("tolerance") or 50)
        if kind == "load-balance":
            item["strategy"] = "round-robin"
        groups.append(item)
        if group.get("socks5_enabled", True):
            port = int(group.get("socks5_port") or (18080 + index))
            listeners.append({
                "name": f"subweaver-{group['id']}", "type": "socks",
                "listen": group.get("socks5_listen") or settings.get("mihomo_socks_listen") or "127.0.0.1",
                "port": port, "proxy": group_name,
            })

    secret = settings.get("mihomo_api_secret") or secrets.token_urlsafe(24)
    return {
        "mixed-port": int(settings.get("mihomo_mixed_port") or 0),
        "allow-lan": False,
        "mode": "rule",
        "log-level": settings.get("mihomo_log_level") or "info",
        "ipv6": False,
        "proxies": proxies,
        "proxy-groups": groups,
        "listeners": listeners,
        "rules": ["MATCH,DIRECT"],
        "external-controller": f"127.0.0.1:{int(api_port)}",
        "secret": secret,
        "profile": {"store-selected": True},
    }


class MihomoManager:
    def __init__(self, binary, run_dir):
        self.binary = binary
        self.run_dir = run_dir
        self.config_path = os.path.join(run_dir, "config.yaml")
        self.log_path = os.path.join(run_dir, "mihomo.log")
        self._lock = threading.RLock()
        self._proc = None
        self.last_error = ""

    def status(self):
        with self._lock:
            running = bool(self._proc and self._proc.poll() is None)
            return {"running": running, "pid": self._proc.pid if running else None,
                    "binary": self.binary, "config": self.config_path,
                    "last_error": self.last_error}

    def write_config(self, config):
        os.makedirs(self.run_dir, exist_ok=True)
        tmp = self.config_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(tmp, self.config_path)

    def stop(self):
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._proc = None

    def start(self):
        with self._lock:
            self.stop()
            if not os.path.isfile(self.binary) or not os.access(self.binary, os.X_OK):
                self.last_error = f"mihomo binary unavailable: {self.binary}"
                return False
            try:
                log = open(self.log_path, "a", encoding="utf-8")
                self._proc = subprocess.Popen(
                    [self.binary, "-f", self.config_path, "-d", self.run_dir],
                    stdout=log, stderr=log)
                log.close()
                self.last_error = ""
                return True
            except OSError as exc:
                self.last_error = str(exc)
                self._proc = None
                return False
