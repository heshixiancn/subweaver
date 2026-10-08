"""Persistent mihomo gateway used by the Web UI.

The application remains the source of truth.  This module only translates the
current node/group model into a mihomo config and owns the optional process.
JSON is valid YAML, so no YAML dependency is required to write the config.
"""
import ipaddress
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

# 分组 SOCKS5 的兜底监听地址。容器里必须用 SS_SOCKS_LISTEN=0.0.0.0，
# 否则 Docker 端口转发（打到容器 IP）连不上绑在回环上的 listener。
DEFAULT_LISTEN = os.environ.get("SS_SOCKS_LISTEN") or "127.0.0.1"


def _exposes_lan(host):
    """绑定地址是否会暴露到局域网。

    只有回环地址（127.x.x.x / ::1 / localhost）和空值算「仅本机」。
    0.0.0.0、:: 或任何具体网卡地址都算对外——包括无法解析的写法，从严。
    """
    host = str(host or "").strip()
    if not host or host == "localhost":
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not ip.is_loopback


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
                "listen": group.get("socks5_listen") or settings.get("mihomo_socks_listen") or DEFAULT_LISTEN,
                "port": port, "proxy": group_name,
            })

    secret = settings.get("mihomo_api_secret") or secrets.token_urlsafe(24)
    # 只要有任一 listener 绑到非回环地址，就必须打开 allow-lan：
    # allow-lan=false 时 mihomo 会把入站限制在 127.0.0.1，绑 0.0.0.0 也连不上。
    allow_lan = any(_exposes_lan(item.get("listen")) for item in listeners)
    return {
        "mixed-port": int(settings.get("mihomo_mixed_port") or 0),
        "allow-lan": allow_lan,
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


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError, TypeError):
        return False
    return True


def _proc_cmdline(pid):
    """读取某个进程的命令行。

    优先 /proc（Linux；python:slim 镜像里没有 procps，pgrep/ps 都不存在），
    取不到再退回 ps（macOS 没有 /proc）。
    """
    try:
        with open("/proc/%d/cmdline" % int(pid), "rb") as handle:
            raw = handle.read()
        if raw:
            return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except (OSError, ValueError, TypeError):
        pass
    try:
        out = subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return out.stdout.strip()


def _pids_by_cmdline(needle):
    """命令行里含 needle 的 pid 集合。"""
    found = set()
    if os.path.isdir("/proc"):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            if needle in _proc_cmdline(entry):
                found.add(int(entry))
        return found
    try:
        out = subprocess.run(["pgrep", "-f", needle],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            found.update(int(t) for t in out.stdout.split() if t.isdigit())
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return found


class MihomoManager:
    def __init__(self, binary, run_dir):
        self.binary = binary
        self.run_dir = run_dir
        self.config_path = os.path.join(run_dir, "config.yaml")
        self.log_path = os.path.join(run_dir, "mihomo.log")
        self.pid_path = os.path.join(run_dir, "mihomo.pid")
        self._lock = threading.RLock()
        self._proc = None
        self.last_error = ""

    # --------------------------------------------------------- orphan reaping
    # subprocess.Popen 起的 mihomo 不会随父进程退出。app.py 一旦被 kill/重启，
    # 旧 mihomo 就变成孤儿：既不 die，也不再跟随新配置，却仍占着监听端口
    # （典型症状：127.0.0.1 上有个"幽灵监听器"，监听的是上一版配置）。
    def _read_pidfile(self):
        try:
            with open(self.pid_path, encoding="utf-8") as handle:
                return int(handle.read().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _our_mihomo_pids(self):
        """可能由本程序启动的 mihomo pid 集合。

        判据是命令行里的配置文件绝对路径 —— mihomo 以 `-f <config_path>` 启动，
        而该路径只出现在本程序拉起的实例里，比按进程名匹配安全得多。
        pid 文件仅作补充，且同样要用命令行核对：否则容器重建后那个 pid 被
        无关进程复用时会被误杀。
        """
        pids = _pids_by_cmdline(self.config_path)
        pid = self._read_pidfile()
        if pid and self.config_path in _proc_cmdline(pid):
            pids.add(pid)
        return pids

    def reap_orphan(self):
        """收掉遗留下来、且不是当前 self._proc 的 mihomo。

        返回被杀掉的 pid 列表；空列表表示没有孤儿。
        """
        with self._lock:
            me = os.getpid()
            current = self._proc.pid if self._proc and self._proc.poll() is None else None
            killed = []
            for pid in sorted(self._our_mihomo_pids()):
                if pid in (me, current) or not _pid_alive(pid):
                    continue
                try:
                    os.kill(pid, 15)
                    for _ in range(20):
                        if not _pid_alive(pid):
                            break
                        threading.Event().wait(0.25)
                    if _pid_alive(pid):
                        os.kill(pid, 9)
                    killed.append(pid)
                except OSError:
                    continue
            return killed

    def status(self):
        with self._lock:
            running = bool(self._proc and self._proc.poll() is None)
            return {"running": running, "pid": self._proc.pid if running else None,
                    "binary": self.binary, "config": self.config_path,
                    "last_error": self.last_error}

    def _write_pidfile(self, pid):
        try:
            os.makedirs(self.run_dir, exist_ok=True)
            with open(self.pid_path, "w", encoding="utf-8") as handle:
                handle.write(str(pid))
        except OSError:
            pass

    def _clear_pidfile(self):
        try:
            os.remove(self.pid_path)
        except OSError:
            pass

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
            self.reap_orphan()
            self._clear_pidfile()

    def start(self):
        with self._lock:
            self.reap_orphan()
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
                self._write_pidfile(self._proc.pid)
                self.last_error = ""
                return True
            except OSError as exc:
                self.last_error = str(exc)
                self._proc = None
                return False
