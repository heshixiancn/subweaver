#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite 持久化层（替代 data.json 单文件存储）。

设计原则：
  - 单文件数据库（默认 <数据目录>/shadowrocket.db），WAL 模式，断电/崩溃安全
  - 实体表存「id + 完整 JSON blob」：app.py 里节点/订阅/分组的 dict 结构
    就是协议，原样入库，新增字段无需改 schema
  - kv 表存标量与文本块（密码哈希、密钥、token、settings、规则文本）
  - save_all() 单事务原子写入，替代原来的「写 tmp + os.replace」
  - 首次启动发现旧 data.json 会自动迁移（由 app.py 调用 migrate_from_json）
"""
import json
import os
import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS nodes (
  id   TEXT PRIMARY KEY,
  pos  INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id   TEXT PRIMARY KEY,
  pos  INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
  id   TEXT PRIMARY KEY,
  pos  INTEGER NOT NULL DEFAULT 0,
  data TEXT NOT NULL
);
"""

# kv 表中由 Store 直接读写的键（settings/rules/surge_rules 都是 JSON 或文本）
_KV_KEYS = ("password_hash", "secret_key", "publish_token",
            "settings", "rules", "surge_rules")


class Store:
    """线程安全的单文件 SQLite 仓库。所有公共方法内部加锁。"""

    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ---------------------------------------------------------- helpers
    @staticmethod
    def _dumps(v):
        return json.dumps(v, ensure_ascii=False)

    @staticmethod
    def _loads(s, default=None):
        if s is None:
            return default
        try:
            return json.loads(s)
        except Exception:
            return default

    # ---------------------------------------------------------- read
    def load_all(self):
        """重建与旧 data.json 完全一致的 dict 结构。"""
        with self._lock:
            kv = {r[0]: r[1] for r in self._conn.execute(
                "SELECT key, value FROM kv")}
            nodes = [self._loads(r[1], {}) for r in self._conn.execute(
                "SELECT id, data FROM nodes ORDER BY pos")]
            subs = [self._loads(r[1], {}) for r in self._conn.execute(
                "SELECT id, data FROM subscriptions ORDER BY pos")]
            groups = [self._loads(r[1], {}) for r in self._conn.execute(
                "SELECT id, data FROM groups ORDER BY pos")]
        return {
            "password_hash": kv.get("password_hash"),
            "secret_key": kv.get("secret_key"),
            "publish_token": kv.get("publish_token"),
            "settings": self._loads(kv.get("settings"), {}) or {},
            "rules": kv.get("rules") or "",
            "surge_rules": kv.get("surge_rules") or "",
            "nodes": nodes,
            "subscriptions": subs,
            "groups": groups,
        }

    def is_empty(self):
        """数据库里还没有任何业务数据（用于判断是否首次启动）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT (SELECT COUNT(*) FROM kv) +"
                " (SELECT COUNT(*) FROM nodes) +"
                " (SELECT COUNT(*) FROM subscriptions) +"
                " (SELECT COUNT(*) FROM groups)").fetchone()
        return row[0] == 0

    # ---------------------------------------------------------- write
    def save_all(self, data):
        """单事务原子重写全部数据。data 与旧 data.json 同构。"""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                for k in _KV_KEYS:
                    v = data.get(k)
                    if v is None:
                        cur.execute("DELETE FROM kv WHERE key=?", (k,))
                    elif isinstance(v, (dict, list)):
                        cur.execute(
                            "INSERT INTO kv(key,value) VALUES(?,?)"
                            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (k, self._dumps(v)))
                    else:
                        cur.execute(
                            "INSERT INTO kv(key,value) VALUES(?,?)"
                            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (k, str(v)))
                for table, key in (("nodes", "nodes"),
                                   ("subscriptions", "subscriptions"),
                                   ("groups", "groups")):
                    cur.execute(f"DELETE FROM {table}")
                    rows = [(str(item.get("id") or ""), i, self._dumps(item))
                            for i, item in enumerate(data.get(key) or [])
                            if item.get("id")]
                    cur.executemany(
                        f"INSERT INTO {table}(id,pos,data) VALUES(?,?,?)", rows)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ---------------------------------------------------------- migration
    def migrate_from_json(self, json_path):
        """把旧 data.json 导入数据库。返回导入的记录数（节点/订阅/分组）。"""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.save_all(data)
        return (len(data.get("nodes") or []),
                len(data.get("subscriptions") or []),
                len(data.get("groups") or []))

    def close(self):
        with self._lock:
            self._conn.close()
