#!/bin/bash
# Shadowsocks 配置管理器 改密脚本
# 用法：
#   ./set-password.sh              交互式输入新密码（推荐，不留痕迹）
#   ./set-password.sh 我的新密码    直接作为参数传入（会留在 shell 历史里）
# 说明：只替换管理密码，节点 / 分组 / 订阅源等数据完全不受影响。

cd "$(dirname "$0")" || exit 1

PY=/Users/heshixian/.workbuddy/binaries/python/envs/default/bin/python
exec "$PY" app.py --set-password "$@"
