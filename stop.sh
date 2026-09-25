#!/bin/bash
# 停止 Shadowsocks 配置管理器
cd "$(dirname "$0")" || exit 1
PORT="${PORT:-5017}"
PID=$(lsof -ti tcp:"$PORT")
if [ -n "$PID" ]; then
  kill $PID
  echo "已停止端口 $PORT 上的服务 (PID $PID)"
else
  echo "端口 $PORT 上没有运行中的服务"
fi
