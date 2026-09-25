#!/bin/bash
# Shadowsocks 配置管理器 启动脚本
# 用法：
#   ./start.sh            仅本机访问（http://127.0.0.1:5017）
#   ./start.sh lan        局域网访问（手机/平板可打开，需与电脑同一 WiFi）
# 停止：./stop.sh

cd "$(dirname "$0")" || exit 1

PY=/Users/heshixian/.workbuddy/binaries/python/envs/default/bin/python
PORT="${PORT:-5017}"

if [ "$1" = "lan" ]; then
  HOST=0.0.0.0
  IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
  echo "局域网模式：http://${IP:-<本机IP>}:${PORT}"
else
  HOST=127.0.0.1
  echo "本机模式：http://127.0.0.1:${PORT}"
fi

# 端口占用处理：用 /api/status 的应答指纹判断占用者是不是本程序
if lsof -ti tcp:"$PORT" > /dev/null 2>&1; then
  OLD_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null)
  if curl -s --noproxy '*' --max-time 2 "http://127.0.0.1:${PORT}/api/status" \
       | grep -q '"group_count"'; then
    echo "检测到旧实例（PID $OLD_PID），正在重启…"
    kill $OLD_PID 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      lsof -ti tcp:"$PORT" > /dev/null 2>&1 || break
      sleep 0.3
    done
    if lsof -ti tcp:"$PORT" > /dev/null 2>&1; then
      echo "旧实例未能退出，请手动执行：kill $OLD_PID"
      exit 1
    fi
  else
    echo "端口 $PORT 被其他程序占用（PID $OLD_PID），未做处理。查看：lsof -i tcp:$PORT"
    exit 1
  fi
fi

HOST="$HOST" PORT="$PORT" nohup "$PY" -u app.py > server.log 2>&1 &

# 轮询等待端口就绪（最多 15 秒）——Python + Flask 启动耗时不定，固定 sleep 会误报失败
# --noproxy：本机若设了 HTTP_PROXY，健康检查会被代理拦截而误报失败
READY=""
for _ in $(seq 1 50); do
  if curl -s --noproxy '*' --max-time 1 -o /dev/null "http://127.0.0.1:${PORT}/"; then
    READY=1
    break
  fi
  sleep 0.3
done

if [ -n "$READY" ]; then
  NEW_PID=$(lsof -ti tcp:"$PORT" 2>/dev/null)
  echo "已启动（PID $NEW_PID），日志：$(pwd)/server.log"
  echo "停止：./stop.sh"
else
  echo "启动失败，请查看 server.log；末尾日志："
  tail -n 8 server.log 2>/dev/null | sed 's/^/  /'
fi
