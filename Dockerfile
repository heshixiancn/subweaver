# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG TARGETARCH
ARG MIHOMO_VERSION=1.19.32

# 时区（测速时间戳可读）
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# mihomo 内核：构建期按目标架构从官方 Releases 下载，让镜像自带
# SOCKS5 中转、策略组和真实协议测速能力（不依赖仓库里的 bin/）。
# TARGETARCH 由 Buildx 注入；经典 builder 下为空则退回 uname -m。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gzip \
    && case "${TARGETARCH:-$(uname -m)}" in \
         amd64|x86_64) MIHOMO_ARCH=amd64 ;; \
         arm64|aarch64) MIHOMO_ARCH=arm64 ;; \
         *) echo "unsupported arch: ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
       esac \
    && curl -fsSL --retry 3 --retry-delay 2 \
         "https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/mihomo-linux-${MIHOMO_ARCH}-v${MIHOMO_VERSION}.gz" \
       | gzip -d > /usr/local/bin/mihomo \
    && chmod 0755 /usr/local/bin/mihomo \
    && test -s /usr/local/bin/mihomo \
    && rm -rf /var/lib/apt/lists/*

# 依赖层单独缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码（数据不入镜像，走 /app/data 卷）
COPY app.py protocols.py db.py mihomo_gateway.py ./
COPY static ./static

# 非 root 运行
RUN useradd -m -u 10001 app \
    && mkdir -p /app/data \
    && chown -R app:app /app
USER app

# 数据目录（SQLite 库 + 生成的订阅产物），挂卷即可持久化
ENV SS_DATA_DIR=/app/data
ENV SS_MIHOMO=/usr/local/bin/mihomo
VOLUME ["/app/data"]

EXPOSE 5017
# 分组 SOCKS5 出口（默认 18080 起，每组一个，最多 10 组）
EXPOSE 18080-18089
ENV HOST=0.0.0.0 PORT=5017
# 容器内分组 SOCKS5 必须绑 0.0.0.0：Docker 的端口转发是打到容器 IP 的，
# 绑 127.0.0.1 的话即使 -p 发布了端口，外面也连不进来。
ENV SS_SOCKS_LISTEN=0.0.0.0

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','5017')+'/api/status',timeout=4)"

CMD ["python", "-u", "app.py"]
