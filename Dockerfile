# syntax=docker/dockerfile:1
FROM python:3.12-slim

# 时区（测速时间戳可读）
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# 依赖层单独缓存
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码（数据不入镜像，走 /app/data 卷）
COPY app.py protocols.py db.py ./
COPY static ./static

# 非 root 运行
RUN useradd -m -u 10001 app \
    && mkdir -p /app/data \
    && chown -R app:app /app
USER app

# 数据目录（SQLite 库 + 生成的订阅产物），挂卷即可持久化
ENV SS_DATA_DIR=/app/data
VOLUME ["/app/data"]

EXPOSE 5017
ENV HOST=0.0.0.0 PORT=5017

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','5017')+'/api/status',timeout=4)"

CMD ["python", "-u", "app.py"]
