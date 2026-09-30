# SubWeaver · Shadowrocket 订阅聚合与配置中心

把多个远程订阅源**编织**成一份统一的 Shadowrocket 配置：聚合节点、分组设策略、
管理分流规则与 DNS，一键导入客户端。单容器 + 单个 SQLite 文件即可运行。

```
订阅源聚合  →  节点池  →  分组与策略  →  规则 / DNS  →  订阅链接 · 完整配置
```

## 功能

- **订阅聚合**：添加多个远程订阅源，一键抓取、解析、合并节点，刷新时按来源替换
- **订阅源管理**：页面上直接查看订阅地址（点击复制）、在线编辑名称/地址/自动归组，
  单个刷新，抓取失败原因如实显示
- **20 种协议**：ss / ssr / vmess / vless / trojan / hysteria / hysteria2 / tuic /
  socks5 / socks5-tls / http / https / http2 / http3 / wireguard / ssh / snell /
  brook / gost / juicity，支持 URI 解析与手工录入
- **节点分组**：显式挑选成员 + 按订阅源自动归组，每个分组一条独立订阅链接
- **负载均衡策略**：手动顺序 / 延迟优先（url-test）/ 轮询 / 随机 / 故障转移（fallback）
- **测速**：内置 mihomo 内核做真实协议握手测速（内核不支持的协议自动降级为端口探测，
  如实标注「仅端口可达」）
- **Surge 风格规则**：表单或文本两种方式编辑分流规则，随配置一起下发
- **一键导入 Shadowrocket**：`shadowrocket://` 协议直达，含分组与规则的完整配置
- **DNS 设置**：可视化配置 `[General] dns-server`（system / DoH / DoT / DoQ）与 `[Host]`
  指定域名解析或固定 IP，含直连 DNS、兜底 DNS
- **静态托管导出**：一键导出发布包（订阅文件 + 完整配置 + 手机友好落地页），
  上传到任意静态托管后，手机在蜂窝网络下也能订阅刷新，不依赖本机常开
- 数据存 SQLite（`shadowrocket.db`，WAL 模式），自动从旧版 `data.json` 迁移

## 快速开始

### 本地运行

```bash
pip install -r requirements.txt
python app.py            # 或 ./start.sh（本机）/ ./start.sh lan（局域网）
```

打开 http://127.0.0.1:5017 ，首次进入设置管理密码。

### Docker

```bash
docker build -t subweaver .
docker run -d --name subweaver \
  -p 5017:5017 \
  -v "$PWD/data:/app/data" \
  subweaver
```

或直接 compose：

```bash
docker compose up -d
```

也可以用 GitHub Actions 构建好的镜像（见下），把 compose 里的 `build: .` 换成 `image:`。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `5017` | 监听端口 |
| `HOST` | `127.0.0.1`（镜像内 `0.0.0.0`） | 监听地址 |
| `SS_DATA_DIR` | 项目目录（镜像内 `/app/data`） | 数据目录：`shadowrocket.db` 与订阅产物都在这里 |
| `SS_DB_FILE` | `<SS_DATA_DIR>/shadowrocket.db` | 单独指定数据库文件 |
| `SS_OUTPUT_DIR` | `<SS_DATA_DIR>/output` | 生成的订阅/配置文件目录 |
| `SS_MIHOMO` | `bin/mihomo` | mihomo 内核路径 |

## 数据与迁移

- 所有数据在 **单个 SQLite 文件** `shadowrocket.db` 中（节点、订阅源、分组、规则、设置、
  密码哈希）。备份 = 拷贝这一个文件；迁移机器 = 把它放进数据目录。
- 从旧版升级：首次启动检测到 `data.json` 会**自动迁移**入库，原文件改名
  `data.json.migrated` 保留备份。
- **不要提交/公开** `shadowrocket.db` 与 `data.json*`（含全部节点凭据与密码哈希），
  `.gitignore` 已排除。

## 真实测速（可选）

仓库不含 mihomo 二进制。本地使用放一份到 `bin/mihomo`（或用 `SS_MIHOMO` 指定）即可启用
内核真实握手测速；没有内核时测速自动降级为端口层探测并在界面如实标注。

下载：https://github.com/MetaCubeX/mihomo/releases （注意与系统架构匹配）

## GitHub Actions 构建镜像

仓库自带 `.github/workflows/docker.yml`：推送到默认分支或打 `v*` 标签时，
自动构建 `linux/amd64` + `linux/arm64` 双架构镜像并推送到
`ghcr.io/<你的用户名>/<仓库名>`（使用仓库自带的 `GITHUB_TOKEN`，无需额外配置）。

```bash
docker pull ghcr.io/<你的用户名>/subweaver:latest
```

## 安全提示

- 管理界面包含全部节点凭据。默认开启登录密码，**不要**在未加密码的情况下暴露到公网
  或不可信局域网。
- 密码以 PBKDF2-HMAC-SHA256（10 万次迭代）哈希存储，服务端不存明文，忘记只能重置
  （`./set-password.sh`）。

## License

[MIT](LICENSE)
