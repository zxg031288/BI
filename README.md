# Temp Mail Admin Panel + OpenAI Auto-Register

## 文件说明

| 文件 | 说明 |
|------|------|
| `index.html` | 前端管理面板（单文件，可在浏览器直接打开） |
| `proxy_server.py` | Flask 代理服务器（封装注册逻辑为 HTTP API） |
| `back_gao.py` | 原始命令行注册脚本 |
| `Dockerfile` | Docker 镜像构建文件 |
| `docker-compose.yml` | Docker Compose 部署配置 |
| `.env` | 配置文件（API 密钥等） |
| `requirements.txt` | Python 依赖 |

---

## 快速开始

### Docker 部署（推荐）

```bash
# 1. 构建并启动（会自动从 .env 读取配置）
docker-compose up -d

# 2. 查看运行状态
docker-compose ps

# 3. 查看日志
docker-compose logs -f app

# 4. 停止
docker-compose down
```

访问 `http://localhost:5000`

### 本地运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务器
python proxy_server.py --port 5000 --proxy http://127.0.0.1:7890
```

访问 `http://localhost:5000`

---

## 功能

### 临时邮箱管理

- **创建邮箱** — 随机 / 自定义用户名，支持批量生成
- **邮箱列表** — 查看所有邮箱及 JWT，支持复制、查看邮件、删除
- **邮件** — 查看邮件详情（原始内容）
- **自动注册** — 完整的 OpenAI Codex 账号自动注册流程

### 自动注册流程

```
① 连接服务器 → ② 自动创建临时邮箱 → ③ 生成 OAuth URL
→ ④ 浏览器打开授权链接 → ⑤ 完成 OpenAI 账号注册/登录
→ ⑥ 授权后提交 Callback URL → ⑦ Token 获取成功
```

---

## 配置说明

### .env 文件

```
MAIL_DOMAIN=031208.xyz
MAIL_WORKER_BASE=https://m.031208.xyz
MAIL_ADMIN_PASSWORD=zxg0312.
TOKEN_OUTPUT_DIR=/app/tokens
```

### 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--port` | 5000 | 服务端口 |
| `--host` | 0.0.0.0 | 监听地址 |
| `--proxy` | 无 | HTTP 代理 |
| `--callback-host` | localhost | OAuth callback 主机名 |
| `--callback-port` | 1455 | OAuth callback 端口 |

### Docker 部署 Callback Host 说明

| 环境 | CALLBACK_HOST 值 |
|------|-----------------|
| Windows Docker Desktop | `host.docker.internal` |
| Linux | `172.17.0.1`（容器 IP）或服务器公网 IP |
| Mac | `host.docker.internal` |
| 云服务器 | 服务器公网 IP 或域名 |

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 服务器状态、配置信息 |
| POST | `/api/register/start` | 启动注册流程 |
| GET | `/api/register/poll/{session_id}` | 轮询注册状态、实时日志 |
| POST | `/api/register/callback/{session_id}` | 提交 OAuth callback URL |
| POST | `/api/register/stop/{session_id}` | 停止注册 |
| POST | `/api/register/delete/{session_id}` | 删除任务 |
| GET | `/api/register/history` | 获取所有历史任务 |

---

## 注意事项

- `worker.dev` 域名在中国无法访问，请使用自定义域名
- 注册需要**非中国 IP** 的代理
- Callback URL 格式：`http://localhost:1455/auth/callback?code=xxx&state=xxx`
- Token 包含 `access_token`、`refresh_token`、`id_token`，请妥善保管
- Docker 部署时确保端口 1455 已正确映射
