# ClouDisk

一个为局域网个人文件存储与组织内共享设计的轻量级网盘应用。

---

## 功能

- **多用户隔离**：每个用户拥有独立的文件空间，互不可见。
- **文件与文件夹管理**：上传、下载、重命名、移动、复制、删除，支持拖拽上传整个文件夹并保留目录结构。
- **在线预览**：图片、视频、音频、PDF 直接在浏览器中查看。
- **浏览器内视频转码**：浏览器无法直接播放的视频（AVI / MKV / WMV / FLV 等），可在纯前端用 ffmpeg.wasm 转码为 MP4 后播放，不上传服务器。
- **在线编辑**：基于 Ace 编辑器的文本/代码编辑，支持语法高亮与 JSON 格式化。
- **批量打包下载**：服务端收集文件清单，前端 JSZip 并发拉取并打包为 zip。
- **配额管理**：按用户分配存储空间，超出配额时自动拒绝上传与复制。
- **主题切换**：浅色 / 深色主题，跟随系统偏好。
- **SVG 图标**：所有图标统一由 Jinja 宏（`templates/icon_svg.html`）渲染，含加载动画与未知类型兜底。
- **Cloudflare Access 集成**（可选）：通过 JWT 自动登录，未配置时自动回退传统注册/登录。

---

## 安装运行

```bash
pip install flask
python main.py
```

默认监听 `http://0.0.0.0:5000/`。

默认使用 Werkzeug 内置服务器，适合小规模场景。正式部署建议使用 Waitress 等生产级 WSGI 服务器：

```bash
pip install waitress
waitress-serve --listen=0.0.0.0:5000 main:app
```

传输重要文件时建议通过 Nginx 反向代理并启用 HTTPS。

### 单文件上限

单文件上限默认 2GB，可通过环境变量调整：

```bash
# 本地 / 直连部署（默认 2GB）
python main.py

# 走 Cloudflare Tunnel 免费版（100MB 请求体限制）
CLOUDDISK_MAX_FILE=99614720 python main.py
```

`MAX_CONTENT_LENGTH` 会随 `CLOUDDISK_MAX_FILE` 自动同步，无需单独配置。

---

## 空间配额管理

每个用户注册后的初始空间为 0。管理员需要在 `data/quotas.json` 中为用户分配空间：

```json
{
  "alice": 10737418240,
  "bob":   5368709120
}
```

配额单位为字节（上例分别为 10GB 和 5GB）。

未分配配额的用户无法上传文件，这是为了防止存储在不受控网络环境下被滥用。

---

## 密钥管理

`SECRET_KEY` 用于签名 session cookie，保护账户安全。首次启动时，服务会在 `data/secret.key` 生成一串强随机密钥并持久化，后续启动读取同一值，重启不会导致用户登出。

如需强制所有用户重新登录，删除该文件后重启即可。

也可通过环境变量注入，优先级高于本地文件：

```bash
export CLOUDDISK_SECRET_KEY=YOUR_SECRET_KEY
python main.py
```

---

## Cloudflare Access 集成（可选）

ClouDisk 支持通过 Cloudflare Access 的 JWT 自动登录，实现"邮箱验证通过即自动登录"的体验。

### 启用方式

```bash
pip install PyJWT cryptography

export CF_ACCESS_TEAM_DOMAIN="your-team.cloudflareaccess.com"
export CF_ACCESS_AUD="你的应用AUD_TAG"

python main.py
```

**Team Domain**：Cloudflare Zero Trust → Settings → Custom Pages 顶部可见。
**AUD Tag**：Zero Trust → Access → Applications → 你的应用 → Overview。

### 工作流程

1. 用户访问站点 → Cloudflare Access 拦截
2. 用户通过 Access 提供的身份验证（GitHub / Google / 邮箱 OTP 等）
3. Access 向源站注入包含已验证邮箱的 JWT
4. ClouDisk 验证 JWT 签名，提取邮箱
5. 用邮箱作为用户名查找本地账号：
   - **账号已存在** → 直接自动登录
   - **账号不存在** → 跳转"完成注册"页面，用户设置密码后创建账号
6. 任何环节失败 → 回退到传统登录页

### 预创建账号

如需精确控制谁能登录，可以在 `data/db.json` 中手动预创建用户，`username` 字段直接填写邮箱：

```json
{
  "users": {
    "1": {
      "id": 1,
      "username": "alice@qq.com",
      "password_hash": "pbkdf2:sha256:...",
      "created_at": "2026-09-23T10:00:00"
    }
  },
  "next_user_id": 2,
  "nodes": {},
  "next_node_id": 1
}
```

预创建的账号首次访问时会直接自动登录，不会看到注册页。

### 未启用 Access 时

不装 `PyJWT` 或不设置上述环境变量，系统自动回退到传统注册/登录模式，完全不受影响。

---

## 浏览器内转码

浏览器无法直接播放的视频（AVI / MKV / WMV / FLV 等），可在预览弹窗中点击「转码播放」，由前端 ffmpeg.wasm 转码为 H.264 MP4 后播放。整个过程在本地完成，原文件不上传服务器。

### 部署 ffmpeg 资源

ffmpeg.wasm 的 Worker 脚本必须与页面同源，因此相关文件需放在 `static/ffmpeg/` 下，随 Flask 一同提供：

```bash
mkdir -p static/ffmpeg

curl -L -o static/ffmpeg/ffmpeg.js \
  https://cdn.jsdelivr.net/npm/@ffmpeg/ffmpeg@0.12.10/dist/umd/ffmpeg.js

curl -L -o static/ffmpeg/814.ffmpeg.js \
  https://cdn.jsdelivr.net/npm/@ffmpeg/ffmpeg@0.12.10/dist/umd/814.ffmpeg.js

curl -L -o static/ffmpeg/ffmpeg-core.js \
  https://cdn.jsdelivr.net/npm/@ffmpeg/core@0.12.6/dist/umd/ffmpeg-core.js

curl -L -o static/ffmpeg/ffmpeg-core.wasm \
  https://cdn.jsdelivr.net/npm/@ffmpeg/core@0.12.6/dist/umd/ffmpeg-core.wasm
```

### 说明

- 首次点击「转码播放」时下载约 30MB 解码器，之后浏览器会缓存。
- 转码强制使用 `libx264` 完整重编码（`-preset ultrafast`），不尝试 `-c:v copy`，保证输出一定可播放。
- 大文件会先弹确认框：超过 300MB 提示、超过 800MB 明确警告。
- 转码结果会在播放前用 `verifyPlayable()` 校验；浏览器无法解码时自动报错，不会出现"控件出现但画面不动"。

---

## 第三方依赖

### 服务端

随 `pip install flask` 一并安装：

| 依赖 | 许可证 | 来源 |
|---|---|---|
| Flask | BSD-3-Clause | https://github.com/pallets/flask |
| Werkzeug | BSD-3-Clause | https://github.com/pallets/werkzeug |

可选（仅在启用 Cloudflare Access JWT 时需要）：

| 依赖 | 许可证 | 来源 |
|---|---|---|
| PyJWT | MIT | https://github.com/jpadilla/pyjwt |
| cryptography | Apache-2.0 / BSD-3-Clause | https://github.com/pyca/cryptography |

可选（生产级 WSGI 服务器）：

| 依赖 | 许可证 | 来源 |
|---|---|---|
| Waitress | ZPL-2.1 | https://github.com/Pylons/waitress |

### 前端

Ace 与 JSZip 通过 jsDelivr CDN 引入；ffmpeg.wasm 需自行下载到 `static/ffmpeg/`（见上文）：

| 依赖 | 许可证 | 来源 |
|---|---|---|
| Ace 1.32.6 | BSD-3-Clause | https://github.com/ajaxorg/ace |
| JSZip 3.10.1 | MIT | https://github.com/Stuk/jszip |
| @ffmpeg/ffmpeg 0.12.10 | MIT | https://github.com/ffmpegwasm/ffmpeg.wasm |
| @ffmpeg/core 0.12.6 | LGPL-2.1-or-later（部分构建为 GPL） | https://github.com/ffmpegwasm/ffmpeg.wasm |

**注**：`@ffmpeg/core` 是 FFmpeg 的 WebAssembly 构建，其许可证取决于具体的构建配置。默认 npm 发行版包含 `libx264` 等组件，实际遵循 GPL。若要商用并规避 GPL 义务，请自行构建不含 GPL 组件的 core。

局域网部署若无法访问 jsDelivr CDN，可将 Ace 和 JSZip 下载到 `static/` 目录下，并修改模板中的 `<script>` 路径。下载时请保留源文件顶部的许可证声明。

---

## 数据目录结构

```
data/
├── db.json          # 用户与文件节点元数据
├── quotas.json      # 用户配额
├── secret.key       # session 签名密钥（首次启动自动生成）
└── <user_id>/       # 每个用户的文件存储（以 UUID 命名）
    └── <uuid>
```

**建议定期备份整个 `data/` 目录。** 备份时注意排除或加密 `secret.key`。

ffmpeg.wasm 相关文件位于 `static/ffmpeg/`，属于部署产物，无需备份。

---

## 已知限制

- 未实现 CSRF token，请勿将本应用暴露在不受信任的公网环境中。
- 未实现文件版本历史，删除操作不可恢复。
- 用户密码最小长度 8 位，未强制复杂度要求。
- 浏览器内转码为单线程 wasm，速度约为 0.3~1× 实时；文件超过 800MB 时失败概率高，建议直接下载。
- 单文件上限默认 2GB；走 Cloudflare Tunnel 免费版时请将 `CLOUDDISK_MAX_FILE` 设为 95MB 以内，或改用分片上传。

---

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE)。