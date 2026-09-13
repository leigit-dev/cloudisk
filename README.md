# ClouDisk
为局域网个人文件储存和组织内共享云盘空间设计的轻量级网盘应用

### 安装运行
```bash
pip install flask
```
```bash
python main.py
```
服务运行在http://0.0.0.0:5000/

默认使用Werkzeug提供Web服务。在服务规模较大的时候建议使用Waitress等生产级WSGI服务器

在传输重要文件的时候建议通过Nginx转发为https

### 空间配额管理
每个用户注册后的初始空间限制为0GB。

用户注册后，管理员需要在`data/quotas.json`中写入配置如下：
```json
{
  "alice": 10737418240,
  "bob":   5368709120
}
```

配额单位为字节

这是为了防止系统储存在不安全的网络上受到滥用。

### 密钥管理
`SECRET_KEY` 用于签名 session cookie保护账户安全。首次启动时，服务会在 `data/secret.key` 中生成一串强随机密钥并持久化，后续启动读取同一个值，重启不会导致用户登出。
如需强制所有用户重新登录，删除该文件后重启即可。
也可通过环境变量 `CLOUDDISK_SECRET_KEY` 注入，优先级高于本地文件：
```bash
export CLOUDDISK_SECRET_KEY=YOUR_SECRET_KEY
python main.py
```

### 第三方依赖
**服务端**（随 `pip install flask` 一并安装）：
- Flask — BSD-3-Clause — https://github.com/pallets/flask
- Werkzeug — BSD-3-Clause — https://github.com/pallets/werkzeug

**前端**（通过 jsDelivr CDN 引入，未随本项目源码分发）：
- Ace 1.32.6 — BSD-3-Clause — https://github.com/ajaxorg/ace
- JSZip 3.10.1 — 本项目按 MIT 许可证使用 — https://github.com/Stuk/jszip

局域网部署若无法访问 jsDelivr CDN，可将 Ace 和 JSZip 下载到 `static/` 下并修改模板中的 `<script>` 路径，下载时请保留源文件顶部的许可证声明。

### 许可证
本项目采用 MIT 许可证，详见 [LICENSE](LICENSE)。
