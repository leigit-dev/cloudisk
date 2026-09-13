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
用户注册后，管理员需要在`data/quotes.json`中写入配置如下：
```json
{
  "alice": 10737418240,
  "bob":   5368709120
}
```
配额单位为字节
这是为了防止系统储存在不安全的网络上受到滥用
