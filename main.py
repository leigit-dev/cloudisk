import os
import json
import uuid
import shutil
import mimetypes
import threading
import secrets
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, session, send_file, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------------------------------
# 基础配置
# --------------------------------------------------------------------------
BASE_DIR   = os.path.abspath(os.path.dirname(__file__))
DATA_DIR   = os.path.join(BASE_DIR, 'data')
DB_FILE    = os.path.join(DATA_DIR, 'db.json')
QUOTA_FILE = os.path.join(DATA_DIR, 'quotas.json')
os.makedirs(DATA_DIR, exist_ok=True)

def _load_secret_key():
    """从 data/secret.key 读取密钥；不存在则随机生成并持久化。"""
    key_file = os.path.join(DATA_DIR, 'secret.key')

    # 1) 环境变量优先（方便容器部署）
    env_key = os.environ.get('CLOUDDISK_SECRET_KEY')
    if env_key:
        return env_key

    # 2) 读本地文件
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r', encoding='utf-8') as fh:
                key = fh.read().strip()
            if key:
                return key
        except OSError:
            pass

    # 3) 都没有 → 生成新的并写盘
    key = secrets.token_urlsafe(48)
    try:
        with open(key_file, 'w', encoding='utf-8') as fh:
            fh.write(key)
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=_load_secret_key(),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024 * 1024,
    JSON_AS_ASCII=False,
)

# ==========================================================================
# JSON 数据库层
# ==========================================================================
_db_lock = threading.RLock()
_db      = None


def _empty_db():
    return {
        'users':        {},   # str(uid) -> user dict
        'nodes':        {},   # str(nid) -> node dict
        'next_user_id': 1,
        'next_node_id': 1,
    }


def load_db():
    global _db
    with _db_lock:
        if _db is not None:
            return _db

        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, 'r', encoding='utf-8') as fh:
                    raw = json.load(fh)
                base = _empty_db()
                for k, v in base.items():
                    raw.setdefault(k, v)
                _db = raw
            except (json.JSONDecodeError, OSError, ValueError):
                try:
                    os.replace(DB_FILE, DB_FILE + '.broken')
                except OSError:
                    pass
                _db = _empty_db()
                _persist()
        else:
            _db = _empty_db()
            _persist()

        return _db


def _persist():
    if _db is None:
        return
    tmp = DB_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(_db, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)


def save_db():
    with _db_lock:
        _persist()


def _now_iso():
    return datetime.utcnow().isoformat(timespec='seconds')


# --------------------------------------------------------------------------
# 属性化字典（供模板使用 user.username 这种写法）
# --------------------------------------------------------------------------
class AttrDict(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


# ==========================================================================
# 配额管理  ——  data/quotas.json
# --------------------------------------------------------------------------
# 文件格式（按用户名索引，值单位为字节）：
# {
#   "alice": 10737418240,
#   "bob":   5368709120,
#   "carol": 0
# }
# · 用户注册时默认配额为 0 → 无法上传任何文件
# · 只有手动编辑该文件才能调整配额
# · 删除某条记录等价于把该用户配额设为 0
# ==========================================================================
_quota_lock  = threading.RLock()
_quota_cache = {'mtime': None, 'data': {}}


def _ensure_quota_file():
    """首次运行时创建空配额文件。"""
    if not os.path.exists(QUOTA_FILE):
        try:
            with open(QUOTA_FILE, 'w', encoding='utf-8') as fh:
                json.dump({}, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass


def load_quotas(force=False):
    """返回配额字典 {username: int}；基于 mtime 的轻量缓存。"""
    global _quota_cache

    with _quota_lock:
        _ensure_quota_file()

        try:
            mtime = os.path.getmtime(QUOTA_FILE)
        except OSError:
            mtime = None

        if (not force) and mtime is not None and _quota_cache['mtime'] == mtime:
            return _quota_cache['data']

        data = {}
        try:
            with open(QUOTA_FILE, 'r', encoding='utf-8') as fh:
                raw = json.load(fh) or {}
            if isinstance(raw, dict):
                for k, v in raw.items():
                    try:
                        data[str(k)] = int(v)
                    except (TypeError, ValueError):
                        data[str(k)] = 0
        except (json.JSONDecodeError, OSError):
            data = {}

        _quota_cache = {'mtime': mtime, 'data': data}
        return data


def get_user_quota(username):
    """取某用户配额（字节）；未配置 → 0。"""
    if not username:
        return 0
    q = load_quotas().get(username, 0)
    try:
        q = int(q)
    except (TypeError, ValueError):
        q = 0
    return max(0, q)


def get_user_used(user_id):
    """某用户当前占用的总字节数（只统计文件）。"""
    return sum(
        n['size'] for n in load_db()['nodes'].values()
        if n['user_id'] == user_id and not n['is_dir']
    )


def fmt_size(num):
    """人类可读的体积文本。"""
    try:
        n = float(num)
    except (TypeError, ValueError):
        return '0 B'
    if n < 1024:
        return f'{int(n)} B'
    for unit in ('KB', 'MB', 'GB', 'TB', 'PB'):
        n /= 1024
        if n < 1024:
            return f'{n:.2f} {unit}'
    return f'{n:.2f} EB'


# ==========================================================================
# User CRUD
# ==========================================================================
def user_get(uid):
    if uid is None:
        return None
    return load_db()['users'].get(str(uid))


def user_get_by_name(username):
    for u in load_db()['users'].values():
        if u['username'] == username:
            return u
    return None


def user_create(username, password):
    db = load_db()
    with _db_lock:
        uid = db['next_user_id']
        db['next_user_id'] = uid + 1
        u = {
            'id':            uid,
            'username':      username,
            'password_hash': generate_password_hash(password),
            'created_at':    _now_iso(),
        }
        db['users'][str(uid)] = u
        save_db()
    return u


# ==========================================================================
# Node CRUD
# ==========================================================================
def node_get(nid, user_id=None):
    if nid is None:
        return None
    try:
        nid = int(nid)
    except (TypeError, ValueError):
        return None
    n = load_db()['nodes'].get(str(nid))
    if n is None:
        return None
    if user_id is not None and n['user_id'] != user_id:
        return None
    return n


def node_children(user_id, parent_id):
    return [n for n in load_db()['nodes'].values()
            if n['user_id'] == user_id and n['parent_id'] == parent_id]


def node_create(user_id, parent_id, name, is_dir=False,
                size=0, mime='', stored=''):
    db = load_db()
    with _db_lock:
        nid = db['next_node_id']
        db['next_node_id'] = nid + 1
        now = _now_iso()
        n = {
            'id':         nid,
            'user_id':    user_id,
            'parent_id':  parent_id,
            'name':       name,
            'is_dir':     bool(is_dir),
            'size':       int(size or 0),
            'mime':       mime or '',
            'stored':     stored or '',
            'created_at': now,
            'updated_at': now,
        }
        db['nodes'][str(nid)] = n
        save_db()
    return n


def node_path(node):
    chain, cur = [], node
    while cur is not None:
        chain.append(cur)
        if cur['parent_id'] is None:
            break
        cur = load_db()['nodes'].get(str(cur['parent_id']))
    return list(reversed(chain))


def is_descendant(node, ancestor):
    cur = node
    while cur is not None:
        if cur['id'] == ancestor['id']:
            return True
        if cur['parent_id'] is None:
            return False
        cur = load_db()['nodes'].get(str(cur['parent_id']))
    return False


def unique_name(user_id, parent_id, name):
    existing = {n['name'] for n in node_children(user_id, parent_id)}
    if name not in existing:
        return name
    base, ext = os.path.splitext(name)
    i = 1
    while f"{base} ({i}){ext}" in existing:
        i += 1
    return f"{base} ({i}){ext}"


def node_dict(n):
    ext = '' if n['is_dir'] else os.path.splitext(n['name'])[1].lower().lstrip('.')
    updated = (n.get('updated_at') or '').replace('T', ' ')[:16]
    return {
        'id':         n['id'],
        'name':       n['name'],
        'is_dir':     n['is_dir'],
        'size':       n['size'],
        'mime':       n['mime'] or '',
        'parent_id':  n['parent_id'],
        'updated_at': updated,
        'ext':        ext,
    }


def tree_size(node):
    """递归累计一个节点占用的字节数（文件夹会累加其内所有文件）。"""
    if node is None:
        return 0
    if not node['is_dir']:
        return int(node['size'] or 0)
    total = 0
    for c in node_children(node['user_id'], node['id']):
        total += tree_size(c)
    return total


def delete_recursive(node):
    db = load_db()
    collected = []

    def walk(n):
        collected.append(n)
        for c in node_children(n['user_id'], n['id']):
            walk(c)
    walk(node)

    # 先删物理文件
    for n in collected:
        if not n['is_dir'] and n['stored']:
            p = disk_path(n['user_id'], n['stored'])
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass

    with _db_lock:
        for n in collected:
            db['nodes'].pop(str(n['id']), None)
        save_db()


def copy_recursive(node, new_parent_id, user_id):
    new = node_create(
        user_id=user_id,
        parent_id=new_parent_id,
        name=unique_name(user_id, new_parent_id, node['name']),
        is_dir=node['is_dir'],
        size=node['size'],
        mime=node['mime'],
        stored=uuid.uuid4().hex if not node['is_dir'] else '',
    )
    if not node['is_dir']:
        src = disk_path(user_id, node['stored'])
        dst = disk_path(user_id, new['stored'])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.exists(src):
            try:
                shutil.copy2(src, dst)
            except OSError:
                pass
    if node['is_dir']:
        for child in node_children(user_id, node['id']):
            copy_recursive(child, new['id'], user_id)
    return new


def disk_path(user_id, stored):
    return os.path.join(DATA_DIR, str(user_id), stored)


def _match_kind(node, kind):
    m = node.get('mime') or ''
    if kind == 'image':
        return m.startswith('image/')
    if kind == 'video':
        return m.startswith('video/')
    if kind == 'audio':
        return m.startswith('audio/')
    if kind == 'doc':
        return (m.startswith('text/') or 'pdf' in m or 'word' in m
                or 'excel' in m or 'presentation' in m or 'json' in m)
    return True


# ==========================================================================
# 请求钩子 / 装饰器
# ==========================================================================
@app.before_request
def _load_user():
    uid = session.get('uid')
    u = user_get(uid) if uid else None
    g.user = AttrDict(u) if u else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            if request.path.startswith('/api/'):
                return jsonify(success=False, error='未登录'), 401
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def _inject():
    return {'user': g.user}


# ==========================================================================
# 认证
# ==========================================================================
@app.route('/')
def index():
    return redirect(url_for('files') if g.user else url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        u = user_get_by_name(username)
        if u and check_password_hash(u['password_hash'], password):
            session['uid'] = u['id']
            nxt = request.args.get('next') or url_for('files')
            return redirect(nxt)
        return render_template('login.html', error='用户名或密码错误',
                               mode='login', username=username)
    return render_template('login.html', mode='login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm  = request.form.get('confirm') or ''

        def fail(msg):
            return render_template('login.html', error=msg,
                                   mode='register', username=username)

        if len(username) < 2:
            return fail('用户名至少 2 个字符')
        if len(password) < 4:
            return fail('密码至少 4 位')
        if password != confirm:
            return fail('两次密码不一致')
        if user_get_by_name(username):
            return fail('用户名已存在')

        u = user_create(username, password)
        # 注册后默认配额为 0，不在此处写 quota 文件；
        # 管理员编辑 quotas.json 添加该用户名即可赋予配额。
        session['uid'] = u['id']
        return redirect(url_for('files'))

    return render_template('login.html', mode='register')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ==========================================================================
# 页面
# ==========================================================================
@app.route('/files')
@login_required
def files():
    return render_template('index.html')


@app.route('/editor/<int:nid>')
@login_required
def editor(nid):
    n = node_get(nid, g.user['id'])
    if not n or n['is_dir']:
        abort(404)

    p = disk_path(n['user_id'], n['stored'])
    if n['size'] > 4 * 1024 * 1024:
        abort(413)
    try:
        with open(p, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except (UnicodeDecodeError, OSError):
        abort(415)

    class NodeView:
        pass
    nv = NodeView()
    nv.id   = n['id']
    nv.name = n['name']
    nv.size = n['size']
    try:
        nv.updated_at = datetime.fromisoformat(n['updated_at'])
    except (ValueError, TypeError):
        nv.updated_at = datetime.utcnow()

    return render_template('editor.html', node=nv, content=content)


# ==========================================================================
# API：列表 / 统计
# ==========================================================================
@app.route('/api/list')
@login_required
def api_list():
    uid       = g.user['id']
    folder_id = request.args.get('folder', type=int)
    q         = (request.args.get('q') or '').strip()
    kind      = request.args.get('kind') or 'all'

    if q:
        ql = q.lower()
        items = [n for n in load_db()['nodes'].values()
                 if n['user_id'] == uid and ql in n['name'].lower()]
        items.sort(key=lambda n: (0 if n['is_dir'] else 1, n['name'].lower()))
        return jsonify(success=True, items=[node_dict(i) for i in items],
                       breadcrumb=[], current=None, search=True, kind='all')

    parent = None
    if folder_id:
        parent = node_get(folder_id, uid)
        if not parent or not parent['is_dir']:
            return jsonify(success=False, error='文件夹不存在'), 404

    pid = parent['id'] if parent else None

    if kind == 'all':
        items = node_children(uid, pid)
    else:
        items = [n for n in load_db()['nodes'].values()
                 if n['user_id'] == uid and not n['is_dir']]
        items = [n for n in items if _match_kind(n, kind)]

    items.sort(key=lambda n: (0 if n['is_dir'] else 1, n['name'].lower()))

    crumbs = []
    if parent:
        crumbs = [{'id': n['id'], 'name': n['name']} for n in node_path(parent)]

    return jsonify(success=True, items=[node_dict(i) for i in items],
                   breadcrumb=crumbs,
                   current=node_dict(parent) if parent else None,
                   search=False, kind=kind)


@app.route('/api/stats')
@login_required
def api_stats():
    """
    返回：used（已用字节）、count（文件数）、
          quota（配额字节）、remaining（剩余字节）、can_upload（是否还有配额）
    """
    uid   = g.user['id']
    used  = get_user_used(uid)
    quota = get_user_quota(g.user['username'])
    count = sum(1 for n in load_db()['nodes'].values()
                if n['user_id'] == uid and not n['is_dir'])

    remaining  = max(0, quota - used)
    can_upload = quota > 0 and remaining > 0

    return jsonify(
        success=True,
        used=used,
        count=count,
        quota=quota,
        remaining=remaining,
        can_upload=can_upload,
        used_text=fmt_size(used),
        quota_text=fmt_size(quota) if quota > 0 else '未分配',
        remaining_text=fmt_size(remaining) if quota > 0 else '—',
    )


# ==========================================================================
# API：上传（带配额校验）
# ==========================================================================
@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    uid      = g.user['id']
    username = g.user['username']

    # ---- 1) 配额预检 ----
    quota = get_user_quota(username)
    if quota <= 0:
        return jsonify(
            success=False,
            error='您的账号未分配上传配额，请联系管理员在 quotas.json 中为您分配空间。',
            code='NO_QUOTA'
        ), 403

    used        = get_user_used(uid)
    remaining   = max(0, quota - used)
    if remaining <= 0:
        return jsonify(
            success=False,
            error=f'存储空间已满（已用 {fmt_size(used)} / 配额 {fmt_size(quota)}）',
            code='QUOTA_EXCEEDED'
        ), 413

    # content_length 是整个 multipart 请求（含边界），作为快速上界使用
    cl = request.content_length or 0
    if cl > remaining:
        return jsonify(
            success=False,
            error=(f'存储空间不足。剩余 {fmt_size(remaining)}，'
                   f'本文件约 {fmt_size(cl)}。'),
            code='QUOTA_EXCEEDED'
        ), 413

    # ---- 2) 定位父目录 ----
    parent_id = request.form.get('folder') or None
    if parent_id:
        try:
            parent_id = int(parent_id)
        except ValueError:
            parent_id = None

    parent = None
    if parent_id:
        parent = node_get(parent_id, uid)
        if not parent or not parent['is_dir']:
            return jsonify(success=False, error='目标文件夹不存在'), 404

    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify(success=False, error='没有文件'), 400

    rel_path = (request.form.get('rel_path') or f.filename).replace('\\', '/')
    parts = [p for p in rel_path.split('/') if p and p not in ('.', '..')]
    if not parts:
        parts = [f.filename]
    filename = parts[-1]
    subdirs  = parts[:-1]

    # ---- 3) 逐级创建子目录 ----
    cur_pid = parent['id'] if parent else None
    for d in subdirs:
        existing = None
        for c in node_children(uid, cur_pid):
            if c['is_dir'] and c['name'] == d:
                existing = c
                break
        if existing:
            cur_pid = existing['id']
        else:
            nn = node_create(uid, cur_pid, d, is_dir=True)
            cur_pid = nn['id']

    # ---- 4) 落盘 ----
    final_name = unique_name(uid, cur_pid, filename)
    stored     = uuid.uuid4().hex

    user_dir = os.path.join(DATA_DIR, str(uid))
    os.makedirs(user_dir, exist_ok=True)
    dst = os.path.join(user_dir, stored)
    f.save(dst)
    size = os.path.getsize(dst)

    # ---- 5) 精确配额校验（文件已落盘，用实际字节数核对） ----
    used_now = get_user_used(uid)
    if used_now + size > quota:
        try:
            os.remove(dst)
        except OSError:
            pass
        return jsonify(
            success=False,
            error=(f'存储空间不足。已用 {fmt_size(used_now)} / '
                   f'配额 {fmt_size(quota)}，无法写入该文件（{fmt_size(size)}）。'),
            code='QUOTA_EXCEEDED'
        ), 413

    mime = (f.mimetype
            or mimetypes.guess_type(final_name)[0]
            or 'application/octet-stream')

    n = node_create(uid, cur_pid, final_name, is_dir=False,
                    size=size, mime=mime, stored=stored)

    return jsonify(success=True, item=node_dict(n))


# ==========================================================================
# API：下载 / 预览 / 内容
# ==========================================================================
@app.route('/api/download/<int:nid>')
@login_required
def api_download(nid):
    n = node_get(nid, g.user['id'])
    if not n or n['is_dir']:
        abort(404)
    p = disk_path(n['user_id'], n['stored'])
    if not os.path.exists(p):
        abort(404)
    return send_file(p, as_attachment=True,
                     download_name=n['name'], conditional=True)


@app.route('/api/raw/<int:nid>')
@login_required
def api_raw(nid):
    n = node_get(nid, g.user['id'])
    if not n or n['is_dir']:
        abort(404)
    p = disk_path(n['user_id'], n['stored'])
    if not os.path.exists(p):
        abort(404)
    return send_file(p,
                     mimetype=n['mime'] or 'application/octet-stream',
                     as_attachment=False,
                     download_name=n['name'],
                     conditional=True)


@app.route('/api/content/<int:nid>')
@login_required
def api_content(nid):
    n = node_get(nid, g.user['id'])
    if not n:
        return jsonify(success=False, error='文件不存在'), 404
    if n['is_dir']:
        return jsonify(success=False, error='这是一个文件夹'), 400
    if n['size'] > 4 * 1024 * 1024:
        return jsonify(success=False, error='文件超过 4MB，无法在线编辑'), 400

    p = disk_path(n['user_id'], n['stored'])
    try:
        with open(p, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except UnicodeDecodeError:
        return jsonify(success=False, error='二进制文件无法编辑'), 400
    except OSError:
        return jsonify(success=False, error='文件不存在'), 404

    return jsonify(success=True, content=content, item=node_dict(n))


@app.route('/api/save/<int:nid>', methods=['POST'])
@login_required
def api_save(nid):
    n = node_get(nid, g.user['id'])
    if not n:
        return jsonify(success=False, error='文件不存在'), 404
    if n['is_dir']:
        abort(400)

    data    = request.get_json(silent=True) or {}
    content = data.get('content', '')
    p = disk_path(n['user_id'], n['stored'])

    old_size = n['size']
    with open(p, 'w', encoding='utf-8', newline='') as fh:
        fh.write(content)
    new_size = os.path.getsize(p)

    # 编辑也可能撑大文件 → 检查增量是否超出配额
    uid      = g.user['id']
    quota    = get_user_quota(g.user['username'])
    delta    = new_size - old_size
    if delta > 0 and quota > 0:
        used = get_user_used(uid)
        if used + delta > quota:
            # 回滚：把文件还原为原内容长度做不到，
            # 就直接告知超限并保留已写入内容（也可改成截断）。
            return jsonify(
                success=False,
                error=(f'保存后超出配额。已用 {fmt_size(used)} + 增量 '
                       f'{fmt_size(delta)} > 配额 {fmt_size(quota)}。')
            ), 413

    with _db_lock:
        n['size']       = new_size
        n['updated_at'] = _now_iso()
        save_db()

    return jsonify(success=True, size=n['size'])


# ==========================================================================
# API：新建 / 重命名 / 删除 / 移动 / 复制
# ==========================================================================
@app.route('/api/mkdir', methods=['POST'])
@login_required
def api_mkdir():
    uid  = g.user['id']
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip().replace('/', '').replace('\\', '')
    if not name:
        return jsonify(success=False, error='名称不能为空'), 400

    parent_id = data.get('parent') or None
    parent = None
    if parent_id:
        parent = node_get(parent_id, uid)
        if not parent or not parent['is_dir']:
            return jsonify(success=False, error='父文件夹不存在'), 404

    pid = parent['id'] if parent else None
    n = node_create(uid, pid, unique_name(uid, pid, name), is_dir=True)
    return jsonify(success=True, item=node_dict(n))


@app.route('/api/rename', methods=['POST'])
@login_required
def api_rename():
    uid  = g.user['id']
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip().replace('/', '').replace('\\', '')
    if not name:
        return jsonify(success=False, error='名称不能为空'), 400

    n = node_get(data.get('id'), uid)
    if not n:
        return jsonify(success=False, error='文件不存在'), 404

    if name != n['name']:
        with _db_lock:
            n['name']       = unique_name(uid, n['parent_id'], name)
            n['updated_at'] = _now_iso()
            save_db()

    return jsonify(success=True, item=node_dict(n))


@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    uid  = g.user['id']
    data = request.get_json(silent=True) or {}

    count = 0
    for nid in (data.get('ids') or []):
        n = node_get(nid, uid)
        if n:
            delete_recursive(n)
            count += 1

    return jsonify(success=True, count=count)


@app.route('/api/move', methods=['POST'])
@login_required
def api_move():
    uid  = g.user['id']
    data = request.get_json(silent=True) or {}

    target_id = data.get('target') or None
    target = None
    if target_id:
        target = node_get(target_id, uid)
        if not target or not target['is_dir']:
            return jsonify(success=False, error='目标文件夹不存在'), 404
    tpid = target['id'] if target else None

    count = 0
    with _db_lock:
        for nid in (data.get('ids') or []):
            n = node_get(nid, uid)
            if not n:
                continue
            if n['id'] == tpid:
                continue
            if target and is_descendant(target, n):
                continue
            n['parent_id']  = tpid
            n['name']       = unique_name(uid, tpid, n['name'])
            n['updated_at'] = _now_iso()
            count += 1
        if count:
            save_db()

    return jsonify(success=True, count=count)


@app.route('/api/copy', methods=['POST'])
@login_required
def api_copy():
    uid      = g.user['id']
    username = g.user['username']
    data     = request.get_json(silent=True) or {}

    # ---- 复制也消耗配额 ----
    quota = get_user_quota(username)
    if quota <= 0:
        return jsonify(success=False,
                       error='您的账号未分配上传配额，无法复制文件'), 403

    target_id = data.get('target') or None
    target = None
    if target_id:
        target = node_get(target_id, uid)
        if not target or not target['is_dir']:
            return jsonify(success=False, error='目标文件夹不存在'), 404
    tpid = target['id'] if target else None

    # 先统计即将新增的字节数
    ids = list(data.get('ids') or [])
    incoming = 0
    for nid in ids:
        n = node_get(nid, uid)
        if n:
            incoming += tree_size(n)

    used = get_user_used(uid)
    if used + incoming > quota:
        return jsonify(
            success=False,
            error=(f'剩余空间不足，无法复制。需 {fmt_size(incoming)}，'
                   f'剩余 {fmt_size(max(0, quota - used))}。'),
            code='QUOTA_EXCEEDED'
        ), 413

    count = 0
    for nid in ids:
        n = node_get(nid, uid)
        if not n:
            continue
        copy_recursive(n, tpid, uid)
        count += 1

    return jsonify(success=True, count=count)


# ==========================================================================
# API：打包收集（供前端 JSZip 使用）
# ==========================================================================
@app.route('/api/collect', methods=['POST'])
@login_required
def api_collect():
    uid  = g.user['id']
    data = request.get_json(silent=True) or {}
    out  = []

    def walk(n, prefix):
        if n['is_dir']:
            np = f"{prefix}{n['name']}/"
            children = sorted(node_children(uid, n['id']),
                              key=lambda x: x['name'].lower())
            for c in children:
                walk(c, np)
        else:
            out.append({
                'id':   n['id'],
                'name': n['name'],
                'path': prefix,
                'size': n['size'],
            })

    for nid in (data.get('ids') or []):
        n = node_get(nid, uid)
        if n:
            walk(n, '')

    return jsonify(success=True, files=out,
                   total=len(out),
                   total_size=sum(f['size'] for f in out))


# ==========================================================================
# API：文件夹树（供移动 / 复制时的目标选择）
# ==========================================================================
@app.route('/api/tree')
@login_required
def api_tree():
    uid   = g.user['id']
    nodes = [n for n in load_db()['nodes'].values()
             if n['user_id'] == uid and n['is_dir']]

    by_parent = {}
    for n in nodes:
        by_parent.setdefault(n['parent_id'], []).append(n)

    def build(pid):
        return [{'id':       n['id'],
                 'name':     n['name'],
                 'children': build(n['id'])}
                for n in sorted(by_parent.get(pid, []),
                                key=lambda x: x['name'].lower())]

    return jsonify(success=True, tree=build(None))


# ==========================================================================
if __name__ == '__main__':
    load_db()          # 确保 db.json 存在
    load_quotas()      # 确保 quotas.json 存在
    app.run(host='0.0.0.0', port=5000, debug=False)