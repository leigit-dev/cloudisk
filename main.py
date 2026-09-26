# ==========================================================================
# main.py — ClouDisk
# 支持：本地用户 / Cloudflare Access JWT 自动登录（可选）
# ==========================================================================
import os
import json
import uuid
import shutil
import mimetypes
import threading
import secrets
import time
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, session, send_file, abort, g)
from werkzeug.security import generate_password_hash, check_password_hash


# ---------- 可选依赖：PyJWT + cryptography ----------
try:
    import jwt
    from jwt import PyJWKClient
    _JWT_IMPORT_OK = True
except ImportError:
    jwt = None
    PyJWKClient = None
    _JWT_IMPORT_OK = False


# ==========================================================================
# 基础配置
# ==========================================================================
BASE_DIR   = os.path.abspath(os.path.dirname(__file__))
DATA_DIR   = os.path.join(BASE_DIR, 'data')
DB_FILE    = os.path.join(DATA_DIR, 'db.json')
QUOTA_FILE = os.path.join(DATA_DIR, 'quotas.json')
os.makedirs(DATA_DIR, exist_ok=True)


def _load_secret_key():
    """从 data/secret.key 读取密钥；不存在则随机生成并持久化。"""
    key_file = os.path.join(DATA_DIR, 'secret.key')

    env_key = os.environ.get('CLOUDDISK_SECRET_KEY')
    if env_key:
        return env_key

    if os.path.exists(key_file):
        try:
            with open(key_file, 'r', encoding='utf-8') as fh:
                key = fh.read().strip()
            if key:
                return key
        except OSError:
            pass

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
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


# ==========================================================================
# Cloudflare Access JWT 配置（可选）
# ==========================================================================
CF_ACCESS_TEAM_DOMAIN = os.environ.get('CF_ACCESS_TEAM_DOMAIN', '').strip()
CF_ACCESS_AUD = os.environ.get('CF_ACCESS_AUD', '').strip()

JWT_AVAILABLE = (
    _JWT_IMPORT_OK
    and bool(CF_ACCESS_TEAM_DOMAIN)
    and bool(CF_ACCESS_AUD)
)

_jwks_client = None
if JWT_AVAILABLE:
    try:
        _jwks_client = PyJWKClient(
            f'https://{CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs',
            cache_keys=True,
            lifespan=3600,
        )
        print("JWT ready")
    except Exception:
        _jwks_client = None
        JWT_AVAILABLE = False
        print("JWT service failed")
else:
    print("JWT not available")

# ==========================================================================
# JSON 数据库层
# ==========================================================================
_db_lock = threading.RLock()
_db      = None


def _empty_db():
    return {
        'users':        {},
        'nodes':        {},
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


class AttrDict(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


# ==========================================================================
# 配额管理
# ==========================================================================
_quota_lock  = threading.RLock()
_quota_cache = {'mtime': None, 'data': {}}


def _ensure_quota_file():
    if not os.path.exists(QUOTA_FILE):
        try:
            with open(QUOTA_FILE, 'w', encoding='utf-8') as fh:
                json.dump({}, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass


def load_quotas(force=False):
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
    if not username:
        return 0
    q = load_quotas().get(username, 0)
    try:
        q = int(q)
    except (TypeError, ValueError):
        q = 0
    return max(0, q)


def get_user_used(user_id):
    with _db_lock:
        nodes = list(load_db()['nodes'].values())
    return sum(
        n['size'] for n in nodes
        if n['user_id'] == user_id and not n['is_dir']
    )


def fmt_size(num):
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
    with _db_lock:
        return load_db()['users'].get(str(uid))


def user_get_by_name(username):
    with _db_lock:
        users = list(load_db()['users'].values())
    for u in users:
        if u['username'] == username:
            return u
    return None


def user_create(username, password):
    with _db_lock:
        db = load_db()
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
    with _db_lock:
        n = load_db()['nodes'].get(str(nid))
    if n is None:
        return None
    if user_id is not None and n['user_id'] != user_id:
        return None
    return n


def node_children(user_id, parent_id):
    with _db_lock:
        nodes = list(load_db()['nodes'].values())
    return [n for n in nodes
            if n['user_id'] == user_id and n['parent_id'] == parent_id]


def node_create(user_id, parent_id, name, is_dir=False,
                size=0, mime='', stored=''):
    with _db_lock:
        db = load_db()
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
        cur = node_get(cur['parent_id'])
    return list(reversed(chain))


def is_descendant(node, ancestor):
    cur = node
    while cur is not None:
        if cur['id'] == ancestor['id']:
            return True
        if cur['parent_id'] is None:
            return False
        cur = node_get(cur['parent_id'])
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
# 登录限速
# ==========================================================================
_login_attempts = {}
_login_lock = threading.Lock()
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300


def _client_ip():
    return (request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
            .split(',')[0].strip())


def _check_login_rate(ip):
    """只读检查，不计数。返回 True 表示允许尝试。"""
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip)
        if not rec or now - rec['first'] > LOGIN_WINDOW_SECONDS:
            return True
        return rec['count'] < LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip):
    now = time.time()
    with _login_lock:
        rec = _login_attempts.get(ip)
        if not rec or now - rec['first'] > LOGIN_WINDOW_SECONDS:
            _login_attempts[ip] = {'count': 1, 'first': now}
        else:
            rec['count'] += 1


def _reset_login_rate(ip):
    with _login_lock:
        _login_attempts.pop(ip, None)


# ==========================================================================
# 全局上传配额锁
# ==========================================================================
upload_quota_lock = threading.Lock()


# ==========================================================================
# Cloudflare Access JWT 工具
# ==========================================================================
def _get_cf_jwt():
    token = request.headers.get('Cf-Access-Jwt-Assertion')
    if token:
        return token
    return request.cookies.get('CF_Authorization')


def verify_cf_jwt(token):
    if not JWT_AVAILABLE or not token or _jwks_client is None:
        return None
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=CF_ACCESS_AUD,
            issuer=f'https://{CF_ACCESS_TEAM_DOMAIN}',
            options={'verify_exp': True},
        )
        return payload
    except Exception:
        return None


# ==========================================================================
# 请求钩子 / 装饰器
# ==========================================================================
@app.before_request
def _load_user():
    # ===== 临时调试，问题解决后删掉 =====
    # print("=" * 60)
    # print(f"PATH: {request.path}")
    # print(f"HEADER JWT: {'有' if request.headers.get('Cf-Access-Jwt-Assertion') else '无'}")
    # print(f"HEADER EMAIL: {request.headers.get('Cf-Access-Authenticated-User-Email') or '无'}")
    # print(f"COOKIE: {'有' if request.cookies.get('CF_Authorization') else '无'}")
    # # 1) 已有 session，直接加载
    uid = session.get('uid')
    if uid:
        u = user_get(uid)
        if u:
            g.user = AttrDict(u)
            g.pending_email = None
            return
        session.clear()

    g.pending_email = None
    verified_email = (request.headers.get('Cf-Access-Authenticated-User-Email') or '').strip().lower()
    if verified_email:
        u = user_get_by_name(verified_email)
        if u:
            session.clear()
            session['uid'] = u['id']
            g.user = AttrDict(u)
            return
        g.pending_email = verified_email
        g.user = None
        return

    # 2) 尝试从 Cloudflare Access JWT 自动登录
    g.pending_email = None
    if JWT_AVAILABLE:
        token = _get_cf_jwt()
        if token:
            payload = verify_cf_jwt(token)
            if payload:
                email = (payload.get('email') or '').strip().lower()
                if email:
                    u = user_get_by_name(email)
                    if u:
                        session.clear()
                        session['uid'] = u['id']
                        g.user = AttrDict(u)
                        return
                    g.pending_email = email
                    g.user = None
                    return

    g.user = None


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
        ip = _client_ip()

        if not _check_login_rate(ip):
            return render_template(
                'login.html',
                error='尝试次数过多，请 5 分钟后再试',
                mode='login',
                username=(request.form.get('username') or '').strip()
            )

        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        u = user_get_by_name(username)

        if u and check_password_hash(u['password_hash'], password):
            session.clear()
            session['uid'] = u['id']
            _reset_login_rate(ip)
            nxt = request.args.get('next') or url_for('files')
            return redirect(nxt)

        _record_login_failure(ip)
        return render_template('login.html', error='用户名或密码错误',
                               mode='login', username=username)
    verified = (request.headers.get('Cf-Access-Authenticated-User-Email') or '').strip().lower()
    if verified:
        return redirect("/")
    return render_template('login.html', mode='login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # 尝试从 JWT 取已认证邮箱
    jwt_email = None
    verified = (request.headers.get('Cf-Access-Authenticated-User-Email') or '').strip().lower()
    if verified:
        jwt_email = verified
    elif JWT_AVAILABLE:
        token = _get_cf_jwt()
        if token:
            payload = verify_cf_jwt(token)
            if payload:
                jwt_email = (payload.get('email') or '').strip().lower() or None

    # ---------- POST ----------
    if request.method == 'POST':
        # A. 有 JWT 邮箱 → "完成注册" 流程
        if jwt_email:
            password = request.form.get('password') or ''
            confirm  = request.form.get('confirm') or ''

            def fail(msg):
                return render_template('register.html', error=msg,
                                       locked_email=jwt_email, mode='complete')

            if len(password) < 8:
                return fail('密码至少 8 位')
            if password != confirm:
                return fail('两次密码不一致')

            existing = user_get_by_name(jwt_email)
            if existing:
                session.clear()
                session['uid'] = existing['id']
                return redirect(url_for('files'))

            u = user_create(jwt_email, password)
            session.clear()
            session['uid'] = u['id']
            return redirect(url_for('files'))

        # B. 无 JWT → 传统注册（回退）
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm  = request.form.get('confirm') or ''

        def fail(msg):
            return render_template('login.html', error=msg,
                                   mode='register', username=username)

        if len(username) < 2:
            return fail('用户名至少 2 个字符')
        if len(password) < 8:
            return fail('密码至少 8 位')
        if password != confirm:
            return fail('两次密码不一致')
        if user_get_by_name(username):
            return fail('用户名已存在')

        u = user_create(username, password)
        session.clear()
        session['uid'] = u['id']
        return redirect(url_for('files'))

    # ---------- GET ----------
    if jwt_email:
        existing = user_get_by_name(jwt_email)
        if existing:
            session.clear()
            session['uid'] = existing['id']
            return redirect(url_for('files'))
        return render_template('register.html',
                               locked_email=jwt_email, mode='complete')

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
        with _db_lock:
            all_nodes = list(load_db()['nodes'].values())
        items = [n for n in all_nodes
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
        with _db_lock:
            all_nodes = list(load_db()['nodes'].values())
        items = [n for n in all_nodes
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
    uid   = g.user['id']
    used  = get_user_used(uid)
    quota = get_user_quota(g.user['username'])

    with _db_lock:
        all_nodes = list(load_db()['nodes'].values())
    count = sum(1 for n in all_nodes
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
# API：上传
# ==========================================================================
MAX_SINGLE_FILE = 95 * 1024 * 1024  # 受 Cloudflare Tunnel 免费版 100MB 限制


@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    uid      = g.user['id']
    username = g.user['username']

    quota = get_user_quota(username)
    if quota <= 0:
        return jsonify(
            success=False,
            error='您的账号未分配上传配额，请联系管理员在 quotas.json 中为您分配空间。',
            code='NO_QUOTA'
        ), 403

    cl = request.content_length or 0
    if cl > MAX_SINGLE_FILE:
        return jsonify(
            success=False,
            error=f'单文件不能超过 {fmt_size(MAX_SINGLE_FILE)}',
            code='FILE_TOO_LARGE'
        ), 413

    with upload_quota_lock:
        used      = get_user_used(uid)
        remaining = max(0, quota - used)
        if remaining <= 0:
            return jsonify(
                success=False,
                error=f'存储空间已满（已用 {fmt_size(used)} / 配额 {fmt_size(quota)}）',
                code='QUOTA_EXCEEDED'
            ), 413

        if cl > remaining:
            return jsonify(
                success=False,
                error=(f'存储空间不足。剩余 {fmt_size(remaining)}，'
                       f'本文件约 {fmt_size(cl)}。'),
                code='QUOTA_EXCEEDED'
            ), 413

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

        final_name = unique_name(uid, cur_pid, filename)
        stored     = uuid.uuid4().hex

        user_dir = os.path.join(DATA_DIR, str(uid))
        os.makedirs(user_dir, exist_ok=True)
        dst = os.path.join(user_dir, stored)
        f.save(dst)
        size = os.path.getsize(dst)

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

        # 服务端重新判断 MIME，不信任客户端的 f.mimetype
        safe_mime = mimetypes.guess_type(final_name)[0] or 'application/octet-stream'
        if safe_mime in ('text/html', 'image/svg+xml',
                         'application/xhtml+xml', 'text/xml'):
            safe_mime = 'application/octet-stream'

        n = node_create(uid, cur_pid, final_name, is_dir=False,
                        size=size, mime=safe_mime, stored=stored)

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

    # 服务端根据文件名重新判断 MIME，二次防御
    safe_mime = mimetypes.guess_type(n['name'])[0] or 'application/octet-stream'
    if safe_mime in ('text/html', 'image/svg+xml',
                     'application/xhtml+xml', 'text/xml'):
        safe_mime = 'application/octet-stream'

    resp = send_file(p, mimetype=safe_mime,
                     as_attachment=False,
                     download_name=n['name'],
                     conditional=True)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'"
    return resp


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

    uid   = g.user['id']
    quota = get_user_quota(g.user['username'])
    delta = new_size - old_size
    if delta > 0 and quota > 0:
        used = get_user_used(uid)
        if used + delta > quota:
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
# API：打包收集
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
# API：文件夹树
# ==========================================================================
@app.route('/api/tree')
@login_required
def api_tree():
    uid = g.user['id']
    with _db_lock:
        all_nodes = list(load_db()['nodes'].values())
    nodes = [n for n in all_nodes
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
    load_db()
    load_quotas()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)