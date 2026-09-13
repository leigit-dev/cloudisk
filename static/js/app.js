/* ============================================================
   static/js/app.js  —  全局工具
   ============================================================ */

/* ---------- 主题 ---------- */
(function initTheme() {
  const btn = document.getElementById('themeBtn');
  const sync = () => {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (btn) btn.textContent = dark ? '☀️' : '🌙';
  };
  sync();

  if (btn && !btn.dataset.bound) {
    btn.dataset.bound = '1';
    btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme');
      const next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('cd_theme', next); } catch (e) {}
      sync();
    });
  }

  // 跟随系统（仅当用户未手动设置过）
  try {
    if (!localStorage.getItem('cd_theme') &&
        window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.documentElement.setAttribute('data-theme', 'dark');
      sync();
    }
  } catch (e) {}
})();

/* ---------- 体积格式化 ---------- */
function fmtSize(bytes) {
  if (bytes === null || bytes === undefined) return '0 B';
  const n = Number(bytes);
  if (isNaN(n)) return '0 B';
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 ? 0 : 1) + ' ' + units[i];
}

/* ---------- Toast ---------- */
function showToast(msg, type) {
  let host = document.getElementById('toastHost');
  if (!host) {
    host = document.createElement('div');
    host.id = 'toastHost';
    host.className = 'toast-host';
    document.body.appendChild(host);
  }
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = msg;
  host.appendChild(el);

  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 260);
  }, 2600);
}

/* ---------- 防抖 ---------- */
function debounce(fn, wait) {
  let t = null;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), wait);
  };
}

/* ---------- 导出到全局 ---------- */
window.fmtSize = fmtSize;
window.showToast = showToast;
window.debounce = debounce;