'use strict';

// The token arrives in the URL fragment (never sent to the server or kept in
// history); sessionStorage keeps it for reloads of this tab only.
let token = '';
{
  const m = location.hash.match(/token=([0-9a-f]+)/);
  if (m) {
    token = m[1];
    try { sessionStorage.setItem('cg-token', token); } catch (e) {}
    history.replaceState(null, '', location.pathname);
  } else {
    try { token = sessionStorage.getItem('cg-token') || ''; } catch (e) {}
  }
}

const $ = (id) => document.getElementById(id);

// The theme follows the system unless the user picked one in the footer.
let theme = 'auto';
try { theme = localStorage.getItem('cg-theme') || 'auto'; } catch (e) {}
function applyTheme() {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  // In the app window the title bar follows the chosen theme.
  try { window.webkit.messageHandlers.claudeguard.postMessage(theme); } catch (e) {}
}
applyTheme();

const KIND = { ssh: 'SSH-сервер', socks5: 'SOCKS5-прокси', http: 'HTTP-прокси' };
const LINK = { ssh: 'SSH-туннель', socks5: 'SOCKS5', http: 'HTTP-прокси' };

const ICON = {
  check: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="m3 8.5 3.2 3.2L13 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  ok: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="m6 11.5 3.3 3.3L16.5 7.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 6.5v5.5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><circle cx="11" cy="15.5" r="1.3" fill="currentColor"/></svg>',
  busy: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 3.5a7.5 7.5 0 1 0 7.5 7.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  idle: '<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="6.5" stroke="currentColor" stroke-width="1.8"/><path d="M7.5 11h7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
  info: '<svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="7.25" stroke="currentColor" stroke-width="1.5"/><path d="M9 8v4.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="9" cy="5.6" r="1" fill="currentColor"/></svg>',
  arrow: '<svg width="16" height="10" viewBox="0 0 16 10" fill="none"><path d="M1 5h13m-3-3.5L14.5 5 11 8.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  line: '<svg width="30" height="10" viewBox="0 0 30 10" fill="none"><path d="M1 5h27" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>',
  broken: '<svg width="30" height="10" viewBox="0 0 30 10" fill="none"><path d="M1 5h27" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-dasharray="3 5"/></svg>',
  cross: '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="m3 3 8 8M11 3l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
};

let state = null;
let stateJSON = '';
let check = null;
let checking = false;
const testing = new Set();
let fwDraft = null;   // {allow, extra} while the user edits the kill switch
let fwBusy = false;
let fwError = '';

class AuthError extends Error {}

async function api(path, body, signal) {
  const opts = { headers: { 'X-Claudeguard-Token': token }, signal };
  if (body !== undefined) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) throw new AuthError(data.error || 'нет доступа');
  if (!r.ok) {
    const err = new Error(data.error || r.statusText);
    err.step = data.step;
    throw err;
  }
  return data;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function button(label, cls, onClick) {
  const b = el('button', cls, label);
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

// hideAuth drops user:pass@ from a proxy URL before showing it.
function hideAuth(target) {
  return target.replace(/\/\/[^@/]*@/, '//');
}

function activeProfile() {
  return state.profiles.find((p) => p.name === state.active) || null;
}

function fresh(rec) {
  return rec && state.tunnel && new Date(rec.at) >= new Date(state.tunnel.since);
}

function alternative() {
  const others = state.profiles.filter((p) => p.name !== state.active);
  return others.find((p) => p.test && p.test.ok) || others[0] || null;
}

// refresh polls the state; the page is rebuilt only when something changed,
// so keyboard focus is not lost every two seconds.
let removed = false; // uninstall was requested: the page is done

async function refresh(force) {
  if (removed) return;
  let next;
  try {
    next = await api('/api/state');
  } catch (e) {
    if (e instanceof AuthError) return showNoAuth();
    return;
  }
  const json = JSON.stringify(next);
  $('noauth').hidden = true;
  $('app').hidden = false;
  if (force === true || json !== stateJSON) {
    state = next;
    stateJSON = json;
    render();
  }
  autoTest();
}

function showNoAuth() {
  $('app').hidden = true;
  $('noauth').hidden = false;
}

async function runCheck() {
  if (checking) return;
  checking = true;
  renderKillSwitch();
  try { check = await api('/api/check'); check.at = new Date(); } catch (e) {}
  checking = false;
  renderKillSwitch();
}

async function test(name) {
  if (testing.has(name)) return;
  testing.add(name);
  render();
  try { await api('/api/test', { name }); } catch (e) {}
  testing.delete(name);
  await refresh();
}

// autoTest measures the active server as soon as its tunnel is up, so the
// status shows the real exit IP rather than "connected" on faith.
function autoTest() {
  const p = activeProfile();
  if (!p || testing.has(p.name)) return;
  const st = state.tunnel.state;
  if ((st === 'up' || st === 'direct') && !fresh(p.test)) test(p.name);
}

async function act(fn) {
  try { await fn(); } catch (e) { alert(e.message); }
  await refresh();
}

function activate(name) {
  act(() => api('/api/activate', { name }));
}

function render() {
  if (!state) return;
  renderStatus();
  renderServers();
  renderKillSwitch();
  renderBrowser();
  $('ver').textContent = `Claudeguard ${state.version}, прокси на ${state.listen}`;
}

function renderStatus() {
  const p = activeProfile();
  const st = state.tunnel.state;
  const rec = p && p.test;
  const badge = $('st-badge');
  const actions = $('st-actions');
  actions.replaceChildren();
  $('st-error').hidden = true;

  const setBadge = (kind) => {
    badge.className = 'badge ' + kind;
    badge.innerHTML = ICON[kind === 'busy' ? 'busy' : kind === 'ok' ? 'ok' : kind === 'warn' ? 'warn' : 'idle'];
  };
  const showError = (text) => {
    if (!text) return;
    $('st-error').textContent = text;
    $('st-error').hidden = false;
  };
  const alt = alternative();
  const switchBtn = () => {
    if (alt) actions.append(button(`Переключиться на ${alt.name}`, 'btn primary', () => activate(alt.name)));
  };
  let broken = false;

  if (!p) {
    setBadge('idle');
    $('st-title').textContent = 'Сервер не выбран';
    $('st-detail').textContent = state.profiles.length
      ? 'Выберите сервер в списке ниже. Пока он не выбран, Claude офлайн и напрямую не пойдёт.'
      : 'Добавьте сервер, через который Claude будет выходить в сеть. Пока его нет, Claude офлайн.';
    if (!state.profiles.length) actions.append(button('Добавить сервер', 'btn primary', () => openSheet(null)));
    broken = true;
  } else if (st === 'starting') {
    setBadge('busy');
    $('st-title').textContent = `Подключаюсь к ${p.name}…`;
    $('st-detail').textContent = 'Поднимаю SSH-туннель. Пока его нет, Claude ждёт и напрямую не пойдёт.';
  } else if (st === 'down') {
    setBadge('warn');
    $('st-title').textContent = `${p.name} не отвечает`;
    $('st-detail').textContent = 'Claude офлайн и в обход не пойдёт. Claudeguard переподключается сам каждые несколько секунд.';
    showError(state.tunnel.detail);
    switchBtn();
    actions.append(button('Повторить сейчас', 'btn', () => act(() => api('/api/restart', {}))));
    broken = true;
  } else if (fresh(rec) && !rec.ok && !testing.has(p.name)) {
    setBadge('warn');
    $('st-title').textContent = `${p.name} не пропускает к Anthropic`;
    $('st-detail').textContent = 'Сервер на связи, но запрос к api.anthropic.com через него не прошёл. Claude будет офлайн, пока это так.';
    showError(rec.error);
    switchBtn();
    actions.append(button('Проверить снова', 'btn', () => test(p.name)));
    broken = true;
  } else {
    setBadge('ok');
    $('st-title').textContent = `Подключено через ${p.name}`;
    $('st-detail').textContent = fresh(rec) && rec.ok
      ? `Выход в сеть с ${rec.exit_ip || 'неизвестного адреса'}, отклик ${rec.latency_ms} мс` + (rec.connect_ms ? `, новое соединение ${rec.connect_ms} мс` : '')
      : 'Проверяю, что Anthropic отвечает через этот сервер…';
    const relaunch = button('Перезапустить Claude', 'btn', () => {
      if (!confirm('Приложение Claude закроется и откроется снова, уже через прокси. Продолжить?')) return;
      act(() => api('/api/launch', {}));
    });
    relaunch.title = 'Нужно после установки: приложение Claude должно быть запущено через прокси';
    actions.append(relaunch);
  }
  renderRoute(p, broken);
}

function renderRoute(p, broken) {
  const route = $('route');
  route.replaceChildren();
  const here = state.os === 'darwin' ? 'Этот Mac' : 'Этот компьютер';
  const arrow = () => { const s = el('span', 'arrow'); s.innerHTML = ICON.arrow; return s; };
  route.append(el('span', 'node', 'Claude'), arrow(), el('span', 'node', here));
  const link = el('span', 'link' + (broken ? ' broken' : ''));
  if (broken) {
    link.innerHTML = ICON.broken + ICON.cross;
    link.append(p ? 'нет связи' : 'сервер не выбран');
    link.insertAdjacentHTML('beforeend', ICON.broken);
  } else {
    link.innerHTML = ICON.line;
    link.append(LINK[p.kind]);
    link.insertAdjacentHTML('beforeend', ICON.line);
  }
  route.append(link);
  if (p) route.append(el('span', 'node ' + (broken ? 'dim' : 'exit'), p.name));
  if (!broken) route.append(arrow());
  route.append(el('span', 'node' + (broken ? ' dim' : ''), 'Anthropic'));
  route.setAttribute('aria-label', broken
    ? 'Маршрут оборван: Claude офлайн'
    : `Маршрут: Claude, ${here}, ${LINK[p.kind]}, ${p.name}, Anthropic`);
}

const UNTRUSTED = /Host key verification failed/i;

// sshReason turns common ssh failures into something a person can act on.
function sshReason(err, p) {
  if (!err) return 'Не отвечает';
  if (UNTRUSTED.test(err)) return 'Ключ хоста не подтверждён';
  if (/Permission denied/i.test(err)) return 'Нет входа по ключу';
  if (/Could not resolve hostname/i.test(err)) return 'Хост не найден';
  return 'Не отвечает';
}

function resultText(p) {
  if (testing.has(p.name)) return ['Проверяю…', ''];
  if (p.name === state.active && state.tunnel.state === 'down') return [sshReason(state.tunnel.detail, p), 'bad'];
  if (!p.test) return ['Не проверялся', ''];
  if (!p.test.ok) return [sshReason(p.test.error, p), 'bad'];
  const ip = p.test.exit_ip ? `, ${p.test.exit_ip}` : '';
  return [`${p.test.latency_ms} мс${ip}`, 'ok'];
}

function renderServers() {
  const list = $('servers');
  list.replaceChildren();
  list.setAttribute('role', 'radiogroup');
  list.setAttribute('aria-labelledby', 'servers-h');
  if (!state.profiles.length) {
    const li = el('li', 'empty', 'Серверов пока нет. Добавьте SSH-хост, к которому есть доступ по ключу, или готовый SOCKS5/HTTP-прокси.');
    list.append(li);
  }
  for (const p of state.profiles) {
    const li = el('li');
    const row = el('div', 'row server');
    const pick = el('button', 'pick');
    pick.type = 'button';
    pick.setAttribute('role', 'radio');
    pick.setAttribute('aria-checked', String(p.name === state.active));
    const check = el('span', 'check');
    check.innerHTML = ICON.check;
    const names = el('span', 'names');
    names.append(el('span', 'name', p.name));
    let sub = `${KIND[p.kind]}, ${hideAuth(p.target)}`;
    if (p.kind === 'ssh') {
      const where = (p.user ? p.user + '@' : '') + p.target + (p.port ? ':' + p.port : '');
      sub = where === p.name ? KIND.ssh : `${KIND.ssh}, ${where}`;
    }
    names.append(el('span', 'kind', sub));
    pick.append(check, names);
    pick.addEventListener('click', () => { if (p.name !== state.active) activate(p.name); });

    const [text, cls] = resultText(p);
    const result = el('span', 'result ' + cls, text);
    const err = p.name === state.active && state.tunnel.state === 'down' ? state.tunnel.detail : p.test && !p.test.ok && p.test.error;
    if (err) result.title = err;

    const testBtn = button('Проверить', 'btn small', () => test(p.name));
    testBtn.disabled = testing.has(p.name);
    testBtn.setAttribute('aria-label', `Проверить ${p.name}`);
    const edit = button('', 'iconbtn', () => openSheet(p));
    edit.innerHTML = ICON.info;
    edit.setAttribute('aria-label', `Изменить ${p.name}`);

    row.append(pick, result, testBtn, edit);
    li.append(row);
    if (p.kind === 'ssh' && err && UNTRUSTED.test(err)) {
      const box = hostKeyBox(p);
      if (box) li.append(box);
    }
    list.append(li);
  }
  $('test-all').hidden = state.profiles.length < 2;
}

function renderKillSwitch() {
  if (!state) return;
  const ks = $('ks-state');
  const detail = $('ks-detail');
  const notInstalled = check && /not/i.test(check.firewall);
  if (!check) {
    ks.className = 'small strong';
    ks.textContent = checking ? 'Проверяю…' : '';
    detail.textContent = 'Проверяю, можно ли пройти к Anthropic напрямую';
  } else if (notInstalled) {
    ks.className = 'small strong warn-text';
    ks.textContent = 'Не установлен';
    detail.textContent = 'Правила брандмауэра не стоят. Нажмите «Применить», чтобы включить защиту.';
  } else if (check.blocked) {
    ks.className = 'small strong ok-text';
    ks.textContent = 'Включён';
    detail.textContent = 'Напрямую к Anthropic не пройти, проверено в ' + check.at.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  } else if (state.allow_tunnels) {
    ks.className = 'small strong ok-text';
    ks.textContent = 'Через VPN';
    detail.textContent = 'Сейчас включён VPN, и Claude может идти через него. Без VPN прямой путь закрыт.';
  } else {
    ks.className = 'small strong warn-text';
    ks.textContent = 'Пропускает';
    detail.textContent = 'Claude может пойти к Anthropic напрямую, минуя прокси. Нажмите «Применить», чтобы восстановить правила.';
  }

  const saved = { allow: state.allow_tunnels, extra: (state.extra_block || []).join(', ') };
  const draft = fwDraft || saved;
  const tun = $('tun');
  tun.setAttribute('aria-checked', String(draft.allow));
  const extra = $('extra');
  if (document.activeElement !== extra) extra.value = draft.extra;

  const dirty = fwDraft && (fwDraft.allow !== saved.allow || fwDraft.extra.trim() !== saved.extra);
  const needs = dirty || notInstalled || (check && !check.blocked && !state.allow_tunnels);
  $('fw-bar').hidden = !needs && !fwBusy && !fwError;
  $('fw-cancel').hidden = !dirty;
  $('fw-apply').disabled = fwBusy;
  $('fw-apply').textContent = fwBusy ? 'Применяю…' : 'Применить';
  const note = $('fw-note');
  if (fwError) {
    note.className = 'err small';
    note.textContent = fwError;
  } else {
    note.className = 'muted small';
    note.textContent = state.os === 'windows'
      ? 'Windows попросит подтверждение администратора.'
      : 'macOS попросит пароль администратора. Открытые соединения Claude с Anthropic оборвутся и тут же переподключатся.';
  }
}

let brBusy = false;
let brError = '';

function renderBrowser() {
  const sw = $('br');
  if (!brBusy) sw.setAttribute('aria-checked', String(!!state.browser_proxy));
  sw.disabled = brBusy;
  const note = $('br-note');
  if (brError) {
    note.className = 'err small';
    note.textContent = `${brError} Адрес для ручной настройки: ${state.pac_url}`;
  } else {
    note.className = 'muted small';
    note.textContent = state.browser_proxy
      ? 'claude.ai и другие сайты Anthropic идут через сервер выше, остальные сайты — как обычно. Если страница была открыта, обновите её.'
      : 'claude.ai в браузере сейчас закрыт kill switch. Включите, и сайты Claude пойдут через сервер выше; остальные сайты это не затронет.';
  }
}

async function toggleBrowser() {
  const on = $('br').getAttribute('aria-checked') !== 'true';
  brBusy = true;
  brError = '';
  $('br').setAttribute('aria-checked', String(on));
  renderBrowser();
  try {
    await api('/api/browser', { on });
  } catch (e) {
    brError = e.message;
  }
  brBusy = false;
  await refresh(true);
}

function editDraft(change) {
  const saved = { allow: state.allow_tunnels, extra: (state.extra_block || []).join(', ') };
  fwDraft = Object.assign({}, fwDraft || saved, change);
  fwError = '';
  renderKillSwitch();
}

async function applyFirewall() {
  const d = fwDraft || { allow: state.allow_tunnels, extra: (state.extra_block || []).join(', ') };
  fwBusy = true;
  fwError = '';
  renderKillSwitch();
  try {
    await api('/api/firewall', { allow_tunnels: d.allow, extra_block: d.extra });
    fwDraft = null;
  } catch (e) {
    fwError = e.message;
  }
  fwBusy = false;
  await refresh();
  check = null;
  runCheck();
}

// --- host key of a server already in the list ---

const hostKeys = new Map(); // name -> {key, error, hidden}

function hostKeyBox(p) {
  let hk = hostKeys.get(p.name);
  if (!hk) {
    hk = {};
    hostKeys.set(p.name, hk);
    api('/api/hostkey', { name: p.name })
      .then((key) => { hk.key = key; }, (e) => { hk.error = e.message; })
      .then(render);
  }
  if (hk.hidden || (!hk.key && !hk.error)) return null;
  const box = el('div', 'expand');
  if (hk.error) {
    box.append(el('span', 'muted small', hk.error));
    return box;
  }
  if (hk.key.status === 'known') return null;
  const fp = el('div', 'fp onrow');
  fp.append(el('span', 'k', `${hk.key.address}, ${keyName(hk.key.key_type)}`), el('code', '', hk.key.fingerprint));
  box.append(fp);
  if (hk.key.status === 'changed') {
    box.append(el('span', 'warn-strong small', 'Сервер отвечает другим ключом, чем раньше. Так бывает после переустановки, но так же выглядит перехват соединения. Claudeguard к нему не подключится.'));
    return box;
  }
  const acts = el('div', 'actions');
  acts.append(
    button('Доверять ключу', 'btn primary', async () => {
      try {
        await api('/api/trust', { address: hk.key.address, fingerprint: hk.key.fingerprint });
      } catch (e) { alert(e.message); }
      hostKeys.delete(p.name);
      test(p.name);
    }),
    button('Не сейчас', 'btn', () => { hk.hidden = true; render(); }),
  );
  box.append(acts);
  return box;
}

function keyName(type) {
  return type.replace(/^ssh-/, '').replace(/^ecdsa-sha2-.*/, 'ecdsa').toUpperCase();
}

// --- add / edit sheet, and the setup of a new SSH server ---

const sheet = { old: null, orig: null, kind: 'ssh', mode: 'new', nameTouched: false, key: null, abort: null, poll: 0, name: '' };
const VIEWS = ['form', 'key', 'run', 'done', 'changed'];
const STEPS = ['Ключ хоста подтверждён', 'Вход по паролю', 'Ключ Claudeguard на сервере', 'Сервер пускает туннели', 'Вход по ключу и путь до Anthropic'];

function showView(v) {
  for (const name of VIEWS) $('v-' + name).hidden = name !== v;
}

function openSheet(p) {
  sheet.old = p ? p.name : null;
  sheet.orig = p;
  sheet.kind = p ? p.kind : 'ssh';
  sheet.mode = 'new';
  sheet.nameTouched = !!p;
  $('sheet-h').textContent = p ? p.name : 'Новый сервер';
  $('sheet-del').hidden = !p;
  $('host').value = p && p.kind === 'ssh' ? p.target : '';
  $('addr').value = p && p.kind !== 'ssh' ? p.target : '';
  $('pname').value = p ? p.name : '';
  $('n-host').value = '';
  $('n-user').value = 'root';
  $('n-port').value = '22';
  $('n-pass').value = '';
  formError('');
  showView('form');
  renderSheet();
  $('sheet').showModal();
  focusSheet();
}

function setupMode() {
  return !sheet.old && sheet.kind === 'ssh' && sheet.mode === 'new';
}

function focusSheet() {
  (setupMode() ? $('n-host') : sheet.kind === 'ssh' ? $('host') : $('addr')).focus();
}

function formError(text, hint) {
  $('sheet-err').textContent = text;
  $('sheet-err').hidden = !text;
  $('sheet-err-hint').textContent = hint || '';
  $('sheet-err-hint').hidden = !hint;
}

function renderSheet() {
  for (const b of document.querySelectorAll('.seg button')) {
    b.setAttribute('aria-checked', String(b.dataset.kind === sheet.kind));
  }
  for (const b of document.querySelectorAll('#ssh-mode button')) {
    b.setAttribute('aria-checked', String(b.dataset.mode === sheet.mode));
  }
  const setup = setupMode();
  $('ssh-mode').hidden = !!sheet.old || sheet.kind !== 'ssh';
  $('f-new').hidden = !setup;
  $('f-ssh').hidden = sheet.kind !== 'ssh' || setup;
  $('f-proxy').hidden = sheet.kind === 'ssh';
  $('sheet-ok').textContent = sheet.old ? 'Сохранить' : setup ? 'Подключить' : 'Добавить';
  $('addr').placeholder = sheet.kind === 'http' ? 'http://proxy.example.com:3128' : 'socks5://127.0.0.1:1080';
  $('addr-hint').textContent = 'Логин и пароль, если нужны, пишутся в адресе: '
    + (sheet.kind === 'http' ? 'http://логин:пароль@хост:порт' : 'socks5://логин:пароль@хост:порт');
  const o = sheet.orig;
  if (o && o.kind === sheet.kind && /\/\/[^@/]+@/.test(o.target)) {
    $('addr-hint').textContent = 'Пароль сохранён и сюда не выводится. Чтобы сменить его, впишите в адрес: логин:пароль@хост:порт';
  }
  $('ssh-hint').textContent = o && o.managed
    ? `Настроен в Claudeguard: вход по его ключу${o.user ? ', пользователь ' + o.user : ''}${o.port ? ', порт ' + o.port : ''}.`
    : 'Нужен вход по ключу без пароля: Claudeguard сам держит туннель ssh -D и переподключает его.';

  const used = new Set(state.profiles.filter((p) => p.kind === 'ssh' && p.name !== sheet.old).map((p) => p.target));
  const hosts = (state.ssh_hosts || []).filter((h) => !used.has(h));
  $('mode-config-hint').textContent = hosts.length
    ? hosts.slice(0, 3).join(', ') + (hosts.length > 3 ? ` и ещё ${hosts.length - 3}` : '')
    : 'Вход по ключу уже работает';
  const chips = $('chips');
  chips.replaceChildren();
  for (const h of hosts) {
    const c = button(h, '', () => {
      $('host').value = h;
      if (!sheet.nameTouched) $('pname').value = h;
      renderSheet();
    });
    c.setAttribute('aria-pressed', String($('host').value === h));
    chips.append(c);
  }
  $('chips-label').hidden = !hosts.length;
}

function sheetProfile() {
  const kind = sheet.kind;
  let target = kind === 'ssh' ? $('host').value.trim() : $('addr').value.trim();
  if (kind !== 'ssh' && target && !/^[a-z0-9]+:\/\//i.test(target)) target = kind + '://' + target;
  let name = $('pname').value.trim();
  if (!name && kind === 'ssh') name = target;
  if (!name && target) {
    try { name = new URL(target).hostname; } catch (e) {}
  }
  const profile = { name, kind, target };
  // Renaming a server set up here must not lose how to log in to it.
  const o = sheet.orig;
  if (o && o.kind === 'ssh' && kind === 'ssh' && o.target === target) {
    Object.assign(profile, { user: o.user, port: o.port, managed: o.managed });
  }
  return profile;
}

async function saveSheet() {
  if (setupMode()) return startSetup();
  const profile = sheetProfile();
  if (!profile.target) {
    formError(sheet.kind === 'ssh' ? 'Укажите SSH-хост.' : 'Укажите адрес прокси.');
    return;
  }
  try {
    await api('/api/profile', { old: sheet.old || '', profile });
  } catch (e) {
    formError(e.message);
    return;
  }
  $('sheet').close();
  await refresh();
  test(profile.name);
}

function setupRequest() {
  const host = $('n-host').value.trim();
  return {
    host,
    port: Number($('n-port').value.trim() || '22'),
    user: $('n-user').value.trim() || 'root',
    name: $('pname').value.trim() || host,
  };
}

async function startSetup() {
  const req = setupRequest();
  if (!req.host) return formError('Укажите адрес сервера.');
  if (!Number.isInteger(req.port) || req.port < 1 || req.port > 65535) return formError('Порт должен быть числом от 1 до 65535.');
  if (!$('n-pass').value) return formError('Введите пароль.');
  if (state.profiles.some((p) => p.name === req.name)) return formError(`Сервер «${req.name}» уже есть. Задайте другое название.`);
  formError('');
  sheet.name = req.name;
  const ok = $('sheet-ok');
  ok.disabled = true;
  ok.textContent = 'Проверяю сервер…';
  let key;
  try {
    // No name: with one, the server looks the host up among saved servers.
    key = await api('/api/hostkey', { host: req.host, port: req.port, user: req.user });
  } catch (e) {
    formError(e.message);
    return;
  } finally {
    ok.disabled = false;
    renderSheet();
  }
  sheet.key = key;
  if (key.status === 'known') return runSetup();
  if (key.status === 'changed') {
    $('changed-badge').innerHTML = ICON.warn;
    $('changed-text').textContent = `${req.host} отвечает другим ключом, чем раньше. Так бывает после переустановки сервера, но так же выглядит и перехват соединения.`;
    $('changed-fp').textContent = key.fingerprint;
    showView('changed');
    $('changed-ok').focus();
    return;
  }
  $('key-text').textContent = `Claudeguard подключается к ${req.host} впервые. Сверьте отпечаток ключа с тем, что показывает сам сервер. Если они совпадают, соединение никто не подменил.`;
  $('key-type').textContent = `${keyName(key.key_type)}, порт ${req.port}`;
  $('key-fp').textContent = key.fingerprint;
  $('key-cmd').textContent = `ssh-keygen -lf /etc/ssh/ssh_host_${keyName(key.key_type).toLowerCase()}_key.pub`;
  $('key-err').hidden = true;
  showView('key');
  $('key-trust').focus();
}

async function trustAndSetup() {
  $('key-trust').disabled = true;
  try {
    await api('/api/trust', { address: sheet.key.address, fingerprint: sheet.key.fingerprint });
  } catch (e) {
    $('key-err').textContent = e.message;
    $('key-err').hidden = false;
    return;
  } finally {
    $('key-trust').disabled = false;
  }
  runSetup();
}

// renderSteps draws the checklist: `done` steps are finished, the next one
// is either running or, with failed set, the one that went wrong.
function renderSteps(done, failed) {
  const list = $('run-steps');
  list.replaceChildren();
  STEPS.forEach((label, i) => {
    const cls = i < done ? 'done' : i > done ? 'wait' : failed ? 'fail' : 'busy';
    const li = el('li', cls);
    const dot = el('span', 'dot');
    if (cls === 'done') dot.innerHTML = ICON.check;
    if (cls === 'fail') dot.innerHTML = ICON.warn;
    li.append(dot, el('span', '', label));
    list.append(li);
  });
}

function stopSetup() {
  clearInterval(sheet.poll);
  sheet.poll = 0;
  if (sheet.abort) sheet.abort.abort();
  sheet.abort = null;
}

async function runSetup() {
  const req = Object.assign(setupRequest(), { password: $('n-pass').value });
  $('run-h').textContent = `Настраиваю ${req.name}`;
  $('run-err').hidden = true;
  $('run-note').hidden = false;
  $('run-retry').hidden = true;
  $('run-cancel').textContent = 'Отменить';
  $('sheet').setAttribute('aria-busy', 'true');
  let done = 1;
  renderSteps(done);
  showView('run');
  stopSetup();
  const abort = sheet.abort = new AbortController();
  sheet.poll = setInterval(async () => {
    try {
      const { step } = await api('/api/setup');
      if (sheet.abort === abort && step + 1 > done) { done = step + 1; renderSteps(done); }
    } catch (e) {}
  }, 400);
  let res, err;
  try {
    res = await api('/api/setup', req, abort.signal);
  } catch (e) {
    err = e;
  }
  if (sheet.abort !== abort) return; // cancelled or closed meanwhile
  stopSetup();
  $('sheet').removeAttribute('aria-busy');
  if (err) return setupFailed(err);
  $('n-pass').value = '';
  await refresh(true);
  setupDone(res);
}

function setupFailed(err) {
  const step = err.step || 0;
  if (step === 0 && /^пароль не подошёл/i.test(err.message)) {
    const [head, ...rest] = err.message.split('. ');
    showView('form');
    formError(head.charAt(0).toUpperCase() + head.slice(1) + '.', rest.join('. '));
    $('n-pass').value = '';
    $('n-pass').focus();
    return;
  }
  renderSteps(step + 1, true);
  $('run-err').textContent = err.message.charAt(0).toUpperCase() + err.message.slice(1) + '.';
  $('run-err').hidden = false;
  $('run-note').hidden = true;
  $('run-retry').hidden = false;
  $('run-cancel').textContent = 'Назад';
  $('run-retry').focus();
}

function setupDone(res) {
  const t = res.test || {};
  const facts = $('done-facts');
  facts.replaceChildren();
  const fact = (k, v) => facts.append(el('dt', '', k), el('dd', '', v));
  const p = state.profiles.find((x) => x.name === res.name) || {};
  if (t.ok) {
    $('done-badge').className = 'badge ok';
    $('done-badge').innerHTML = ICON.ok;
    $('done-h').textContent = `${res.name} работает`;
    $('done-text').textContent = 'Сервер добавлен в список. Пароль больше не нужен: дальше Claudeguard входит по своему ключу.';
    if (t.exit_ip) fact('IP выхода', t.exit_ip);
    fact('Отклик до Anthropic', `${t.latency_ms} мс`);
  } else {
    $('done-badge').className = 'badge warn';
    $('done-badge').innerHTML = ICON.warn;
    $('done-h').textContent = `${res.name} добавлен, но проверка не прошла`;
    $('done-text').textContent = 'Ключ на сервере стоит, но запрос к Anthropic через туннель не прошёл. Попробуйте «Проверить» в списке серверов.';
    fact('Ошибка', t.error || 'нет ответа');
  }
  fact('Вход', `${p.user || 'root'}, ключ Claudeguard`);
  $('done-use').hidden = !t.ok || state.active === res.name;
  showView('done');
  ($('done-use').hidden ? $('done-close') : $('done-use')).focus();
}

async function deleteFromSheet() {
  const name = sheet.old;
  const msg = name === state.active
    ? `Удалить ${name}? Это активный сервер: Claude останется офлайн, пока вы не выберете другой.`
    : `Удалить ${name}?`;
  if (!confirm(msg)) return;
  $('sheet').close();
  act(() => api('/api/delete', { name }));
}

function renderTheme() {
  for (const b of document.querySelectorAll('#theme button')) {
    b.setAttribute('aria-checked', String(b.dataset.theme === theme));
  }
}

// --- wiring ---

document.addEventListener('DOMContentLoaded', () => {
  renderTheme();
  for (const b of document.querySelectorAll('#theme button')) {
    b.addEventListener('click', () => {
      theme = b.dataset.theme;
      try { localStorage.setItem('cg-theme', theme); } catch (e) {}
      applyTheme();
      renderTheme();
    });
  }
  if (!token) return showNoAuth();

  $('add').addEventListener('click', () => openSheet(null));
  $('test-all').addEventListener('click', () => state.profiles.forEach((p) => test(p.name)));
  $('recheck').addEventListener('click', () => { check = null; runCheck(); });
  $('uninstall').addEventListener('click', async () => {
    if (!confirm('Удалить Claudeguard? Kill switch, фоновый прокси, значок и сама программа будут убраны, настройки Claude Code вернутся к прежним, ключ Claudeguard будет снят с серверов, настроенных в панели. Claude снова пойдёт напрямую. Понадобится пароль администратора.')) return;
    try {
      await api('/api/uninstall', {});
      removed = true;
      document.querySelector('main').replaceChildren(el('p', 'foot', 'Claudeguard удаляется: подтвердите действие паролем администратора в системном окне. Это окно закроется само.'));
    } catch (e) { alert(e.message); }
  });
  $('tun').addEventListener('click', () => editDraft({ allow: $('tun').getAttribute('aria-checked') !== 'true' }));
  $('br').addEventListener('click', toggleBrowser);
  $('extra').addEventListener('input', () => editDraft({ extra: $('extra').value }));
  $('fw-cancel').addEventListener('click', () => { fwDraft = null; fwError = ''; renderKillSwitch(); });
  $('fw-apply').addEventListener('click', applyFirewall);

  for (const b of document.querySelectorAll('.seg button')) {
    b.addEventListener('click', () => { sheet.kind = b.dataset.kind; formError(''); renderSheet(); });
  }
  for (const b of document.querySelectorAll('#ssh-mode button')) {
    b.addEventListener('click', () => { sheet.mode = b.dataset.mode; formError(''); renderSheet(); focusSheet(); });
  }
  $('host').addEventListener('input', () => {
    if (!sheet.nameTouched) $('pname').value = $('host').value.trim();
    renderSheet();
  });
  $('n-host').addEventListener('input', () => {
    if (!sheet.nameTouched) $('pname').value = $('n-host').value.trim();
  });
  $('pname').addEventListener('input', () => { sheet.nameTouched = $('pname').value.trim() !== ''; });
  $('sheet-cancel').addEventListener('click', () => $('sheet').close());
  $('sheet-ok').addEventListener('click', saveSheet);
  $('sheet-del').addEventListener('click', deleteFromSheet);
  $('v-form').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); saveSheet(); }
  });
  $('key-back').addEventListener('click', () => { showView('form'); focusSheet(); });
  $('key-trust').addEventListener('click', trustAndSetup);
  $('run-cancel').addEventListener('click', () => { stopSetup(); showView('form'); focusSheet(); });
  $('run-retry').addEventListener('click', runSetup);
  $('done-close').addEventListener('click', () => $('sheet').close());
  $('done-use').addEventListener('click', () => { $('sheet').close(); activate(sheet.name); });
  $('changed-ok').addEventListener('click', () => { showView('form'); focusSheet(); });
  // However the sheet closes, the password and a running setup go with it.
  $('sheet').addEventListener('close', () => { stopSetup(); $('n-pass').value = ''; });

  refresh().then(runCheck);
  setInterval(refresh, 2000);
  setInterval(runCheck, 60000);
});
