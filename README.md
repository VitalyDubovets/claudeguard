# claudeguard

Пускает Claude (десктоп-приложение и Claude Code) через выбранный прокси или VPN. Если прокси или VPN упали, Claude остаётся без сети и не уходит напрямую (kill switch).

macOS и Windows, один бинарник на Go без зависимостей. Серверы переключаются в локальной панели настроек, без перезапуска Claude.

## Как это устроено

Защита из двух слоёв:

1. **Kill switch в системном файрволе.** Все прямые соединения к сетям Anthropic запрещены:
   `160.79.104.0/21`, `153.61.208.0/20`, `153.61.224.0/22`, `2607:6bc0::/48`
   ([официальный список](https://platform.claude.com/docs/en/api/ip-addresses)). На них живут claude.ai, api.anthropic.com и эндпоинты Claude Code.
   - macOS: правила pf в анкере `com.apple/claudeguard`. `/etc/pf.conf` не меняется. LaunchDaemon восстанавливает правила при загрузке и проверяет их каждые 15–60 с.
   - Windows: правило Windows Firewall в группе `claudeguard`. Правила блокировки там сильнее правил разрешения, а сами правила переживают перезагрузку.

   Это правила ОС, а не процесс. Если claudeguard упадёт, Claude обновится или кто-то запустит его в обход лаунчера, прямого пути к Anthropic всё равно нет.

2. **Локальный HTTP-прокси** `127.0.0.1:41080` → активный сервер из списка (SSH-хост, `socks5://` или `http://`). Нужен потому, что Claude Code не умеет работать с SOCKS. Имена хостов уходят в upstream нерезолвленными, так что DNS для Claude резолвится на стороне прокси. Если upstream недоступен, мост отвечает 502 и напрямую не ходит.
   - Claude Code: в `~/.claude/settings.json` → `env` прописываются `HTTPS_PROXY` и `HTTP_PROXY`. Исходный файл сохраняется в `settings.json.claudeguard.bak`.
   - Десктоп: ярлык «Claude via Proxy» перезапускает приложение с `--proxy-server=http://127.0.0.1:41080`. Chromium с этим флагом напрямую не ходит.

### Режимы

| Режим | Флаг | Что разрешено к Anthropic |
|---|---|---|
| Только прокси | (по умолчанию) | только через прокси. С любого интерфейса напрямую нельзя, даже через VPN |
| Прокси или VPN | `--allow-tunnels` | через прокси и через VPN-интерфейсы (`utun*`, `ipsec*`, `ppp*`, `wg*`…). VPN отключился → блок |

Если Claude ходит через системный VPN (например, AmneziaWG), нужен `--allow-tunnels`. Без него прямой трафик в VPN тоже режется, и работает только путь через прокси.

## Установка

> **Во время `install` текущие соединения Claude к Anthropic рвутся** (pf сбрасывает их, чтобы старые не продолжали идти напрямую). С `--allow-tunnels` и включённым VPN Claude сам переподключится. Без этого флага перезапусти его через «Claude via Proxy».

### macOS

```bash
chmod +x claudeguard-darwin-arm64
./claudeguard-darwin-arm64 install --ssh vd-poland --allow-tunnels
```

`--ssh HOST` добавляет сервер и делает его активным. Для SSH-сервера claudeguard сам держит `ssh -N -D 127.0.0.1:<свободный порт> HOST`: поднимает при старте и перезапускает после сна, смены сети или обрыва. Нужен вход по ключу без интерактивного пароля (`BatchMode=yes`), и ключ хоста уже должен быть в `known_hosts` (один раз зайди `ssh HOST` руками). Если прокси уже есть, вместо `--ssh` укажи `--upstream socks5://host:port` или `--upstream http://host:port`. Можно не указывать ничего и добавить серверы потом в панели.

Один раз спросит пароль администратора: через sudo ставятся `/usr/local/bin/claudeguard`, LaunchDaemon и правила pf. Дальше:

- прокси работает как LaunchAgent `com.claudeguard.proxy`, лог в `~/Library/Logs/claudeguard.log`;
- в `~/Applications` появляются «Claude via Proxy.app» (запускай Claude через него) и «Claudeguard.app» (панель настроек).

### Windows (PowerShell, без прав администратора; UAC спросит сам)

```powershell
.\claudeguard-windows-amd64.exe install --ssh vd-poland --allow-tunnels
```

- Бинарник копируется в `%LOCALAPPDATA%\claudeguard`, прокси стартует при входе в систему (ключ `HKCU\...\Run`).
- Ярлыки «Claude via Proxy» и «Claudeguard» (панель настроек) появляются на рабочем столе и в меню «Пуск».
- `--ssh` использует встроенный OpenSSH (`ssh.exe`, есть в Windows 10/11). Ключ должен лежать в `%USERPROFILE%\.ssh`.
- `--allow-tunnels` на Windows вешает блок только на физические адаптеры (`Get-NetAdapter -Physical`), так что Wintun/TAP (WireGuard, AmneziaWG, OpenVPN) остаются разрешены. Адаптер, подключённый позже (USB-модем, новая сетевая карта), не покрыт, пока не выполнишь `claudeguard enable --allow-tunnels` ещё раз.
- Нужен включённый Windows Firewall. Если его заменил сторонний файрвол, правило не действует, и `install` об этом предупредит.

## Панель настроек

```bash
claudeguard ui
```

Открывает в браузере `http://127.0.0.1:41080/ui` (или запусти «Claudeguard.app» / ярлык «Claudeguard»). Если прокси не запущен, `ui` запустит его сам. В панели:

- **Состояние:** через какой сервер сейчас идёт Claude, IP выхода и отклик до Anthropic. Если сервер не отвечает, видно ошибку ssh и кнопку переключиться на другой.
- **Серверы:** список, нажатие на строку делает сервер активным. Переключение мгновенное, Claude перезапускать не нужно: мост берёт новый сервер для каждого нового соединения. «Проверить» поднимает временный туннель и меряет отклик и IP выхода, не трогая активный сервер. «Добавить сервер…» подсказывает хосты из `~/.ssh/config`.
- **Защита:** состояние kill switch (панель сама пробует достучаться до Anthropic напрямую), переключатель «Пускать через VPN» (`--allow-tunnels`) и дополнительные сети. «Применить» просит пароль администратора и переустанавливает правила.
- «Перезапустить Claude» закрывает приложение и открывает его через прокси, то же самое, что «Claude via Proxy».

Типы серверов:

- SSH-хост: алиас из `~/.ssh/config` или `user@host`. Туннель claudeguard держит сам.
- SOCKS5 или HTTP-прокси, в том числе с паролем: `http://user:pass@proxy.example:3128`, `socks5://user:pass@host:1080`.
- Прокси от VPN-клиента (Amnezia, v2ray, sing-box и т. п.): его локальный SOCKS или HTTP порт.

Список хранится в `~/Library/Application Support/claudeguard/config.json` (Windows: `%APPDATA%\claudeguard\config.json`), права 0600. Путь можно переопределить переменной `CLAUDEGUARD_CONFIG`.

Панель живёт на том же порту, что и прокси, а до него может достучаться любая программа на этом компьютере. Поэтому каждый запрос к API несёт ключ из конфига (в ссылку он попадает после `#`, браузер его на сервер не шлёт и из адресной строки он стирается), а запросы с чужим `Host` или `Origin` отклоняются. Страницу нельзя встроить во фрейм.

## Проверка

```bash
claudeguard status
```

```
server:          vd-poland (ssh vd-poland)
local proxy:     http://127.0.0.1:41080 running (claudeguard 0.2.0 -> vd-poland)
firewall rules:  installed
via proxy:       ok (api.anthropic.com reachable through the proxy)
direct IPv4:     blocked/unreachable (connection refused)
direct IPv6:     blocked/unreachable (no route to host)
```

Ручной тест kill switch:

```bash
curl --noproxy '*' -m 5 https://api.anthropic.com    # должен упасть сразу
curl -x http://127.0.0.1:41080 https://api.anthropic.com -o /dev/null -w '%{http_code}\n'   # 404/401: дошли
# в панели выбери сервер, который не отвечает (или удали активный)
curl -x http://127.0.0.1:41080 https://api.anthropic.com   # ошибка 502, напрямую тоже нет
```

В режиме `--allow-tunnels` при включённом VPN первая команда пройдёт: трафик идёт через VPN. Выключи VPN, и она начнёт падать.

## Команды

```
install / uninstall      всё сразу / всё убрать
ui                       панель настроек в браузере
status                   проверка
launch [--app PATH]      перезапустить десктоп через прокси
serve [--detach]         прокси и панель (обычно их запускает LaunchAgent / автозагрузка)
enable / disable         только правила файрвола (admin)
```

Опции `install`: `--ssh HOST` или `--upstream URL` (добавить сервер и сделать активным), `--listen`, `--allow-tunnels`, `--extra-block CIDR,CIDR`, `--no-settings`, `--no-launcher`.

## Ограничения (честно)

- **Блокируются только сети Anthropic.** Часть служебного трафика Claude идёт на чужие CDN: обновления Claude Code с `storage.googleapis.com`, `downloads.claude.ai` на Google Cloud, сторонняя телеметрия. По IP их не заблокировать без вреда для остальной системы. При запуске через лаунчер (десктоп) и с `settings.json` (Claude Code) этот трафик тоже идёт через прокси, но kill switch его не страхует. Дополнительные сети можно добавить через `--extra-block`.
- **DNS-запрос** к `claude.ai` при запуске в обход лаунчера уходит в системный резолвер. Сам трафик при этом блокируется.
- **Десктоп, запущенный из Dock или Spotlight**, а не через «Claude via Proxy», работает без флага прокси, то есть офлайн (kill switch). Лечится перезапуском через лаунчер.
- **claude.ai в браузере** тоже попадает под блок. Значит, в браузере его тоже нужно открывать через прокси или VPN.
- **`settings.json` env** действует и на дочерние процессы Claude Code (Bash, MCP-серверы): `curl`, `gh` и прочие тоже пойдут через прокси.
- **Основной процесс Electron** (Node-запросы десктопа, не Chromium) флаг `--proxy-server` может не учитывать. В режиме `--allow-tunnels` такие запросы идут через VPN, в режиме «только прокси» блокируются, и часть функций десктопа может не работать без VPN.
- Что вкладка Code в десктопе читает `env` из `~/.claude/settings.json`, не проверено. Kill switch её в любом случае страхует.
- **Windows** собран и проверен только кросс-компиляцией и unit-тестами. На живой Windows-машине не запускался.
- **Кнопка «Применить»** на macOS проверена только до вызова: диалог пароля и переустановка правил pf на этом Mac не запускались. Переключение серверов, проверки и туннели проверены вживую.
- **Пароль от прокси** хранится в конфиге открытым текстом (файл доступен только твоему пользователю) и виден в панели при редактировании сервера.

## Аналоги

- [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge): open source (MIT), Windows и macOS, правила по процессам (proxy/direct/block). Самый близкий аналог. Правило block можно использовать как kill switch, но оно привязано к процессу, а не к адресам.
- [ProxiFyre](https://github.com/wiresock/proxifyre): только Windows, SOCKS5 по процессам через NDISAPI, умеет UDP.
- [Proximac](https://github.com/csujedihy/proximac): только macOS, CLI в духе Proxifier.
- [sing-box](https://sing-box.sagernet.org/): TUN с правилами `process_name`. На Apple-платформах нет `strict_route`, а без него нет жёсткого kill switch.
- Proxifier: платный, правила по приложениям.

## Сборка

```bash
go test ./...
GOOS=windows GOARCH=amd64 go build -o dist/claudeguard-windows-amd64.exe .
GOOS=darwin  GOARCH=arm64 go build -o dist/claudeguard-darwin-arm64 .
```

Панель (`ui/`) встраивается в бинарник через `go:embed`, отдельно ничего ставить не нужно. Готовые бинарники лежат в Releases.

Макет панели в Claude Design: https://claude.ai/artifact/3bjRyRajb78edZDhGEPKgm
