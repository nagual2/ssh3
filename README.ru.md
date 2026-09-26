<div align="center">
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>

> [!NOTE]
> SSH3 всё ещё экспериментальный, и имя протокола может измениться. Протокол сохраняет семантику сессий и каналов в стиле SSH поверх QUIC и HTTP/3 Extended CONNECT, но реализация и продуктовая обвязка продолжают развиваться.

# SSH3 over HTTP/3
[English](README.md) | **Русский** | [Deutsch](README.de.md)

SSH3 переносит семантику удалённых сессий в духе RFC 4254 на QUIC, TLS 1.3 и HTTP/3 Extended CONNECT. Цель проекта — сохранить привычные SSH-сценарии, добавив HTTP-нативную аутентификацию и транспортные возможности QUIC, такие как пересылка датаграмм.

В репозитории сейчас две реализации:

- Оригинальные Go-клиент и Go-сервер в [`cmd/ssh3`](cmd/ssh3) и [`cmd/ssh3-server`](cmd/ssh3-server)
- Развивающийся рерайт на Rust в [`crates/`](crates)

> [!WARNING]
> Не считайте ни одну из реализаций production-ready. Протокол и код активно разрабатываются, а рерайт на Rust сосредоточен в первую очередь на корректности и совместимости, а не на продуктовой полноте.

## О форке nagual2
Этот форк нацелен на то, чтобы Go-реализация стала практичным повседневным инструментом:

- **Windows-клиент — полноценный гражданин.** Начиная с v0.1.8 клиент компилируется под Windows и поддерживает интерактивные PTY-сессии: VT-ввод/вывод, кодовую страницу UTF-8, реальный размер консоли, проброс `SIGINT`/`SIGTERM` и фолбэк PTY 80x24, если размер консоли узнать не удалось.
- **Пакеты сервера только с ключевой авторизацией.** Релизный `.deb` содержит systemd-сервис (`ssh3-server.service`, UDP 443, секретный URL-путь), собранный с `-tags disable_password_auth`: парольная авторизация выпилена на этапе компиляции, OIDC не настроен, а пост-установочный скрипт генерирует self-signed сертификат ed25519 с IP/DNS SAN.
- **Баннер статистики при входе.** Интерактивные сессии перед промптом шелла показывают uptime, load, память и диск (запросы `exec` не затрагиваются).
- **Локаль и шелл.** Сервер пробрасывает `LANG`/`LC_*` из своего systemd-окружения в шеллы пользователей и запускает реальный login-шелл аккаунта из `/etc/passwd` вместо захардкоженного `/bin/sh`.
- **CI.** Каждый тег `v*` собирает релизные архивы и `.deb` через goreleaser; каждый пуш в `main` — артефакты Windows-клиента.

## Скачивание и установка
Берите ассеты из [последнего релиза](https://github.com/nagual2/ssh3/releases/latest):

| Файл | Назначение |
| --- | --- |
| `ssh3_client_<ver>_windows_amd64.zip` | Клиент для Windows (`ssh3.exe`) |
| `ssh3_client_<ver>_<os>_<arch>.tar.gz` | Клиент для Linux, macOS, FreeBSD, OpenBSD |
| `ssh3_server_<ver>_linux_<arch>.tar.gz` | Серверные бинарники для Linux |
| `ssh3_<ver>_amd64.deb` | Пакет сервер + клиент для Debian/Ubuntu/Mint (systemd-сервис, только ключи) |

Установка deb-пакета:

```bash
sudo dpkg -i ssh3_0.1.8_amd64.deb
```

Сервис слушает UDP 443 по секретному URL-пути `/ssh3-term`. Конфигурация — в `/etc/ssh3/ssh3-server.env` (файл и уровень лога, `LANG`), юнит — в `/usr/lib/systemd/system/ssh3-server.service`, а self-signed сертификат ed25519 с IP/DNS SAN генерируется в `/etc/ssh3/` при установке, если его нет.

## Заметки о Windows-клиенте
- Флаги (например, `-privkey`) должны стоять **до** позиционного URL: парсер флагов Go останавливается на первом позиционном аргументе.
- Консоль на время сессии переключается в UTF-8 и VT-режим, при выходе настройки восстанавливаются. Используйте шрифт с поддержкой Unicode (Consolas, Lucida Console).
- На Windows нет `/dev/tty`, поэтому интерактивный TOFU-промпт не работает: закрепите сертификат сервера в `%USERPROFILE%\.ssh3\known_hosts` (`host:port/path x509-certificate <base64 DER>`) или осознанно используйте `-insecure`.
- Проброс SSH-агента недоступен (только unix-сокет); изменение размера окна не пробрасывается (нет аналога SIGWINCH).

## Статус
Go-реализация по-прежнему обладает самым широким CLI-поверхностью. Rust-воркспейс покрывает ядро протокола, bootstrap QUIC/HTTP/3, аутентификацию, работу с сессиями, PTY-шеллы, проброс изменений размера и сигналов, рантаймы форвардинга и реальные тесты совместимости Rust<->Go.

Rust уже не просто эксперимент с кодеками: там есть рабочие клиент и сервер, но часть эксплуатационных функций пока есть только в Go.

## Статус возможностей
| Возможность | Go CLI/сервер | Rust | Примечания |
| --- | --- | --- | --- |
| Транспорт QUIC + HTTP/3 SSH3 | Да | Да | Rust использует `quinn` и патченный vendored-крейт `h3`. |
| Сессия: шелл и exec | Да | Да | Покрыто юнит- и real-binary interop-тестами. |
| PTY-шелл, resize, проброс сигналов | Да | Да | Real-binary interop по resize и сигналам проверен в обе стороны. Windows-клиенты получают PTY с фиксированным фолбэком 80x24. |
| Аутентификация по публичному ключу | Да | Да | Покрыты Ed25519, P-256 и RSA. |
| Парольная аутентификация | Да | Да | Парольная аутентификация в Go зависит от платформенной поддержки системного хранилища паролей. Релизные пакеты собираются с `-tags disable_password_auth`. |
| Аутентификация OpenID Connect | Да | Да | Токены привязаны к SSH3-конвертации через проверку nonce. |
| Аутентификация через SSH-агент | Да | Да | |
| Проброс SSH-агента | Да | Да | Только unix-сокеты; недоступно из Windows-клиентов. |
| Прямой TCP-форвардинг | Да | Да | Рантайм Rust поддерживает; CLI Rust флаги форвардинга пока не отдаёт. |
| Прямой UDP-форвардинг | Да | Да | Рантайм Rust поддерживает; CLI Rust флаги форвардинга пока не отдаёт. |
| Proxy jump | Да | Нет | Пока только в Go. |
| Секретный URL-путь / скрытый путь сервера | Да | Нет | Пока только в Go. |
| Автоматизация публичных сертификатов | Да | Нет | Go-сервер поддерживает Let's Encrypt; Rust-сервер пока только self-signed. |

## Структура репозитория
- [`cmd/ssh3`](cmd/ssh3): оригинальный Go-клиент
- [`cmd/ssh3-server`](cmd/ssh3-server): оригинальный Go-сервер
- [`crates/ssh3-proto`](crates/ssh3-proto): формат сообщений, сообщения и заголовки форвардинга
- [`crates/ssh3-core`](crates/ssh3-core): рантайм конвертаций и каналов
- [`crates/ssh3-quinn`](crates/ssh3-quinn): привязки QUIC
- [`crates/ssh3-h3`](crates/ssh3-h3): bootstrap HTTP/3 и обработка CONNECT
- [`crates/ssh3-auth`](crates/ssh3-auth): публичные ключи, вспомогательное для паролей и проверка OIDC
- [`crates/ssh3-client`](crates/ssh3-client): Rust-клиент (библиотека и бинарник)
- [`crates/ssh3-server`](crates/ssh3-server): Rust-сервер (библиотека и бинарник)
- [`internal/interop`](internal/interop): Go-помощники для real-binary interop-набора Rust

## Сборка
### Rust
Нужен недавний стабильный Rust.

```bash
cargo build --workspace
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Текущий CLI Rust:

```text
$ cargo run -p ssh3-client -- --help
Usage: ssh3-client [OPTIONS] <URL> [COMMAND]...

$ cargo run -p ssh3-server -- --help
Usage: ssh3-server [OPTIONS]
```

Для Rust-клиента предпочтительны файловые секреты (`--password-file`, `--bearer-token-file`, `--oidc-client-secret-file`) вместо передачи секретов прямо в командной строке: они меньше рискуют утечь через историю шелла, список процессов и логи CI.

### Go
Нужен Go 1.21+. В репозитории есть vendored Rust-крейт `h3` (шим `:protocol=ssh3`) без Go-файла `vendor/modules.txt`, поэтому держите Go в режиме модулей:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o ssh3 ./cmd/ssh3
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -tags disable_password_auth -o ssh3-server ./cmd/ssh3-server
```

Релизные и CI-сборки используют `CGO_ENABLED=0` с `-tags disable_password_auth` — парольная аутентификация полностью выпилена из бинарника. Если нужна парольная аутентификация на Linux, собирайте с CGO и без тега:

```bash
CGO_ENABLED=1 GOFLAGS=-mod=mod go build -o ssh3-server ./cmd/ssh3-server
```

## Быстрый старт
### Локальные Rust-сервер + Rust-клиент
Rust-сервер стартует с self-signed сертификатом, поэтому в примерах клиента используется `--insecure`.

Запуск сервера:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Подключение приватным ключом:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Удалённая команда вместо шелла:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

### Go-сервер для публичных сценариев
Если нужны автоматизация публичных сертификатов, секретный URL-путь, proxy jump или CLI-форвардинг — используйте Go-бинарники.

Пример Go-сервера с публичным сертификатом:

```bash
ssh3-server -generate-public-cert my-domain.example.org -url-path /ssh3
```

Пример Go-клиента:

```bash
ssh3 -privkey ~/.ssh/id_ed25519 username@my-domain.example.org/ssh3
```

Для релизного сервера:

```bash
ssh3 max@my-server.example.org/ssh3-term -privkey ~/.ssh/id_ed25519
```

## Аутентификация
### Публичный ключ
Rust-клиент:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Сервер читает `~/.ssh3/authorized_identities` или стандартный `~/.ssh/authorized_keys` целевого пользователя.

### SSH-агент
Rust-клиент:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  https://127.0.0.1:4433/ssh3-term
```

Проброс локального агента в удалённую сессию:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  --forward-agent \
  https://127.0.0.1:4433/ssh3-term
```

### Пароль
Включите парольный вход на сервере:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --enable-password-login
```

Подключение клиентом:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --password-file /path/to/password.txt \
  https://127.0.0.1:4433/ssh3-term
```

Примечание: релизные пакеты собраны с `-tags disable_password_auth`; этот путь существует только в собственных сборках.

### OpenID Connect
OIDC в Rust-клиенте конфигурируется флагами, а не конфиг-файлом:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --use-oidc https://issuer.example \
  --oidc-client-id your-client-id \
  --oidc-client-secret-file /path/to/oidc-client-secret.txt \
  https://127.0.0.1:4433/ssh3-term
```

Авторизованные OIDC-идентичности можно перечислять в `authorized_identities` наряду с публичными ключами:

```text
oidc <client_id> <issuer_url> <email>
```

## Тестирование
Rust-воркспейс — основной путь верификации в этом репозитории.

Полный Rust-набор:

```bash
cargo test
```

Самая глубокая матрица совместимости Rust/Go:

```bash
cargo test -p ssh3-client
```

Interop-набор гоняет реальные Rust- и Go-бинарники друг против друга:

- сессии exec и shell;
- выделение PTY, resize и проброс сигналов;
- аутентификация по ключу, паролю и OIDC;
- SSH-агент и проброс агента;
- TCP- и UDP-форвардинг.

При прямом запуске Go-команд держите тулчейн в режиме модулей из-за vendored Rust-шима:

```bash
GOFLAGS=-mod=mod go build ./...
```

## Известные ограничения
- Rust-сервер сегодня намеренно минимален: только self-signed сертификаты, без секретного URL-пути и без автоматизации публичных сертификатов.
- CLI Rust пока не отдаёт флаги TCP- и UDP-форвардинга и proxy jump, хотя рантайм реализован и протестирован.
- Vendored-патч `h3` — намеренный шим совместимости для произвольной обработки `:protocol=ssh3`, требующий уборки.
- Windows-клиент не умеет пробрасывать SSH-агент и resize; первое подключение к self-signed серверу требует закрепления сертификата в `known_hosts`, потому что интерактивному TOFU-промпту нужен tty в стиле Unix.

## Безопасность
SSH3 перспективен, но проекту нужна серьёзная проверка, прежде чем доверять ему в production. Поверхность протокола объединяет TLS 1.3, QUIC, HTTP-авторизацию и семантику каналов в стиле SSH, поэтому правильный стандарт — долгий период ревью и проверки совместимости, а не «у меня работает».

Используйте в лабораториях, CI, приватных средах и interop-экспериментах. Не полагайтесь на него как на готовую production-замену OpenSSH.
