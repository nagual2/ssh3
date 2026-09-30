# FORWARDING-TESTPLAN: TCP/UDP форвардинг с проверкой реального трафика

Дополнение к [TESTPLAN.md](TESTPLAN.md): сценарии **B10 (TCP forward)** и
**B11 (UDP forward)**, которых не было в матрице R3. Механика: локальный
listener в клиенте; TCP — канал на каждое соединение
(`Client.ForwardTCP`, client/client.go:476); UDP — канал на каждый
source-адрес, датаграммы QUIC (`Client.ForwardUDP`, client/client.go:426,
буфер 1500 Б). Флаги CLI: `-forward-tcp localport/remoteip@remoteport`,
`-forward-udp localport/remoteip@remoteport` (cmd/ssh3.go:387-388).
Форвардинг живёт, пока открыта сессия клиента (тест держит её командой
`sleep N`).

## Статус (2026-09-30)

- Форвардинг **не был покрыт** тестами R3 (B1–B9) — пробел, закрыт этим
  документом и `bench/forwarding.sh`.
- Баг UDP-форвардинга (терялась примерно половина датаграмм) **исправлен**
  (2026-09-29). Причина: `EnableDatagrams` на уровне `http3.Server` /
  `http3.RoundTripper` поднимал второго читателя на общей очереди датаграмм
  соединения, и HTTP/3-слой забирал часть датаграмм ssh3 себе. Слой HTTP/3
  отключён, `EnableDatagrams` перенесён на `quic.Config`; дополнительно
  исправлено накопление «висячих» датаграмм в `resources_manager.go`.
  Фикс: `1990e19` «stop HTTP/3 datagram layer from stealing ssh3 datagrams».
- Баг «канал не срабатывал» **исправлен** соседней сессией (2026-09-29):
  `99121bd` «wait for conversation registration in stream hijacker» — канал
  приходил раньше регистрации conversation и отбрасывался. Это и есть
  механизм, который обязателен при миграции на quic-go v0.63
  (см. `QUICGO-063-MIGRATION.md`): там собственный accept-цикл вместо
  `StreamHijacker`.
- **Прогон 2026-09-30 на v0.1.18 (оба фикса), стенд S1, задеплоенный
  `/usr/local/bin/ssh3` + systemd `ssh3-server`:**

  | Сценарий | Результат |
  |----------|-----------|
  | SANITY-exec | PASS |
  | B10-TCP | PASS (greeting + 512 MiB sha-verified) |
  | B10-TCP | PASS (greeting + 1 MiB sha-verified, дефолт) |
  | B11-UDP | PASS (20/20 датаграмм эхом совпало) |
  | B11-DNS | PASS (реальный запрос к резолверу через туннель) |

  WSL был перезапущен, `/dev/shm` пуст (ловушка WSL: tmpfs не переживает
  переработку), payload генерируется самим скриптом.
- TRAP: `SIZE_MB` из `bench/config.env` (512, размер payload для B1) перебивал
  дефолт форвардинга. Разведён на `FWD_SIZE_MB` со своим дефолтом 1 MiB.


## Как запускать

```bash
# S1 (WSL loopback, сервер задеплоен):
bash bench/forwarding.sh --stand S1

# с собственным билдом клиента:
SSH3_BIN=/tmp/ssh3-mys build bash bench/forwarding.sh --stand S1
```

Критерий приёмки: `SANITY-exec: PASS`, `B10-TCP: PASS`, `B11-UDP: PASS`
(и `B11-DNS: PASS` при наличии dig), отсутствие регрессий B4/B1.

## Сценарии

| № | Сценарий | Проверка |
|---|----------|----------|
| SANITY | exec `true` | базовый транспорт жив до форвардинга |
| B10 | TCP: greeting (обратный путь) + 1 MiB urandom через `-forward-tcp 13456/127.0.0.1@19999` | greeting побайтово, sha256 blob'а на приёмнике |
| B11 | UDP: 20 × 1 KiB различных датаграмм через `-forward-udp 13455/127.0.0.1@19998` в echo-сервис | каждая датаграмма эхом совпала побайтово |
| B11-DNS | реальный DNS-запрос через `-forward-udp 15353/127.0.0.53@53` | непустой ответ dig |

Сервисы на S1 — локальные процессы того же хоста (клиент и сервер на одной
машине): полный путь клиент → QUIC → ssh3d → 127.0.0.1:сервис отрабатывается,
но сетевого сегмента нет. Для S2/LAN сценарии те же, сервисы запускаются на
удалённой стороне.

## Известные ограничения реализации (не баги, для интерпретации)

- UDP: один канал на source-адрес (`forwardings map`), датаграммы QUIC
  **ненадёжны** по дизайну — на loopback потери редки, на LAN возможны;
  критерий 20/20 может деградировать при нагрузке.
- UDP: буфер чтения 1500 Б — датаграммы больше ~1400 Б полезной нагрузки
  через туннель не проходят (QUIC-лимиты).
- TCP: окно канала 30000, 10 приоритет (`OpenTCPForwardingChannel(30000, 10)`);
  1 MiB блоб прогоняет flow-control пути.
- Обратный путь TCP проверяется greeting'ом сервер-сервис → клиент.
