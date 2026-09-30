# Миграция ssh3: quic-go v0.49.0 → v0.63.0

Ветка: `stage15/quic-go-0.63` (worktree `C:\Git\project\ssh3-v063`).

Коммит `b2d6ddf` заявляет «upgrade quic-go v0.40.1 -> v0.59.1», но фактический
`go.mod` и в нём, и в текущем дереве указывал **v0.49.0**. Апгрейд не был
выполнен. Дельта апстрима между v0.49.0 и v0.63.0 — **570 коммитов**.

Зависимости уже подняты (`go mod tidy` + `go mod vendor` выполнены):

| Модуль | Было | Стало |
|--------|------|-------|
| quic-go | v0.49.0 | v0.63.0 (replace на `../quic-go`, ветка `feat/io-uring-send`) |
| go directive | 1.22 | 1.26.0 |
| golang.org/x/crypto | v0.26.0 | v0.54.0 |
| golang.org/x/sys | v0.23.0 | v0.47.0 |
| golang.org/x/term | v0.23.0 | v0.45.0 |
| quic-go/qpack | v0.5.1 | v0.6.0 |

Стек сборки: WSL, go1.26.0 (требование форка — ровно 1.26.0).

## Это не механический рефакторинг

`http3` в v0.63 переписан: приложение больше не получает внутренние структуры
http3, но получило два явных escape-hatch'а для «сырых» протоколов вроде ssh3:

- сервер: `(*http3.Server).NewRawServerConn(conn *quic.Conn) (*RawServerConn, error)`;
- клиент: `(*http3.Transport).NewRawClientConn(conn *quic.Conn) *RawClientConn`.

У обоих конструкторы **экспортированы** — это подтверждённая точка входа.

## Карта замен

| v0.49 | v0.63 | Комментарий |
|-------|-------|-------------|
| `quic.Connection` | `*quic.Conn` | переименование + стал указателем |
| `quic.EarlyConnection` | `*quic.Conn` | `DialEarly` теперь возвращает `*Conn` |
| `quic.ConnectionTracingID` | `*quic.Conn` | **концепция удалена** (в пакете нет ни одного `Tracing`) |
| `quic.ConnectionTracingKey` | — | удалено; идентичность = сам указатель `*quic.Conn` |
| `quic.Session` | `*quic.Conn` | |
| `http3.Connection` | `*http3.RawServerConn` | + `*quic.Conn` для уровня QUIC |
| `http3.RoundTripper` | `*http3.Transport` | поля диала переехали в `Transport` |
| `RoundTripper.NewClientConn(qconn)` | `Transport.NewRawClientConn(qconn)` | возвращает `*http3.RawClientConn` |
| `http3.Hijacker` | `http3.HTTPStreamer` | `HTTPStream() *http3.Stream`; уже используется в `server_auth/auth.go` |
| `http3.Server.StreamHijacker` | **нет** → свой accept-цикл | см. ниже |
| `RoundTripper.StreamHijacker` | **нет** → свой accept-цикл | см. ниже |
| `cc.OpenRequestStream` → `http3.Stream` | `ClientConn.OpenRequestStream` → `*http3.RequestStream` | методы `SendRequestHeader`/`ReadResponse`/`Write` сохранены |

## Главное архитектурное изменение: свой accept-цикл

`StreamHijacker` в v0.63 удалён с обеих сторон. Нужен свой dispatch поверх
`conn.AcceptStream()`: читаем первый QUIC-varint и решаем, кто владеет потоком.

- `0x1` (HEADERS) → это HTTP/3 request stream → `hconn.HandleRequestStream(str)`;
- иначе → это SSH3-канал (`SSH_FRAME_TYPE = 0xaf3627e6`) → наш обработчик.

Диспетчер нужен **на обеих сторонах**, и на клиенте это не опция:

- `cmd/ssh3-server.go:759` открывает канал `"agent-connection"` к клиенту
  (проброс ssh-agent), значит клиентский `StreamHijacker` — живой код;
- но `(*http3.ClientConn).HandleBidirectionalStream` в v0.63 закрывает
  соединение с `STREAM_CREATION_ERROR` на любом серверном bidi-потоке
  (это соответствует RFC 9114, где сервер не открывает request streams).

Значит на клиенте `"agent-connection"` нельзя отдавать в
`HandleBidirectionalStream` — его надо обрабатывать как SSH3-канал в своём же
accept-цикле. Иначе сломается проброс ssh-agent.

## Как достать `*quic.Conn` в HTTP-обработчике

`http3.Stream` не отдаёт наружу underlying-соединение (поле `conn *rawConn`
неэкспортировано; экспортированы только `Read`/`Write`/`StreamID`/
`SendDatagram`/`ReceiveDatagram`).

Поддерживаемый путь — `http3.Server.ConnContext`:

```go
ConnContext func(ctx context.Context, c *quic.Conn) context.Context
```

Кладём `*quic.Conn` в contextvalue, достаём в обработчике CONNECT.
Это же решает задачу идентификации: `map[*quic.Conn]*conversationsManager`
вместо `map[quic.ConnectionTracingID]...`.

## Что уже проверено

- `go mod tidy` + `go mod vendor` проходят; зависимости разрешаются.
- Бамп изолирован в worktree: `main` ssh3 и форк quic-go не тронуты.
- Форк (`feat/io-uring-send`) = upstream v0.63.0+9 + наш io_uring-патч,
  так что после порта ssh3 подключит его обычным replace, без v0.49-worktree.
- Регрессия форвардинга (B10/B11/DNS) уже проверена на **v0.49** после фиксов
  соседней сессии — её нужно перепроверить на новой базе как регресс.

## Открытый риск

Порт затрагивает ровно ту диспетчеризацию потоков, которую соседняя сессия
только что починила (`99121bd` — ожидание регистрации conversation в stream
hijacker). Регресс-план обязателен: `bash bench/forwarding.sh --stand S1`
(B10 TCP, B11 UDP, B11-DNS) плюс B1 throughput.
