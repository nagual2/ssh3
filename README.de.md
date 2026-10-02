<div align="center">
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>

> [!NOTE]
> SSH3 ist weiterhin experimentell, und der Protokollname kann sich noch ändern. Das Protokoll bleibt SSH-typische Sitzungs- und Kanalsemantik über QUIC und HTTP/3 Extended CONNECT, aber die Implementierung und das drumherum entwickeln sich weiter.

# SSH3 over HTTP/3
[English](README.md) | [Русский](README.ru.md) | **Deutsch**

SSH3 abbildet RFC-4254-artige Sitzungssemantik auf QUIC, TLS 1.3 und HTTP/3 Extended CONNECT. Das Projekt möchte vertraute SSH-Workflows erhalten und gleichzeitig HTTP-native Authentifizierung und QUIC-native Transportfunktionen wie Datagram-Forwarding hinzufügen.

Dieses Repository enthält derzeit zwei Implementierungen:

- Den ursprünglichen Go-Client und -Server in [`cmd/ssh3`](cmd/ssh3) bzw. [`cmd/ssh3-server`](cmd/ssh3-server)
- Ein laufendes Rust-Rewrite in [`crates/`](crates)

> [!WARNING]
> Betrachten Sie keine der Implementierungen als produktionsreif. Protokoll und Code befinden sich in aktiver Entwicklung; das Rust-Rewrite konzentriert sich in erster Linie auf Korrektheit und Interoperabilität, nicht auf Produktvollständigkeit.

## Über den nagual2-Fork
Dieser Fork zielt darauf ab, die Go-Implementierung zu einem praktischen Alltagswerkzeug zu machen. Diese README basiert auf der README des Upstream-Projekts und wurde von den Fork-Maintainern geändert; nur den Fork betreffende Änderungen werden in [CHANGELOG.md](CHANGELOG.md) nachverfolgt:

- **Der Windows-Client ist vollwertig.** Seit v0.1.8 kompiliert der Client für Windows und unterstützt interaktive PTY-Sitzungen: VT-Eingabe/-Ausgabe, UTF-8-Konsolcodepage, echte Konsolengröße, Weiterleitung von `SIGINT`/`SIGTERM` und einen 80x24-PTY-Fallback, wenn die Konsolengröße nicht ermittelt werden kann.
- **Server-Pakete: standardmäßig Schlüssel, Passwörter als Opt-in.** Das Release-`.deb` liefert einen systemd-Dienst (`ssh3-server.service`, UDP 443, geheimer URL-Pfad); OIDC ist nicht konfiguriert, und das Post-Install-Skript erzeugt ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs. In amd64-Builds ist das Passwort-Backend einkompiliert, aber deaktiviert, bis der Administrator es ausdrücklich einschaltet (`SSH3_ENABLE_PASSWORD_LOGIN=1` in `/etc/ssh3/ssh3-server.env` oder `-enable-password-login`); arm-Server-Builds sind nur mit Schlüsseln.
- **systemd-Unit mit OpenSSH-Parität.** Der Unit enthält keine Sandbox-Direktiven (`CapabilityBoundingSet`, `NoNewPrivileges`, `Protect*`): Der Root-Daemon startet jede Sitzung mit der uid/gid des authentifizierten Benutzers (wie sshd), sodass `sudo` innerhalb einer Sitzung die vollen Root-Capabilities zurückerlangt — tcpdump, trafshow, modprobe und sysctl funktionieren. `KillMode=process` erhält aktive Sitzungen über Daemon-Neustarts hinweg, wie in Debians `ssh.service`. Die Vertrauensgrenze ist die Schlüsselauthentifizierung, nicht die Unit-Sandbox.
- **Statistik-Banner beim Login.** Interaktive Sitzungen zeigen vor dem Shell-Prompt Uptime, Load, Arbeitsspeicher und Festplatte (`exec`-Anfragen bleiben unberührt).
- **Locale- und Shell-Fixes.** Der Server reicht `LANG`/`LC_*` aus seiner systemd-Umgebung an die Benutzer-Shells weiter und startet die echte Login-Shell des Kontos aus `/etc/passwd` statt eines hartkodierten `/bin/sh`.
- **CI.** Jedes `v*`-Tag erzeugt Release-Archive und ein `.deb` via goreleaser; jeder Push nach `main` erzeugt Windows-Client-Artefakte.

## Download & Installation
Die Assets gibt es im [neuesten Release](https://github.com/nagual2/ssh3/releases/latest):

| Datei | Zweck |
| --- | --- |
| `ssh3_client_<ver>_windows_amd64.zip` | Windows-Client (`ssh3.exe`) |
| `ssh3_client_<ver>_<os>_<arch>.tar.gz` | Client für Linux, macOS, FreeBSD, OpenBSD |
| `ssh3_server_<ver>_linux_<arch>.tar.gz` | Linux-Server-Binaries |
| `ssh3_<ver>_amd64.deb` | Server-+-Client-Paket für Debian/Ubuntu/Mint (systemd-Dienst, standardmäßig Schlüssel; Passwort-Authentifizierung als Opt-in auf amd64) |

Installation des Debian-Pakets:

```bash
sudo dpkg -i ssh3_0.1.22_amd64.deb
```

Der Dienst lauscht auf UDP 443 unter dem geheimen URL-Pfad `/ssh3-term`. Die Konfiguration liegt in `/etc/ssh3/ssh3-server.env` (Logdatei und -level, `LANG`), die systemd-Unit in `/usr/lib/systemd/system/ssh3-server.service`; ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs wird bei der Installation in `/etc/ssh3/` erzeugt, falls es fehlt.

### Serverkonfiguration
Das Release-Paket wird über die systemd-`EnvironmentFile` unter `/etc/ssh3/ssh3-server.env` konfiguriert:

| Variable | Standard | Zweck |
| --- | --- | --- |
| `SSH3_LOG_FILE` | `/var/log/ssh3.log` | Server-Logdatei |
| `SSH3_LOG_LEVEL` | `info` | Log-Ausführlichkeit (`trace`, `debug`, `info`, `warn`, `error`) |
| `LANG` | `C.UTF-8` | Locale, die an Benutzer-Shells weitergereicht wird |

Änderungen anwenden: `sudo systemctl restart ssh3-server`.

Client und Server akzeptieren QUIC-Tuning-Flags für Bulk-Transfers: `-initial-packet-size` (initiale QUIC-Paketgröße in Bytes, Standard `1350`), `-stream-rx-mb` (Flow-Control-Empfangsfenster pro Stream in MiB, Standard `8`) und `-conn-rx-mb` (Empfangsfenster auf Verbindungsebene in MiB, Standard `16`).

## Hinweise zum Windows-Client
- Flags (z. B. `-privkey`) müssen **vor** der positionalen URL stehen: Gos Flag-Parser stoppt beim ersten positionalen Argument.
- Die Konsole wird für die Sitzung auf UTF-8 und VT-Verarbeitung umgeschaltet und beim Beenden zurückgesetzt. Verwenden Sie einen Unicode-fähigen Zeichensatz (Consolas, Lucida Console).
- Es gibt kein `/dev/tty` unter Windows, daher ist die interaktive TOFU-Abfrage nicht möglich: Hinterlegen Sie das Serverzertifikat in `%USERPROFILE%\.ssh3\known_hosts` (`host:port/path x509-certificate <base64 DER>`) oder verwenden Sie bewusst `-insecure`.
- SSH-Agent-Forwarding ist nicht verfügbar (nur Unix-Sockets); Fenstergrößenänderungen werden nicht weitergeleitet (kein SIGWINCH-Äquivalent).

## Status
Die Go-Implementierung bietet weiterhin die breiteste Endbenutzer-CLI. Der Rust-Workspace deckt inzwischen den Protokollkern, QUIC/HTTP/3-Bootstrap, Authentifizierung, Sitzungsverwaltung, PTY-Shells, Resize- und Signal-Forwarding, Forwarding-Runtimes sowie echte Rust<->Go-Interoperabilitätstests ab.

Rust ist kein reines Codec-Experiment mehr: funktionierende Client- und Server-Binaries existieren, aber einige betriebliche Funktionen gibt es heute nur in Go.

## Funktionsstatus
| Funktion | Go CLI/Server | Rust | Hinweise |
| --- | --- | --- | --- |
| QUIC + HTTP/3 SSH3-Transport | Ja | Ja | Rust nutzt `quinn` plus einen gepatchten vendored `h3`-Crate. |
| Sitzung: Shell und Exec | Ja | Ja | Durch Unit- und Real-Binary-Interop-Tests abgedeckt. |
| PTY-Shell, Resize und Signal-Forwarding | Ja | Ja | Real-Binary-Interop für Resize und Signale ist beidseitig getestet. Windows-Clients erhalten ein PTY mit fester 80x24-Fallback-Geometrie. |
| Public-Key-Authentifizierung | Ja | Ja | Ed25519, P-256 und RSA sind abgedeckt. |
| Passwortauthentifizierung | Ja | Ja | Go-Passwortauthentifizierung nutzt das systemweite Shadow-Backend (CGO). amd64-Release-Server-Builds kompilieren sie ein, halten sie aber standardmäßig deaktiviert; arm-Builds sind nur mit Schlüsseln. |
| OpenID-Connect-Authentifizierung | Ja | Ja | Tokens sind inzwischen per Nonce-Prüfung an die SSH3-Konversation gebunden. |
| SSH-Agent-Authentifizierung | Ja | Ja | |
| SSH-Agent-Forwarding | Ja | Ja | Nur Unix-Sockets; aus Windows-Clients nicht verfügbar. |
| Direktes TCP-Forwarding | Ja | Ja | Die Rust-Runtime unterstützt es; die Rust-CLI exponiert die Forwarding-Flags noch nicht. |
| Direktes UDP-Forwarding | Ja | Ja | Die Rust-Runtime unterstützt es; die Rust-CLI exponiert die Forwarding-Flags noch nicht. |
| Proxy jump | Ja | Nein | Derzeit nur Go. |
| Geheimer URL-Pfad / versteckter Serverpfad | Ja | Nein | Derzeit nur Go. |
| Automatisierung öffentlicher Zertifikate | Ja | Nein | Der Go-Server unterstützt Let's Encrypt; der Rust-Server derzeit nur selbstsignierte Zertifikate. |

## Repository-Aufbau
- [`cmd/ssh3`](cmd/ssh3): ursprünglicher Go-Client
- [`cmd/ssh3-server`](cmd/ssh3-server): ursprünglicher Go-Server
- [`crates/ssh3-proto`](crates/ssh3-proto): Wire-Format, Nachrichten und Forwarding-Header
- [`crates/ssh3-core`](crates/ssh3-core): Conversations- und Channel-Runtime
- [`crates/ssh3-quinn`](crates/ssh3-quinn): QUIC-Bindings
- [`crates/ssh3-h3`](crates/ssh3-h3): HTTP/3-Bootstrap und CONNECT-Behandlung
- [`crates/ssh3-auth`](crates/ssh3-auth): Public-Key- und passwortnahe Hilfen sowie OIDC-Verifizierung
- [`crates/ssh3-client`](crates/ssh3-client): Rust-Client (Bibliothek und Binary)
- [`crates/ssh3-server`](crates/ssh3-server): Rust-Server (Bibliothek und Binary)
- [`internal/interop`](internal/interop): Go-Helfer für die Rust-Real-Binary-Interop-Suite

## Bauen
### Rust
Aktuelles stabiles Rust-Toolchain verwenden.

```bash
cargo build --workspace
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Aktuelle Rust-CLIs:

```text
$ cargo run -p ssh3-client -- --help
Usage: ssh3-client [OPTIONS] <URL> [COMMAND]...

$ cargo run -p ssh3-server -- --help
Usage: ssh3-server [OPTIONS]
```

Beim Rust-Client sind dateibasierte Secret-Flags wie `--password-file`, `--bearer-token-file` und `--oidc-client-secret-file` zu bevorzugen: Sie lecken weniger über Shell-History, Prozesslisten und CI-Logs.

### Go
Go 1.21 oder neuer. Das Repository trägt einen vendored Rust-`h3`-Crate (den `:protocol=ssh3`-Shim) ohne Go-`vendor/modules.txt` — Go muss daher im Module-Modus bleiben:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o ssh3 ./cmd/ssh3
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -tags disable_password_auth -o ssh3-server ./cmd/ssh3-server
```

Release-Client-Builds und arm-Server-Builds verwenden `CGO_ENABLED=0` mit `-tags disable_password_auth` — Passwortauthentifizierung ist dann vollständig aus dem Binary entfernt. Der amd64-Release-Server wird mit CGO und ohne den Tag gebaut: das Shadow/crypt-Backend ist einkompiliert, aber standardmäßig deaktiviert. Wer Passwortauthentifizierung im eigenen Linux-Build möchte:

```bash
CGO_ENABLED=1 GOFLAGS=-mod=mod go build -o ssh3-server ./cmd/ssh3-server
```

## Schnellstart
### Lokaler Rust-Server + Rust-Client
Der Rust-Server startet derzeit mit einem selbstsignierten Zertifikat, daher nutzt das Client-Beispiel `--insecure`.

Server starten:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Verbindung mit privatem Schlüssel:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Remote-Befehl statt Shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

### Go-Server für öffentliche Einsatzszenarien
Wer Automatisierung öffentlicher Zertifikate, geheimen URL-Pfad, Proxy jump oder das Forwarding-CLI braucht, nutzt heute die Go-Binaries.

Beispiel-Go-Server mit öffentlichem Zertifikat:

```bash
ssh3-server -generate-public-cert my-domain.example.org -url-path /ssh3
```

Beispiel-Go-Client:

```bash
ssh3 -privkey ~/.ssh/id_ed25519 username@my-domain.example.org/ssh3
```

Beim Release-Server:

```bash
ssh3 max@my-server.example.org/ssh3-term -privkey ~/.ssh/id_ed25519
```

### Dateiübertragung

Stage 2 ergänzt den `ssh3 -f`-Modus über einen dedizierten SFTP-Kanal (der
Server stellt `pkg/sftp` bereit, eingesperrt im Home-Verzeichnis des
Sitzungsbenutzers; angelegte Dateien gehören diesem Benutzer):

```bash
# Datei hochladen (Remote-Operand zuletzt)
ssh3 -f ~/report.pdf max@my-server.example.org/ssh3-term:docs/report.pdf

# Verzeichnis rekursiv hochladen
ssh3 -f -r ~/project-dir max@my-server.example.org/ssh3-term:backups/

# Herunterladen (Remote-Operand zuerst)
ssh3 -f max@my-server.example.org/ssh3-term:logs/app.log ./app.log

# Unterbrochene Übertragungen fortsetzen statt zu überschreiben
ssh3 -f --continue big-disk-image.raw max@my-server.example.org/ssh3-term:images/raw

# SHA-256-Prüfung durch erneutes Lesen der Remote-Datei erzwingen
# (automatisch bei Übertragungen über 32 MiB)
ssh3 -f --checksum data.bin max@my-server.example.org/ssh3-term:data.bin
```

Hinweise: Standardport 443, URL-Pfad `/ssh3-term`; überschreibbar mit `-P`
und `-U`, oder als vollständige Form `user@host:port/url_path:remote_path`.
Unreguläre Dateien (Symlinks, Geräte) werden bei rekursiven Übertragungen
übersprungen, ein leeres Verzeichnis wird auf der Gegenseite angelegt.

## Control Master (Verbindungsmultiplexing)

Eine authentifizierte Verbindung für viele Aufrufe - der erste Lauf macht
den Handshake, weitere nutzen ihn über einen Unix-Socket (Stage 3.5):

```bash
# persistenten Master im Hintergrund starten (kehrt sofort zurück)
ssh3 -control-master=yes -control-persist=yes user@host

# weitere Aufrufe laufen als Slave: kein neuer Handshake, ~5x schneller Start
ssh3 -control-master=auto user@host 'uptime'
ssh3 -control-master=auto user@host 'tail -n 5 /var/log/syslog'
ssh3 -control-master=auto -forward-tcp 8080/127.0.0.1@80 user@host 'sleep 30'

# Master beenden
ssh3 -O exit -control-path ~/.ssh3/cm-user@host:443 user@host
```

| Flag | Bedeutung |
|------|-----------|
| `-control-master no\|yes\|auto` | `auto` nutzt einen laufenden Master und startet sonst einen; `yes` startet immer; Standard `no` |
| `-control-path PFAD` | Pfad des Steuerungs-Sockets; Standard `~/.ssh3/cm-<user>@<host>:<port>`, Rechte 0600 |
| `-control-persist no\|yes\|<Sekunden>` | Master nach Sitzungsende im Hintergrund halten; `yes` = unbegrenzt, Zahl = Idle-Timeout |
| `-O exit` | Master beenden (benötigt das Ziel-Operand, wie OpenSSH) |

Hinweise: der Master ist eine abgelöste Kopie dieses Binärprogramms
(`SSH3_CM_DAEMON=1`); jede Slave-Sitzung, TCP/UDP-Weiterleitung und das
Agent-Forwarding werden über die eine QUIC-Verbindung des Masters
multiplext. Der Median von 100 aufeinanderfolgenden Execs sinkt von
~130 ms (kalt, je ein Handshake) auf ~24 ms (~17%) bei genau einem
Handshake. Einschränkungen: `-proxy-jump` ist inkompatibel (die Kombination
mit `-control-master` ist ein Fehler), Windows wird nicht unterstützt.
Interaktive pty-Slave-Sitzungen leiten Fensteränderungen und außerbandige
Signale durch den Master.

## Port-Weiterleitung
Lokale TCP- und UDP-Weiterleitungen laufen auf dem Client und werden über die
ssh3-Verbindung getunnelt (`lokaler_port/remote_ip@remote_port`):

```bash
ssh3 -forward-tcp 8080/10.0.0.10@80 user@host
ssh3 -forward-udp 5353/192.0.2.1@53 user@host
```

`-N` hält die Verbindung für die Weiterleitungen offen, ohne eine Sitzung
zu starten; `Strg+C` baut sie ab:

```bash
ssh3 -N -forward-tcp 8080/10.0.0.10@80 user@host
```

Rückwärtige Weiterleitung (`-R`, ein Listener auf dem Server) ist noch nicht
implementiert; siehe „Bekannte Lücken“.

## Client-Konfiguration (~/.ssh/config)
Neben `HostName`, `Port`, `User` und `IdentityFile` berücksichtigt der Client
pro `Host`-Muster: `ProxyJump` (als ssh3-UDP-Proxy-Jump interpretiert: der
Jump-Host muss ssh3-server ausführen), `UDPProxyJump` (Fork-Erweiterung,
gleiche Semantik), `ForwardAgent` und `ServerAliveInterval` (Sekunden;
stimmt den QUIC-Keepalive ab, Standard 1). `Include`-Direktiven löst die
Konfigurationsbibliothek auf; `Match` wird noch nicht unterstützt.

## Authentifizierung
### Public Key
Rust-Client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Der Server liest `~/.ssh3/authorized_identities` oder die Standarddatei `~/.ssh/authorized_keys` des Zielbenutzers.

### SSH-Agent
Rust-Client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  https://127.0.0.1:4433/ssh3-term
```

Lokalen Agent in die Remote-Sitzung weiterleiten:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  --forward-agent \
  https://127.0.0.1:4433/ssh3-term
```

### Passwort
Go-Server (amd64-Release-Pakete liefern das einkompilierte, standardmäßig deaktivierte Backend). Einschalten pro Aufruf:

```bash
ssh3-server ... -enable-password-login
```

oder beim systemd-Dienst in `/etc/ssh3/ssh3-server.env`:

```bash
SSH3_ENABLE_PASSWORD_LOGIN=1
```

gefolgt von `sudo systemctl restart ssh3-server`. Verbindung mit dem Go-Client:

```bash
ssh3 -use-password benutzer@my-server.example.org/ssh3-term
```

Der Go-Client fragt das Passwort interaktiv im Terminal ab; es wird nie als Kommandozeilen-Argument übergeben.

Rust-Äquivalent (Server/Client):

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --enable-password-login
```

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --password-file /path/to/password.txt \
  https://127.0.0.1:4433/ssh3-term
```

Hinweis: arm-Server-Builds sind mit `-tags disable_password_auth` kompiliert (nur Schlüssel); dort existiert der Passwort-Pfad nur in eigenen Builds.

### OpenID Connect
OIDC im Rust-Client läuft über Flags statt einer Konfigurationsdatei:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --use-oidc https://issuer.example \
  --oidc-client-id your-client-id \
  --oidc-client-secret-file /path/to/oidc-client-secret.txt \
  https://127.0.0.1:4433/ssh3-term
```

Autorisierte OIDC-Identitäten können in `authorized_identities` neben Public Keys stehen:

```text
oidc <client_id> <issuer_url> <email>
```

## Tests
Der Rust-Workspace ist der primäre Verifikationsweg dieses Repositories.

Volle Rust-Suite:

```bash
cargo test
```

Die tiefste Rust/Go-Interop-Matrix:

```bash
cargo test -p ssh3-client
```

Die Interop-Suite lässt echte Rust- und Go-Binaries gegeneinander laufen:

- Exec- und Shell-Sitzungen
- PTY-Zuteilung, Resize und Signal-Forwarding
- Public-Key-, Passwort- und OIDC-Authentifizierung
- SSH-Agent-Authentifizierung und Agent-Forwarding
- TCP- und UDP-Forwarding

Bei direkten Go-Befehlen das Toolchain wegen des vendored Rust-Shims im Module-Modus halten:

```bash
GOFLAGS=-mod=mod go build ./...
```

## Bekannte Lücken
- Rückwärtige Weiterleitung (`-R`): Der Server kann noch nicht gebeten werden, einen Remote-Port zu überwachen und Verbindungen zurück zum Client zu brücken; dafür ist eine kleine Protokollerweiterung nötig (siehe CHANGELOG).
- Der Rust-Server ist heute bewusst minimal: nur selbstsignierte Zertifikate, kein geheimer URL-Pfad, keine Automatisierung öffentlicher Zertifikate.
- Die Rust-CLI exponiert noch keine TCP-/UDP-Forwarding- oder Proxy-Jump-Flags, obwohl die Runtime implementiert und getestet ist.
- Der vendored `h3`-Patch ist ein bewusster Kompatibilitäts-Shim für die beliebte `:protocol=ssh3`-Behandlung und muss noch aufgeräumt werden.
- Der Windows-Client hat kein SSH-Agent-Forwarding und leitet keine Fenstergrößenänderungen weiter; die erste Verbindung zu einem selbstsignierten Server erfordert ein in `known_hosts` hinterlegtes Zertifikat, da die interaktive TOFU-Abfrage ein Unix-typisches tty braucht.

## Sicherheit
SSH3 ist vielversprechend, aber das Projekt braucht noch erhebliche Prüfung, bevor man ihm in der Produktion vertrauen kann. Die Protokolloberfläche kombiniert TLS 1.3, QUIC, HTTP-Autorisierung und SSH-artige Kanalsemantik — der richtige Maßstab ist eine lange Phase von Reviews und Interop-Härtung, nicht „läuft auf meiner Maschine“.

Nutzen Sie es in Labors, CI, privaten Umgebungen und Interop-Experimenten. Verlassen Sie sich noch nicht darauf als fertigen OpenSSH-Ersatz für die Produktion.

## Lizenz
Das Projekt steht unter der [Apache License 2.0](LICENSE), geerbt vom Upstream-Projekt [francoismichel/ssh3](https://github.com/francoismichel/ssh3). Die Änderungen dieses Forks, einschließlich der Dokumentation, werden zu denselben Apache-2.0-Bedingungen vertrieben.
