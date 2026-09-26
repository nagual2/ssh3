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
Dieser Fork zielt darauf ab, die Go-Implementierung zu einem praktischen Alltagswerkzeug zu machen:

- **Der Windows-Client ist vollwertig.** Seit v0.1.8 kompiliert der Client für Windows und unterstützt interaktive PTY-Sitzungen: VT-Eingabe/-Ausgabe, UTF-8-Konsolcodepage, echte Konsolengröße, Weiterleitung von `SIGINT`/`SIGTERM` und einen 80x24-PTY-Fallback, wenn die Konsolengröße nicht ermittelt werden kann.
- **Server-Pakete nur mit Schlüsselauthentifizierung.** Das Release-`.deb` liefert einen systemd-Dienst (`ssh3-server.service`, UDP 443, geheimer URL-Pfad), gebaut mit `-tags disable_password_auth`: Passwortauthentifizierung ist herauskompiliert, OIDC ist nicht konfiguriert, und das Post-Install-Skript erzeugt ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs.
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
| `ssh3_<ver>_amd64.deb` | Server-+-Client-Paket für Debian/Ubuntu/Mint (systemd-Dienst, nur Schlüssel) |

Installation des Debian-Pakets:

```bash
sudo dpkg -i ssh3_0.1.8_amd64.deb
```

Der Dienst lauscht auf UDP 443 unter dem geheimen URL-Pfad `/ssh3-term`. Die Konfiguration liegt in `/etc/ssh3/ssh3-server.env` (Logdatei und -level, `LANG`), die systemd-Unit in `/usr/lib/systemd/system/ssh3-server.service`; ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs wird bei der Installation in `/etc/ssh3/` erzeugt, falls es fehlt.

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
| Passwortauthentifizierung | Ja | Ja | Go-Passwortauthentifizierung hängt von der Plattformunterstützung ab. Release-Pakete werden mit `-tags disable_password_auth` gebaut. |
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

Release- und CI-Builds verwenden `CGO_ENABLED=0` mit `-tags disable_password_auth` — Passwortauthentifizierung ist dann vollständig aus dem Binary entfernt. Wer Passwortauthentifizierung unter Linux möchte, baut mit CGO und ohne den Tag:

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
Passwort-Login auf dem Server aktivieren:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --enable-password-login
```

Verbindung mit dem Client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --password-file /path/to/password.txt \
  https://127.0.0.1:4433/ssh3-term
```

Hinweis: Release-Pakete sind mit `-tags disable_password_auth` kompiliert; dieser Pfad existiert nur in eigenen Builds.

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
- Der Rust-Server ist heute bewusst minimal: nur selbstsignierte Zertifikate, kein geheimer URL-Pfad, keine Automatisierung öffentlicher Zertifikate.
- Die Rust-CLI exponiert noch keine TCP-/UDP-Forwarding- oder Proxy-Jump-Flags, obwohl die Runtime implementiert und getestet ist.
- Der vendored `h3`-Patch ist ein bewusster Kompatibilitäts-Shim für die beliebte `:protocol=ssh3`-Behandlung und muss noch aufgeräumt werden.
- Der Windows-Client hat kein SSH-Agent-Forwarding und leitet keine Fenstergrößenänderungen weiter; die erste Verbindung zu einem selbstsignierten Server erfordert ein in `known_hosts` hinterlegtes Zertifikat, da die interaktive TOFU-Abfrage ein Unix-typisches tty braucht.

## Sicherheit
SSH3 ist vielversprechend, aber das Projekt braucht noch erhebliche Prüfung, bevor man ihm in der Produktion vertrauen kann. Die Protokolloberfläche kombiniert TLS 1.3, QUIC, HTTP-Autorisierung und SSH-artige Kanalsemantik — der richtige Maßstab ist eine lange Phase von Reviews und Interop-Härtung, nicht „läuft auf meiner Maschine“.

Nutzen Sie es in Labors, CI, privaten Umgebungen und Interop-Experimenten. Verlassen Sie sich noch nicht darauf als fertigen OpenSSH-Ersatz für die Produktion.
