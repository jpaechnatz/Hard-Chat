# TURN-Credential-Worker

> **Optional.** Standardmäßig kommt Hard-Chat ohne TURN aus (nur Direktverbindungen). Dieser Worker ist für alle, die ein Relay über einen eigenen coturn-Server (Variante B, empfohlen) oder Cloudflare TURN (Variante A, US-Anbieter mit Konto) betreiben wollen.

Ein kleiner Cloudflare Worker, der der Chat-Seite **kurzlebige** TURN-Zugangsdaten ausstellt. Die eigentlichen Geheimnisse (API-Token bzw. coturn-Secret) liegen nur im Worker und nie im öffentlichen Repo. Damit ersetzt er die früher fest eingebauten Zugangsdaten (Metered.ca des Original-Autors sowie öffentliche Gratis-Relays).

## Warum überhaupt TURN?

Ohne TURN klappt die Verbindung nur, wenn beide Seiten sich direkt erreichen (STUN/Hole-Punching). Hinter symmetrischem NAT (häufig im Mobilfunk und in Firmennetzen) braucht es ein Relay. Der TURN-Betreiber sieht IP-Adressen und Datenmenge, aber **keine Inhalte**, weil die Nachrichten Ende-zu-Ende verschlüsselt sind.

## Variante A: Cloudflare Realtime TURN

1. Im Cloudflare-Dashboard unter **Realtime → TURN Server** einen TURN-Key anlegen. Notiere **Key ID** und **API Token**.
2. Worker deployen:
   ```bash
   cd turn-worker
   npx wrangler login
   npx wrangler secret put TURN_KEY_ID          # Key ID einfügen
   npx wrangler secret put TURN_KEY_API_TOKEN   # API Token einfügen
   npx wrangler deploy
   ```
3. Wrangler zeigt die URL an, z. B. `https://hard-chat-turn.DEIN-ACCOUNT.workers.dev`.

## Variante B: eigener coturn-Server (volle Kontrolle)

coturn-Konfiguration (Auszug, mit Schutz gegen Missbrauch als Proxy):
```
use-auth-secret
static-auth-secret=<langes-zufälliges-secret>
realm=turn.example.org
# Für Text-Chat reichen wenige kbit/s — als Gratis-Proxy wird der Server so uninteressant
max-bps=64000
total-quota=20
user-quota=4
# Niemals ins Heimnetz/Loopback weiterleiten
no-multicast-peers
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
```
Ohne Worker geht es auch direkt: Server und Secret in `config.js` unter `turnServers` eintragen (`staticAuthSecret`). Das Secret ist dann öffentlich — die Limits oben sind dann Pflicht.
Dann in `wrangler.toml` `COTURN_URLS` setzen und das Secret hinterlegen:
```bash
npx wrangler secret put COTURN_SECRET
npx wrangler deploy
```

## Chat-Seite anbinden

1. In `config.js` eintragen:
   ```js
   turnCredentialsUrl: "https://hard-chat-turn.DEIN-ACCOUNT.workers.dev/",
   ```
2. In `index.html` die Worker-Origin in der Content Security Policy unter `connect-src` ergänzen:
   ```
   connect-src https://0.peerjs.com wss://0.peerjs.com https://hard-chat-turn.DEIN-ACCOUNT.workers.dev;
   ```
   Fehlt dieser Eintrag, blockiert der Browser den Abruf. Die Seite zeigt dann `[WARN] TURN endpoint unreachable` und versucht es ohne Relay.
3. Optional `forceRelay: true` setzen. Dann läuft alles über dein Relay, und das Gegenüber erfährt deine IP-Adresse nicht.

## Grenzen

- Die Origin-Prüfung hält nur Browser auf anderen Webseiten ab. Mit `curl` lässt sich der Origin-Header fälschen. Deshalb ist das Rate Limiting in `wrangler.toml` aktiv (10 Abrufe pro Minute und IP), und die Zugangsdaten verfallen nach `CRED_TTL` Sekunden.
- Bei Cloudflare TURN fallen ab einem Freikontingent Traffic-Kosten an. Prüfe die aktuellen Preise im Dashboard.
