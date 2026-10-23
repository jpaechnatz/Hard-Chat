# TURN-Credential-Worker

Ein kleiner Cloudflare Worker, der der Chat-Seite **kurzlebige** TURN-Zugangsdaten ausstellt. Die eigentlichen Geheimnisse (API-Token bzw. coturn-Secret) liegen nur im Worker und nie im öffentlichen Repo. Damit ersetzt er die früher fest eingebauten Zugangsdaten (Metered.ca des Original-Autors sowie öffentliche Gratis-Relays).

## Warum überhaupt TURN?

Ohne TURN klappt die Verbindung nur, wenn beide Seiten sich direkt erreichen (STUN/Hole-Punching). Hinter symmetrischem NAT (häufig im Mobilfunk und in Firmennetzen) braucht es ein Relay. Der TURN-Betreiber sieht IP-Adressen und Datenmenge, aber **keine Inhalte**, weil die Nachrichten Ende-zu-Ende verschlüsselt sind.

## Variante A: Cloudflare Realtime TURN (am einfachsten)

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

coturn-Konfiguration (Auszug):
```
use-auth-secret
static-auth-secret=<langes-zufälliges-secret>
realm=turn.example.org
```
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
