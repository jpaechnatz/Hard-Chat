# 🔒 Zero-Trace Terminal

> End-to-end encrypted P2P chat, right in your browser. No server, no accounts, no stored history.

**by Hardlint Cybersecurity Team**

---

## ⚠️ Important Notice

This project is distributed **for educational and security research purposes**. It does not guarantee network-level anonymity: it protects the **content** of conversations, not necessarily **who** is connecting. Read the [Attack Surface and Known Limitations](#-attack-surface-and-known-limitations) section before using it for sensitive communications.

**Use of a trustworthy VPN on both devices is strongly recommended.**

---

## ✨ Features

- 🔐 **End-to-end encryption** — AES-GCM 256-bit with separate keys per direction (PBKDF2 → HKDF), sequence numbers against replay/reordering
- 🤝 **Key confirmation handshake** — a peer only counts as connected after proving it holds the Room Key; the room accepts exactly one authenticated peer
- 🔄 **Forward secrecy** — ephemeral ECDH (P-256) per connection: a Room Key leaked later does not reveal past conversations
- 🗣️ **Security code (SAS)** — six symbols both sides compare by voice; detects an attacker who intercepted the Room Key and sits in the middle
- 📱 **QR code / invite link** — hand over the Room Key in person without any other channel; the key travels in the URL fragment, which is never sent to a server
- 🌐 **True P2P connection** — direct WebRTC link between the two devices, no central server relaying messages
- 🚫 **Zero persistence** — no cookies, no localStorage, no database: close the tab and nothing remains
- 🔑 **Single shared secret** — a randomly generated Room Key (100 characters), no manual technical configuration required
- 🧹 **Panic Purge** — closes connections, releases session keys, wipes the visible history and overwrites the clipboard (best effort)
- 📡 **No third-party relay** — direct peer-to-peer connections only (IPv6 or IPv4 hole punching via adminForge STUN, no IP logging according to the operator); an own TURN relay can be added optionally
- 🛡️ **No third-party code at runtime** — PeerJS and fonts are served from the repo itself (SRI-pinned), strict Content Security Policy

---

## 🚀 How to Use

1. **Open the page** (must be served over HTTPS — e.g. via GitHub Pages, not opened as a local file)
2. **Host:** click `[1] INITIALIZE ROOM`
3. Hand the Room Key to your contact — best option first:
   - **In person:** `[ SHOW QR CODE ]` → the guest scans it with the phone camera; the page opens and connects automatically
   - **Remotely:** `[ COPY INVITE LINK ]` or `[ COPY KEY ]` and send it through a *different*, ideally end-to-end encrypted channel
4. **Guest:** opens the invite link — or clicks `[2] CONNECT TO ROOM` and pastes the Room Key
5. Wait for the connection (usually a few seconds) → enter the chat
6. **Verify:** both see six symbols (e.g. 🐶 Dog · 🔑 Key · …). Compare them by voice or in person and press `[ ✓ IDENTICAL ]`. If they differ, press `[ ✗ DIFFERENT ]` — someone intercepted the Room Key and is sitting in the middle
7. If no connection is established within 2 minutes, the Room Key expires: generate a new one

---

## 🧩 Deployment

1. **GitHub Pages:** repository *Settings → Pages → Deploy from a branch → `main` / `(root)`*. The app is then available at `https://<user>.github.io/hard-chat/`. That's all that is required.
2. **Optional:** `forceRelay: true` together with an own TURN relay (your peer never learns your IP), a self-hosted credential endpoint ([`turn-worker/`](turn-worker/README.md)), or a self-hosted PeerJS signaling server — see [`config.js`](config.js).

**No TURN relay by default — on purpose.** A TURN relay is the only way through every firewall, but there is no trustworthy *public* one: relays with published credentials (OpenRelay, freestun, …) are run by unknown parties, get abused as free proxies and are frequently down (the Open Relay static-auth endpoint did not respond in our test, October 2026), and the reputable options require an account with a commercial (non-EU) provider. Without a relay, Hard-Chat connects directly — via IPv6 or IPv4 hole punching — which works on most home and mobile connections. On strict networks (company, hotel, guest Wi-Fi) the app shows `[NO DIRECT PATH]`; switching to mobile data usually helps.

---

## 📋 Requirements

- Modern browser with WebRTC and Web Crypto API support (recent Chrome, Firefox, Edge, Safari)
- Internet access on both devices
- The page **must** be served over HTTPS (Secure Context is required for Web Crypto API and WebRTC) — it does not work when opened as a local file
- Both parties must have the page open **at the same time** during the connection attempt
- The Room Key must be copied **in full, exactly 100 characters**, with no extra spaces or line breaks

---

## 🏗️ Architectural Overview

Zero-Trace Terminal is a static web application (HTML/CSS/JS, no proprietary backend) that allows two devices to establish a **direct peer-to-peer connection** via WebRTC, exchanging end-to-end encrypted text messages.

**Main components:**

| Component | Role | Technology |
|---|---|---|
| User interface | Retro terminal UI | Plain HTML/CSS |
| Signaling | Makes the two peers "find" each other | PeerJS (public cloud broker) |
| Data transport | Encrypted P2P channel | WebRTC DataChannel |
| NAT traversal | Punching through firewalls/NAT | STUN + TURN (ICE) |
| Encryption | Message content protection | AES-GCM 256-bit + PBKDF2 |
| Hosting | Code distribution | GitHub Pages (static) |

There is no proprietary application server: the code runs entirely in each user's browser. The only external infrastructure involved is used to "introduce" the two devices to each other (signaling) and, if needed, to relay traffic when a direct connection isn't possible (TURN).

---

## 🔄 Operational Flow

### Room Key Generation

When a user clicks **"INITIALIZE ROOM (HOST)"**:

1. A random **100-character** string is generated (`generateRoomKey()`, rejection sampling), using `crypto.getRandomValues()` — a cryptographically secure random number generator (not `Math.random()`, which is unsuitable for cryptographic purposes).
2. The character set includes uppercase/lowercase letters, digits, and special symbols (`-_!@#$%^&*`), maximizing entropy within 100 characters.

This string (the **Room Key**) is the only shared secret the two parties need to exchange, out-of-band (e.g. voice message, in person, another encrypted channel).

### Deriving Keys from the Room Key

Three independent values are derived from the Room Key (protocol v3):

```
master = PBKDF2(password = Room Key, salt = "ztt-v3-pbkdf2-salt", iterations = 100,000, hash = SHA-256) → 256 bit

hs_host→guest  = HKDF-SHA256(master, info = "ztt-v3 handshake host->guest") → AES-GCM-256, non-extractable
hs_guest→host  = HKDF-SHA256(master, info = "ztt-v3 handshake guest->host") → AES-GCM-256, non-extractable
peer_id        = "ztt3-" + hex(HKDF-SHA256(master, info = "ztt-v3 peer-id", 128 bit))
```

The handshake keys are only used for the key confirmation handshake below; chat messages use per-connection keys derived from an ephemeral ECDH exchange, both nonces and the Room Key. The peer ID is the only Room-Key-derived value the signaling broker ever sees; it is domain-separated from the encryption keys. Separate keys per direction make it impossible to reflect a party's own messages back to it. The keys are created as **non-extractable** `CryptoKey` objects.

The Room Key generator uses rejection sampling, so every character of the 72-character alphabet is equally likely (≈617 bits of entropy).

> **Note on the fixed salt:** the PBKDF2 salt is hardcoded and identical across all sessions. This is acceptable because the "password" (Room Key) already has very high entropy (100 random characters) — a fixed salt only weakens security in scenarios involving weak, reused passwords, which does not apply here.

### Signaling Phase (PeerJS)

1. The Host creates a `Peer` object, registering with the public PeerJS cloud broker using the ID derived from the Room Key.
2. The Guest, after pasting the same Room Key, computes the same ID and calls `peer.connect(id)`.
3. The PeerJS broker only mediates this initial exchange (who wants to talk to whom) — **it never sees or transmits message content**, which by that point travels over a separate WebRTC channel.
4. Once the key confirmation handshake succeeds, both sides **disconnect from the broker**; the P2P channel stays open, and the room is no longer reachable for further connection attempts.

> **Why the handshake matters:** the broker also relays the DTLS fingerprints that secure WebRTC, so a malicious broker could in theory sit in the middle of the WebRTC connection. Because every packet is authenticated with keys derived from the Room Key, such a broker can only drop traffic; it cannot read, forge, replay, reorder or reflect messages.

### Key Confirmation Handshake

```
Guest → Host  : seal_hs_g2h(seq=0, {t:"hello", g:<nonce_guest, 128 bit>, c:SHA-256(pk_guest)})     (commitment; re-sent identically until answered)
Host  → Guest : seal_hs_h2g(seq=0, {t:"chal",  g:<nonce_guest>, n:<nonce_host>, pk:<pk_host>})   (re-sent identically until answered)
Guest → Host  : seal_hs_g2h(seq=1, {t:"resp",  n:<nonce_host>, pk:<pk_guest>})                  (reveal; host checks the commitment)

Both sides then switch to per-connection keys and restart the sequence numbers at 0:
ikm        = ECDH(own private key, peer public key) || HKDF(master, "ztt-v3 ecdh binding")
salt       = SHA-256("ztt-v3 transcript" || nonce_guest || nonce_host || pk_guest || pk_host)
key_conn_x = HKDF-SHA256(ikm, salt, info = "ztt-v3 conn host->guest" / "guest->host")
SAS        = HKDF-SHA256(ikm, salt, info = "ztt-v3 sas", 48 bit) → 6 × 6 bit → 6 of 64 symbols
```
The ephemeral private keys are non-extractable and discarded right after the derivation (**forward secrecy**). Each side proves possession of the Room Key **and** freshness (it echoes the other side's new nonce).

**Security code (SAS):** someone who intercepted the Room Key can decrypt the handshake and substitute their own ECDH keys towards both sides. Doing so inevitably produces two *different* SAS values. Because the guest commits to its public key before it sees the host's (as in ZRTP), the attacker cannot try many keys until the codes happen to match: each attempt succeeds with a probability of only 1 in ~69 billion (36 bits). Comparing the six symbols by voice or in person therefore detects such a man-in-the-middle; the status only shows `ENCRYPTED & VERIFIED ✓` after the user confirms. Only after a correct response does the host treat the connection as authenticated. Because chat messages use keys bound to both nonces, traffic recorded on an earlier connection cannot be replayed into a later one, even with the same Room Key. Connections that do not complete the handshake within 15 seconds after the channel opens are closed, at most 8 unauthenticated attempts are handled at once, and once a peer is authenticated every further incoming connection is rejected (it can no longer replace the active one).

### ICE Negotiation (NAT Traversal)

Once the two Peers have "introduced" themselves, WebRTC starts ICE negotiation to find a valid network path:

1. **Host candidates** — the device's local IP addresses
2. **Server-reflexive (srflx) candidates** — public IP discovered via STUN
3. **Relay candidates** — allocated via TURN, used only if a direct connection fails

**Configured ICE servers (in priority order):**

- **Default: no TURN relay.** Connections are direct only (host/IPv6 and STUN-assisted candidates). If no direct path exists, the app says so (`[NO DIRECT PATH]`) instead of hanging.
- **Optional TURN credential endpoint** (`turnCredentialsUrl`): your own endpoint (`turn-worker/`: coturn or Cloudflare Realtime TURN), returning `{iceServers:[…]}` or a plain array. Fetched fresh per session, validated, port-53 URLs filtered out.
- **Optional own TURN servers** (`turnServers`): fixed credentials or a coturn static-auth secret, from which the app derives time-limited credentials (TURN REST API scheme). Note that such a secret is public in `config.js`; run coturn with a bandwidth cap and `denied-peer-ip` for private ranges.
- **STUN:** `relay.adminforge.de:443` and `relay2.adminforge.de:443` (adminForge states it does not log IP addresses).
- Optional `forceRelay: true` sets `iceTransportPolicy: "relay"`: all traffic goes through the relay and the peer never learns your IP. Without a working relay the connection then fails on purpose (fail closed).

All previously hardcoded relays (the original author's Metered.ca account, OpenRelay, freestun, numb.viagenie, ExpressTurn with publicly known credentials) have been removed.

The browser automatically tries every combination and selects the first one that establishes a working channel (standard ICE algorithm, handled internally by WebRTC).

### Timeout and Session Expiry

- If no peer has been authenticated within **120 seconds**, the session is considered expired:
  - The `Peer` and `DataConnection` are destroyed (`peer.destroy()`, `conn.close()`)
  - The status shows `[EXPIRED] Room Key no longer valid`
  - A button appears to generate a new Room Key (Host) or enter a new one (Guest)
- This prevents a Room Key from remaining "listening" indefinitely on the public broker.
- Every session is an isolated object; all its timers are cleared when it ends (new key, back to menu, Panic Purge), so a stale timer from an earlier session can no longer kill a newer one.

---

## 🔐 Message Cryptographic Model

Every message is individually encrypted before being sent over the DataChannel:

```
1. header = [version=3, 0, 0, 0, seq (uint32, big endian)]      (8 bytes, seq starts at 0 per direction)
2. IV = 12 random bytes (crypto.getRandomValues)
3. ciphertext = AES-GCM-Encrypt(key_my_direction, IV, JSON{t, ...}, additionalData = header)
4. packet = header || IV || ciphertext   → sent as raw ArrayBuffer over the DataChannel
```

On receipt:
```
1. Check version and that seq == next expected sequence number (otherwise: reject)
2. plaintext = AES-GCM-Decrypt(key_peer_direction, IV, ciphertext, additionalData = header)
3. Accept, increment expected sequence number
```
Any rejected packet on an authenticated channel terminates the connection with a `[SECURITY]` notice instead of being silently skipped. Sending and receiving are strictly serialized so the order on the wire always matches the sequence numbers.

**Security properties guaranteed by AES-GCM:**
- **Confidentiality** — nobody without the key can read the content
- **Integrity/authenticity** — any tampering with the packet in transit causes decryption to fail and the connection to be terminated
- **Replay / reordering / reflection protection** — sequence numbers are authenticated as AAD, and each direction has its own key

**What this scheme does NOT cover:**
- **Unverified sessions** — if the security code is *not* compared, an attacker who intercepted the Room Key can still sit in the middle unnoticed. The app shows `ENCRYPTED — NOT YET VERIFIED` until the codes are confirmed.
- **Peer identity authentication** — anyone who knows the Room Key can connect; there is no cryptographic verification of "who" is on the other end beyond possession of the shared key. Whoever obtains the Room Key first (e.g. by intercepting the out-of-band channel) can take the guest's place. The security code comparison exposes this as well: the real guest has no matching code to read out.
- **Compromised device** — malware or a malicious browser extension on either device sees everything in plain text; no protocol can prevent that.

---

## 💾 Data Persistence (Client-Side)

| Data | Persistence | Notes |
|---|---|---|
| Room Key | None | Only in a JS variable, gone on close/reload. Invite links carry it in the URL fragment, which the page removes from the address bar immediately (`history.replaceState`) |
| ECDH private keys | None | Non-extractable, generated per connection, discarded after key derivation |
| Derived AES-GCM keys | None | Non-extractable `CryptoKey` objects, never written to disk |
| Chat messages | None | Only live in the DOM/RAM, no localStorage/IndexedDB |
| Cookies | None | The project uses none at all |
| Application logs | Off by default | `debug: true` in `config.js` enables console logs (they contain IP addresses) |

The **"PANIC: PURGE SESSION"** button:
- notifies the peer (best effort) and closes the `PeerConnection`/`DataConnection`
- drops all references to the session keys and clears all timers
- wipes all UI fields and the displayed message history
- overwrites the clipboard, which may still contain the Room Key (if the browser permits)

> **Honest limitation:** JavaScript cannot guarantee that memory is physically overwritten; released objects are freed by the garbage collector at an unspecified time. Close the tab for the best effect. Clipboard managers or the OS clipboard history may still hold the Room Key.

---

## 👁️ What External Infrastructure Can See (Metadata)

Key point to understand: **encryption protects content, not connection metadata**.

| Service | What it can see | What it CANNOT see |
|---|---|---|
| **GitHub Pages** | IP and timestamp of whoever loads the page (all code, PeerJS and fonts are served from here — no Google Fonts or unpkg requests) | Message content, Room Key |
| **PeerJS broker** (public cloud) | IP of Host and Guest, when they connect, their Peer ID (a hash of the Room Key, not the Key itself) | Message content |
| **Your TURN relay** (Cloudflare or own coturn, if used) | Source/destination IP, ports, amount of data transferred | Message content (already travels encrypted) |
| **Your credential worker** | IP of whoever requests TURN credentials | Room Key, message content |
| **Each user's ISP** | That a connection is being made to github.io / the TURN relay / a PeerJS server | Message content |

**Recommended mitigation (outside the code):** use a trustworthy VPN (e.g. Mullvad, with an anonymously created account) on both devices, to avoid exposing real IP addresses to these third-party services. The project displays an explicit warning to this effect on the splash screen.

---

## 🎯 Attack Surface and Known Limitations

| Risk | Description | Mitigated? |
|---|---|---|
| Message content interception | MITM on TURN/network traffic | ✅ Yes — end-to-end AES-GCM |
| Message tampering in transit | Packet manipulation | ✅ Yes — GCM authentication tag, connection is terminated |
| Intercepted Room Key → man-in-the-middle | Attacker with the key relays and reads everything | ✅ Detectable — security code (SAS) comparison; QR handover avoids interception altogether |
| Room Key leaked after the conversation | Decrypting recorded traffic later | ✅ Yes — forward secrecy via ephemeral ECDH |
| Replay / reordering / reflection | Re-sending or bouncing back captured packets (e.g. by a malicious broker) | ✅ Yes — authenticated sequence numbers + per-direction keys |
| Session hijack / DoS via second connection | Third party connects to the room ID and replaces the active connection | ✅ Yes — key confirmation handshake, one authenticated peer only, broker left after handshake |
| Compromised CDN / supply chain | Manipulated PeerJS from a CDN steals keys | ✅ Yes — PeerJS served from the repo, SRI hash, strict CSP (no inline scripts, no foreign hosts) |
| Leaked relay credentials | Credentials hardcoded in public code | ✅ Yes — no relay credentials in the default configuration |
| No connection behind strict firewalls | Without TURN, symmetric NAT / blocked UDP prevents a direct path | ⚠️ Accepted trade-off — clear error message; optional own TURN relay |
| Invite link in history/camera app | The URL with the Room Key may be stored by the scanning app or browser history | ⚠️ Partial — fragment removed from the address bar on load (the global browser history or the scanner app may still keep the original URL); key expires after 120 s or once a peer is authenticated |
| Clickjacking | Page embedded invisibly in a foreign site (e.g. to trick a click on "IDENTICAL") | ✅ Yes — the app refuses to run inside a frame (GitHub Pages cannot send `frame-ancestors` headers) |
| Deanonymization via IP metadata | IP↔identity correlation through third-party logs | ⚠️ Partial — `forceRelay` hides your IP from the peer; towards broker/relay a VPN is still required |
| Abuse of the credential worker | Origin header can be forged outside browsers | ⚠️ Partial — rate limiting + short TTL, not authentication |
| Dependency on third-party services | GitHub Pages, PeerJS broker, TURN provider — if suspended, the app stops working | ⚠️ Partial — signaling and TURN are configurable/self-hostable |
| Room Key reuse | Would compromise forward secrecy across sessions that reuse it | ✅ Not applicable in normal flow (a new Key every session) |

---

## 🛠️ Full Technology Stack

- **Frontend:** HTML5, CSS3 (no framework)
- **Cryptography:** Browser-native Web Crypto API (`crypto.subtle`) — PBKDF2, AES-GCM, SHA-256
- **P2P/Signaling:** [PeerJS](https://peerjs.com/) v1.5.4 (a wrapper library over native WebRTC), vendored unmodified from the npm package into `vendor/`, pinned with an SRI hash
- **NAT Traversal:** WebRTC ICE — own TURN relay via short-lived credentials (`turn-worker/`), STUN fallback
- **Fonts:** Fira Code (SIL OFL), served locally from `assets/fonts/`
- **QR codes:** [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.5.2 (MIT), vendored unmodified, SRI-pinned
- **Key exchange:** WebCrypto ECDH P-256 (ephemeral), HKDF-SHA256
- **Hardening:** Content Security Policy (`default-src 'none'`, scripts only from the same origin, no inline scripts/handlers), `no-referrer`
- **Hosting:** GitHub Pages (static, automatic HTTPS)
- **Browser requirements:** WebRTC support, Web Crypto API, ES6+ — requires a secure context (HTTPS); does not work from `file://` or `content://`

---

## 📝 Changelog of Major Versions

1. **v1** — Native WebRTC with manual SDP exchange (copy/paste offer/answer)
2. **v2** — Migrated to PeerJS, automatic connection based on the Room Key, removed manual SDP fields
3. **v3** — Added dedicated Metered.ca TURN + multiple public STUN/TURN fallbacks
4. **v4** — Detailed ICE diagnostics (candidate logging, connection states) — fixed a bug that overwrote PeerJS's internal event handlers
5. **v5** — Timeout extended to 120s, Room Key expiry system with manual regeneration, VPN warning on splash screen, TURN credential obfuscation
6. **v6 (fork, protocol v2)** — Security hardening: PeerJS/fonts self-hosted with SRI + strict CSP; per-direction keys (HKDF), authenticated sequence numbers, key confirmation handshake, single authenticated peer, broker disconnect after handshake; fixed stale-timer bug; removed hardcoded/public TURN credentials in favour of a self-hosted credential worker; IP-free logging by default. **Not compatible with v1–v5 clients.**
7. **v7 (fork, protocol v3)** — Ephemeral ECDH key exchange (forward secrecy), security code (SAS) verification, QR code / invite link handover, adminForge STUN, no third-party TURN by default (optional own relay). **Not compatible with v6 clients.**

---

## 💚 Support the Project

Hard-Chat is 100% free, open-source, and maintained by the Hardlint Cybersecurity Team. We don't run ads and we don't sell data. If you believe in our mission and want to help us fund our future self-hosted infrastructure (custom STUN/TURN servers), consider supporting us!

**Solana (SOL) donation address:**
```
GSsqZCtDC7rf53U6gC5cJ4weAYYT9g7twxz9t15mfRDV
```

---

## 📜 License and Disclaimer

This software is provided "as is", without warranties of any kind. The developers are not responsible for any improper or illegal use of this tool. Users are solely responsible for complying with applicable laws in their jurisdiction.

This document is provided for informational and technical documentation purposes only. It does not constitute legal advice regarding regulatory compliance, privacy, or liability for use.

---

<div align="center">

**Hardlint Cybersecurity Team**

</div>
