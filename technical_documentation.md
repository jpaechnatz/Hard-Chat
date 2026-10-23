# Zero-Trace Terminal — Technical Documentation

**Project:** Hardlint Cybersecurity Team
**Type:** Browser-based, end-to-end encrypted P2P chat
**Last updated:** October 2026 (fork hardening, protocol v2)

---

## 1. Architectural Overview

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

## 2. Operational Flow

### 2.1 Room Key Generation

When a user clicks **"INITIALIZE ROOM (HOST)"**:

1. A random **100-character** string is generated (`generateRoomKey()`, rejection sampling), using `crypto.getRandomValues()` — a cryptographically secure random number generator (not `Math.random()`, which is unsuitable for cryptographic purposes).
2. The character set includes uppercase/lowercase letters, digits, and special symbols (`-_!@#$%^&*`), maximizing entropy within 100 characters.

This string (the **Room Key**) is the only shared secret the two parties need to exchange, out-of-band (e.g. voice message, in person, another encrypted channel).

### 2.2 Deriving Keys from the Room Key

Three independent values are derived from the Room Key (protocol v2):

```
master = PBKDF2(password = Room Key, salt = "ztt-v2-pbkdf2-salt", iterations = 100,000, hash = SHA-256) → 256 bit

hs_host→guest  = HKDF-SHA256(master, info = "ztt-v2 handshake host->guest") → AES-GCM-256, non-extractable
hs_guest→host  = HKDF-SHA256(master, info = "ztt-v2 handshake guest->host") → AES-GCM-256, non-extractable
peer_id        = "ztt2-" + hex(HKDF-SHA256(master, info = "ztt-v2 peer-id", 128 bit))
```

The handshake keys are only used for the key confirmation handshake below; chat messages use per-connection keys derived from two fresh nonces. The peer ID is the only Room-Key-derived value the signaling broker ever sees; it is domain-separated from the encryption keys. Separate keys per direction make it impossible to reflect a party's own messages back to it. The keys are created as **non-extractable** `CryptoKey` objects.

The Room Key generator uses rejection sampling, so every character of the 72-character alphabet is equally likely (≈617 bits of entropy).

> **Note on the fixed salt:** the PBKDF2 salt is hardcoded and identical across all sessions. This is acceptable because the "password" (Room Key) already has very high entropy (100 random characters) — a fixed salt only weakens security in scenarios involving weak, reused passwords, which does not apply here.

### 2.3 Signaling Phase (PeerJS)

1. The Host creates a `Peer` object, registering with the public PeerJS cloud broker using the ID derived from the Room Key.
2. The Guest, after pasting the same Room Key, computes the same ID and calls `peer.connect(id)`.
3. The PeerJS broker only mediates this initial exchange (who wants to talk to whom) — **it never sees or transmits message content**, which by that point travels over a separate WebRTC channel.
4. Once the key confirmation handshake succeeds, both sides **disconnect from the broker**; the P2P channel stays open, and the room is no longer reachable for further connection attempts.

> **Why the handshake matters:** the broker also relays the DTLS fingerprints that secure WebRTC, so a malicious broker could in theory sit in the middle of the WebRTC connection. Because every packet is authenticated with keys derived from the Room Key, such a broker can only drop traffic; it cannot read, forge, replay, reorder or reflect messages.

### 2.3a Key Confirmation Handshake

```
Guest → Host  : seal_hs_g2h(seq=0, {t:"hello", g:<nonce_guest, 128 bit>})            (re-sent identically until answered)
Host  → Guest : seal_hs_h2g(seq=0, {t:"chal",  g:<nonce_guest>, n:<nonce_host>})     (re-sent identically until answered)
Guest → Host  : seal_hs_g2h(seq=1, {t:"resp",  n:<nonce_host>})

Both sides then switch to per-connection keys and restart the sequence numbers at 0:
key_conn_x = HKDF-SHA256(master, salt = nonce_guest || nonce_host, info = "ztt-v2 conn host->guest" / "guest->host")
```
Each side proves possession of the Room Key **and** freshness (it echoes the other side's new nonce). Only after a correct response does the host treat the connection as authenticated. Because chat messages use keys bound to both nonces, traffic recorded on an earlier connection cannot be replayed into a later one, even with the same Room Key. Connections that do not complete the handshake within 15 seconds after the channel opens are closed, at most 8 unauthenticated attempts are handled at once, and once a peer is authenticated every further incoming connection is rejected (it can no longer replace the active one).

### 2.4 ICE Negotiation (NAT Traversal)

Once the two Peers have "introduced" themselves, WebRTC starts ICE negotiation to find a valid network path:

1. **Host candidates** — the device's local IP addresses
2. **Server-reflexive (srflx) candidates** — public IP discovered via STUN
3. **Relay candidates** — allocated via TURN, used only if a direct connection fails

**Configured ICE servers (in priority order):**

- **Your own TURN relay**, with short-lived credentials fetched per session from `turnCredentialsUrl` (see `turn-worker/`: Cloudflare Realtime TURN or a self-hosted coturn using the TURN REST API scheme). The response is validated; port-53 URLs (blocked by browsers) are filtered out.
- **STUN fallback** from `config.js` (default: `stun.cloudflare.com:3478`) if no endpoint is configured or it is unreachable.
- Optional `forceRelay: true` sets `iceTransportPolicy: "relay"`: all traffic goes through your relay and the peer never learns your IP. Without TURN credentials the connection then fails on purpose (fail closed).

All previously hardcoded relays (the original author's Metered.ca account, OpenRelay, freestun, numb.viagenie, ExpressTurn with publicly known credentials) have been removed: anyone could operate or log those shared relays.

The browser automatically tries every combination and selects the first one that establishes a working channel (standard ICE algorithm, handled internally by WebRTC).

### 2.5 Timeout and Session Expiry

- If no peer has been authenticated within **120 seconds**, the session is considered expired:
  - The `Peer` and `DataConnection` are destroyed (`peer.destroy()`, `conn.close()`)
  - The status shows `[EXPIRED] Room Key no longer valid`
  - A button appears to generate a new Room Key (Host) or enter a new one (Guest)
- This prevents a Room Key from remaining "listening" indefinitely on the public broker.
- Every session is an isolated object; all its timers are cleared when it ends (new key, back to menu, Panic Purge), so a stale timer from an earlier session can no longer kill a newer one.

---

## 3. Message Cryptographic Model

Every message is individually encrypted before being sent over the DataChannel:

```
1. header = [version=2, 0, 0, 0, seq (uint32, big endian)]      (8 bytes, seq starts at 0 per direction)
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
- **Forward secrecy across sessions** — if the same Room Key were reused across multiple sessions (not the normal flow, which generates a new one every time), all those sessions would share the same master key (per-connection keys differ, but are derivable by anyone holding the Room Key)
- **Peer identity authentication** — anyone who knows the Room Key can connect; there is no cryptographic verification of "who" is on the other end beyond possession of the shared key. Whoever obtains the Room Key first (e.g. by intercepting the out-of-band channel) can take the guest's place.
- **Forward secrecy within a session** — whoever obtains the Room Key *and* recorded the traffic (which additionally requires breaking or bypassing WebRTC's DTLS layer) can decrypt that session.

---

## 4. Data Persistence (Client-Side)

| Data | Persistence | Notes |
|---|---|---|
| Room Key | None | Only in a JS variable, gone on close/reload |
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

## 5. What External Infrastructure Can See (Metadata)

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

## 6. Attack Surface and Known Limitations

| Risk | Description | Mitigated? |
|---|---|---|
| Message content interception | MITM on TURN/network traffic | ✅ Yes — end-to-end AES-GCM |
| Message tampering in transit | Packet manipulation | ✅ Yes — GCM authentication tag, connection is terminated |
| Replay / reordering / reflection | Re-sending or bouncing back captured packets (e.g. by a malicious broker) | ✅ Yes — authenticated sequence numbers + per-direction keys |
| Session hijack / DoS via second connection | Third party connects to the room ID and replaces the active connection | ✅ Yes — key confirmation handshake, one authenticated peer only, broker left after handshake |
| Compromised CDN / supply chain | Manipulated PeerJS from a CDN steals keys | ✅ Yes — PeerJS served from the repo, SRI hash, strict CSP (no inline scripts, no foreign hosts) |
| Leaked relay credentials | Credentials hardcoded in public code | ✅ Yes — short-lived credentials from your own worker; worker restricted by origin and rate limit |
| Deanonymization via IP metadata | IP↔identity correlation through third-party logs | ⚠️ Partial — `forceRelay` hides your IP from the peer; towards broker/relay a VPN is still required |
| Abuse of the credential worker | Origin header can be forged outside browsers | ⚠️ Partial — rate limiting + short TTL, not authentication |
| Dependency on third-party services | GitHub Pages, PeerJS broker, TURN provider — if suspended, the app stops working | ⚠️ Partial — signaling and TURN are configurable/self-hostable |
| Room Key reuse | Would compromise forward secrecy across sessions that reuse it | ✅ Not applicable in normal flow (a new Key every session) |

---

## 7. Full Technology Stack

- **Frontend:** HTML5, CSS3 (no framework)
- **Cryptography:** Browser-native Web Crypto API (`crypto.subtle`) — PBKDF2, AES-GCM, SHA-256
- **P2P/Signaling:** [PeerJS](https://peerjs.com/) v1.5.4 (a wrapper library over native WebRTC), vendored unmodified from the npm package into `vendor/`, pinned with an SRI hash
- **NAT Traversal:** WebRTC ICE — own TURN relay via short-lived credentials (`turn-worker/`), STUN fallback
- **Fonts:** Fira Code (SIL OFL), served locally from `assets/fonts/`
- **Hardening:** Content Security Policy (`default-src 'none'`, scripts only from the same origin, no inline scripts/handlers), `no-referrer`
- **Hosting:** GitHub Pages (static, automatic HTTPS)
- **Browser requirements:** WebRTC support, Web Crypto API, ES6+ — requires a secure context (HTTPS); does not work from `file://` or `content://`

---

## 8. Requirements for Correct Operation

- Both devices need **internet access** (to reach the PeerJS broker and ICE servers)
- The page must be served over **HTTPS** (GitHub Pages guarantees this automatically) — it **will not work** if opened as a local file (`content://`, `file://`) due to Secure Context restrictions on the Web Crypto API and WebRTC
- Both parties must have the page open **at the same time** during the connection attempt (signaling is not persistent/asynchronous)
- The Room Key must be copied **in full, exactly 100 characters**, with no extra spaces or line breaks introduced by copy-paste
- For connections behind restrictive NATs: a configured TURN credential endpoint (`config.js` → `turnCredentialsUrl`, see `turn-worker/README.md`)
- Both parties must use the same protocol version (v6/protocol v2 is not compatible with earlier versions)

---

## 9. Changelog of Major Versions

1. **v1** — Native WebRTC with manual SDP exchange (copy/paste offer/answer)
2. **v2** — Migrated to PeerJS, automatic connection based on the Room Key, removed manual SDP fields
3. **v3** — Added dedicated Metered.ca TURN + multiple public STUN/TURN fallbacks
4. **v4** — Detailed ICE diagnostics (candidate logging, connection states) — fixed a bug that overwrote PeerJS's internal event handlers
5. **v5** — Timeout extended to 120s, Room Key expiry system with manual regeneration, VPN warning on splash screen, TURN credential obfuscation
6. **v6 (fork, protocol v2)** — Security hardening: PeerJS/fonts self-hosted with SRI + strict CSP; per-direction keys (HKDF), authenticated sequence numbers, key confirmation handshake, single authenticated peer, broker disconnect after handshake; fixed stale-timer bug; removed hardcoded/public TURN credentials in favour of a self-hosted credential worker; IP-free logging by default. **Not compatible with v1–v5 clients.**

---

*This document is provided for internal technical documentation purposes only. It does not constitute legal advice regarding regulatory compliance, privacy, or liability for use.*
