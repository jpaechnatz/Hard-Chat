<p align="center"><img src="assets/logo.svg" width="96" alt=""></p>

<h1 align="center">P2P Terminal</h1>

<p align="center">
End-to-end encrypted peer-to-peer chat in the browser, with a retro terminal look.<br>
No accounts, no message server, no history.
</p>

<p align="center"><b><a href="https://jpaechnatz.github.io/Hard-Chat/">→ Open the app</a></b></p>

---

## ✨ What it does

- 🔐 **End-to-end encrypted:** AES-GCM-256 with fresh keys for every connection (ephemeral ECDH P-256 → forward secrecy).
- 🗣️ **Man-in-the-middle detection:** both sides see six symbols (e.g. 🐶 Dog · 🔑 Key · …) and compare them by voice or in person.
- 📱 **QR code / invite link:** hand over the room key in person, with no other channel involved.
- 🌐 **Direct connection first:** messages go straight from browser to browser over WebRTC. A TURN relay (encrypted, TLS) only steps in when no direct path exists, and no server stores anything.
- 🚫 **No persistence:** no cookies, no storage, no logs. Close the tab and nothing is left.
- 🧹 **Panic purge:** one button ends the session, wipes the chat and overwrites the clipboard.
- 🛡️ **No third-party code at runtime:** all scripts and fonts are served from this repository (SRI-pinned), and a strict Content Security Policy is in place.

## 🚀 How to use

1. **Host:** open the app → `[1] INITIALIZE ROOM`.
2. **Hand over the room key**, best option first:
   - **In person:** `[ SHOW QR CODE ]`. The guest scans it with the phone camera and the chat opens and connects automatically.
   - **Remotely:** `[ COPY INVITE LINK ]` or `[ COPY KEY ]`, sent through a *different*, ideally end-to-end encrypted channel.
3. **Guest:** open the invite link, or `[2] CONNECT TO ROOM` and paste the key.
4. **Verify:** compare the six symbols by voice or in person.
   - Identical → `[ ✓ IDENTICAL ]`, and the status turns to `ENCRYPTED & VERIFIED ✓`.
   - Different → `[ ✗ DIFFERENT ]`. Someone intercepted the key and is sitting in the middle; the session ends immediately.
5. A room key expires after 2 minutes if nobody joins, and it is useless once a peer is connected.

## 📶 Will it connect? (network limits)

The browser always tries a **direct connection** first (IPv6, or IPv4 with STUN-assisted hole punching via adminForge). Only if that is impossible does it fall back to a **TURN relay** ([Metered](https://www.metered.ca/), free tier).

| Situation | Path |
|---|---|
| Both devices have **IPv6**, or one side has an "open" IPv4 NAT | ✅ direct |
| Both sides behind **carrier NAT / DS-Lite / symmetric NAT** | ↪️ relay |
| Company, hotel, guest or school Wi-Fi with a strict firewall | ↪️ relay (TURN over TLS on port 443 gets through most firewalls) |

**About the relay:**
- **What it sees:** the relay forwards already encrypted data. It sees IP addresses and data volume, never message content.
- **TLS only:** the connection to the relay itself uses TLS (TURNS, port 443), so even the TURN username stays hidden from network observers.
- **Public credentials:** the credentials in `config.js` are only Base64-obfuscated, which keeps automated scanners away but not humans. Anyone can use them, and the free tier (500 MB/month) simply stops when exhausted. Text chat needs only a tiny fraction of that.
- **Hide your IP from your peer:** set `forceRelay: true`. Then all traffic goes through the relay.

If neither a direct path nor the relay works, the app shows `[NO PATH]` after 45 seconds at the latest.

**Troubleshooting:** open `[3] NETWORK CHECK` on *both* devices. It checks the signaling server, STUN (IPv4/IPv6, NAT type) and whether data really flows through the relay, and then tells you whether this network can work. No IP addresses are displayed.

**Your own copy:** create your own TURN credentials (Metered, or your own coturn; see [`turn-worker/README.md`](turn-worker/README.md)) and replace the entry in `config.js`. Please don't use the credentials of this deployment.

## 🔒 Security in short

| Protects against | How |
|---|---|
| Eavesdropping on network, broker or relay | End-to-end AES-GCM, keys never leave the browser |
| Someone who intercepted the room key | Security code comparison (36 bit, commitment prevents brute-forcing a match) |
| Room key leaked later | Forward secrecy: ephemeral ECDH keys are discarded after each connection |
| Replayed, reordered or reflected messages | Authenticated sequence numbers, separate keys per direction |
| A third person joining | The room accepts exactly one authenticated peer, then leaves the signaling server |
| Compromised CDN / injected scripts | Self-hosted, SRI-pinned dependencies, strict CSP, no inline code |
| Clickjacking | The app refuses to run inside a frame |

**Not protected:**
- **Metadata:** the PeerJS signaling server, the STUN servers and (if used) the TURN relay see your IP address and when you connect. Use a VPN if that matters.
- **Skipped verification:** if you don't compare the symbols, an attacker who obtained the room key could sit in the middle unnoticed.
- **Compromised device:** malware or a malicious browser extension sees everything.

Full details: [technical_documentation.md](technical_documentation.md).

## 🧩 Hosting your own copy

1. Fork this repository.
2. Enable GitHub Pages: *Settings → Pages → Deploy from a branch → `main` / `(root)`*.
3. Optional settings live in [`config.js`](config.js):
   - own TURN relay and `forceRelay` (hides your IP from your peer)
   - self-hosted PeerJS signaling server
   - STUN servers

   Any HTTP(S) endpoint you add there must also be added to `connect-src` in the CSP in `index.html`.

Requirements: a recent Chrome, Firefox, Edge or Safari, and HTTPS (the app does not work from `file://`). Both people must have the page open at the same time.

## 🛠️ Built with

- Plain HTML/CSS/JS, no framework, no build step
- [PeerJS](https://peerjs.com/) 1.5.4 for WebRTC signaling (public PeerJS cloud broker by default)
- Web Crypto API: PBKDF2, HKDF, ECDH P-256, AES-GCM
- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.5.2 (MIT)
- [Fira Code](https://github.com/tonsky/FiraCode) font (SIL OFL)
- STUN: [adminForge](https://adminforge.de/service-stun-server) (no IP logging according to the operator)

## 🙏 Origin

Started as a fork of *Hard-Chat / Zero-Trace Terminal*. It has since been reworked substantially:
- security hardening
- new protocol (v3: ECDH, security code, replay protection)
- QR handover
- no hardcoded relay credentials
- neutral design

The protocol is **not compatible** with the original version.

## ⚠️ Disclaimer

Provided "as is", without warranty of any kind, for private use and education. No independent security audit has been performed. For high-risk communication, use an established, audited messenger.
