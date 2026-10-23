// Zero-Trace Terminal — Anwendungslogik (Protokoll v2)
// ---------------------------------------------------------------------------
// Sicherheitsmodell (Kurzfassung, Details in technical_documentation.md):
//  * Room Key (100 Zeichen, ~617 Bit) -> PBKDF2 -> HKDF -> drei getrennte Werte:
//      - Schlüssel Host->Guest (AES-GCM-256, nicht exportierbar)
//      - Schlüssel Guest->Host (AES-GCM-256, nicht exportierbar)
//      - PeerJS-ID (128 Bit), die einzige vom Room Key abgeleitete Größe, die der Broker sieht
//  * Jedes Paket: Header (Version + Sequenznummer) || IV || Ciphertext.
//    Der Header ist als AAD authentifiziert. Getrennte Richtungsschlüssel verhindern
//    Reflection, strikt fortlaufende Sequenznummern verhindern Replay/Umordnung.
//  * Handshake (Challenge-Response) beweist Schlüsselbesitz, bevor ein Kanal als
//    vertrauenswürdig gilt. Der Host akzeptiert genau EINEN authentifizierten Peer.
// ---------------------------------------------------------------------------
(() => {
    'use strict';

    const CFG = window.ZTT_CONFIG || {};
    const PROTO_VERSION = 2;
    const HEADER_LEN = 8;          // [version, 0, 0, 0, seq(uint32 BE)]
    const IV_LEN = 12;
    const TAG_LEN = 16;
    const MAX_MSG_LENGTH = 5000;
    const MAX_PACKET_BYTES = 64 * 1024;
    const ROOM_KEY_LEN = 100;
    const ROOM_KEY_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_!@#$%^&*';
    const SESSION_TIMEOUT_MS = 120000;  // Room Key verfällt, wenn bis dahin kein Peer authentifiziert ist
    const HANDSHAKE_TIMEOUT_MS = 15000; // unauthentifizierte Verbindungen werden danach geschlossen
    const TURN_FETCH_TIMEOUT_MS = 8000;
    const MAX_PENDING_CONNECTIONS = 8;  // gleichzeitige unauthentifizierte Verbindungsversuche (Host)

    const $ = (id) => document.getElementById(id);

    function dbg(...args) {
        if (CFG.debug) console.log('[ZTT]', ...args);
    }

    // =======================================================================
    // SESSION-VERWALTUNG
    // Jede Sitzung ist ein eigenes Objekt. Alle Callbacks prüfen, ob "ihre"
    // Sitzung noch aktiv ist; Timer werden beim Abbau zuverlässig gelöscht.
    // =======================================================================
    let session = null;

    function newSession(role) {
        teardown();
        session = {
            role,                   // 'host' | 'guest'
            peer: null,
            keys: null,             // { send, recv, peerId }
            active: null,           // authentifizierter Kanal
            candidates: new Set(),  // Kanäle im Handshake
            timers: new Set(),
            closed: false
        };
        return session;
    }

    function isCurrent(s) {
        return s && s === session && !s.closed;
    }

    function sTimeout(s, fn, ms) {
        const t = setTimeout(() => {
            s.timers.delete(t);
            if (isCurrent(s)) fn();
        }, ms);
        s.timers.add(t);
        return t;
    }

    function sClearTimeout(s, t) {
        clearTimeout(t);
        s.timers.delete(t);
    }

    function teardown() {
        const s = session;
        session = null;
        if (!s) return;
        s.closed = true;
        s.timers.forEach(clearTimeout);
        s.timers.clear();
        for (const ch of s.candidates) {
            try { ch.conn.close(); } catch (e) { /* ignore */ }
        }
        s.candidates.clear();
        if (s.active) {
            try { s.active.conn.close(); } catch (e) { /* ignore */ }
            s.active = null;
        }
        if (s.peer) {
            try { s.peer.destroy(); } catch (e) { /* ignore */ }
            s.peer = null;
        }
        // CryptoKeys sind nicht exportierbar; Referenzen fallen weg, der GC räumt auf.
        // (JavaScript erlaubt kein garantiertes Überschreiben von Speicher.)
        s.keys = null;
        s.code = null;
    }

    // =======================================================================
    // KRYPTOGRAFIE
    // =======================================================================

    // Gleichverteilter Room Key per Rejection Sampling (kein Modulo-Bias).
    function generateRoomKey() {
        const n = ROOM_KEY_CHARS.length;
        const limit = 256 - (256 % n);
        let out = '';
        while (out.length < ROOM_KEY_LEN) {
            const buf = crypto.getRandomValues(new Uint8Array(ROOM_KEY_LEN * 2));
            for (const b of buf) {
                if (b < limit) {
                    out += ROOM_KEY_CHARS[b % n];
                    if (out.length === ROOM_KEY_LEN) break;
                }
            }
        }
        return out;
    }

    function isValidRoomKey(code) {
        if (typeof code !== 'string' || code.length !== ROOM_KEY_LEN) return false;
        for (const c of code) if (!ROOM_KEY_CHARS.includes(c)) return false;
        return true;
    }

    async function deriveSessionKeys(roomKey, role) {
        const enc = new TextEncoder();
        const pbkdfBase = await crypto.subtle.importKey('raw', enc.encode(roomKey), 'PBKDF2', false, ['deriveBits']);
        const master = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: enc.encode('ztt-v2-pbkdf2-salt'), iterations: 100000, hash: 'SHA-256' },
            pbkdfBase, 256
        );
        const hkdfBase = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
        const hkdf = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) });
        const aes = { name: 'AES-GCM', length: 256 };

        // Handshake-Schlüssel: nur für hello/chal/resp. Chat-Nachrichten laufen über
        // Verbindungsschlüssel, die zusätzlich von zwei frischen Nonces abhängen.
        const h2g = await crypto.subtle.deriveKey(hkdf('ztt-v2 handshake host->guest'), hkdfBase, aes, false, ['encrypt', 'decrypt']);
        const g2h = await crypto.subtle.deriveKey(hkdf('ztt-v2 handshake guest->host'), hkdfBase, aes, false, ['encrypt', 'decrypt']);
        const idBits = new Uint8Array(await crypto.subtle.deriveBits(hkdf('ztt-v2 peer-id'), hkdfBase, 128));
        const peerId = 'ztt2-' + Array.from(idBits, (b) => b.toString(16).padStart(2, '0')).join('');

        return role === 'host'
            ? { send: h2g, recv: g2h, base: hkdfBase, role, peerId }
            : { send: g2h, recv: h2g, base: hkdfBase, role, peerId };
    }

    // Pro Verbindung frische Schlüssel: HKDF(master, salt = nonceGuest || nonceHost).
    // Dadurch lässt sich aufgezeichneter Verkehr einer früheren Verbindung nicht in
    // eine neue Verbindung einspielen, auch nicht mit demselben Room Key.
    async function deriveConnectionKeys(sessKeys, nonceGuestHex, nonceHostHex) {
        const salt = hexToBytes(nonceGuestHex + nonceHostHex);
        const enc = new TextEncoder();
        const params = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) });
        const aes = { name: 'AES-GCM', length: 256 };
        const h2g = await crypto.subtle.deriveKey(params('ztt-v2 conn host->guest'), sessKeys.base, aes, false, ['encrypt', 'decrypt']);
        const g2h = await crypto.subtle.deriveKey(params('ztt-v2 conn guest->host'), sessKeys.base, aes, false, ['encrypt', 'decrypt']);
        return sessKeys.role === 'host' ? { send: h2g, recv: g2h } : { send: g2h, recv: h2g };
    }

    function hexToBytes(hex) {
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    // Ein Kanal kapselt eine PeerJS-Verbindung samt Sequenzzählern.
    // Senden und Empfangen laufen jeweils strikt seriell (Promise-Ketten),
    // damit die Reihenfolge auf dem Draht den Sequenznummern entspricht.
    function makeChannel(conn, keys) {
        return {
            conn, keys,
            sendSeq: 0, recvSeq: 0,
            sendChain: Promise.resolve(),
            recvChain: Promise.resolve(),
            authed: false,
            nonceGuest: null,
            nonceHost: null,
            dead: false,
            handshakeTimer: null,
            hsSent: null,   // zuletzt gesendetes Handshake-Paket (für identischen Neuversand)
            hsSeen: []      // akzeptierte Handshake-Pakete der Gegenseite (byte-identische Duplikate werden ignoriert)
        };
    }

    function sendFrame(ch, obj) {
        const job = ch.sendChain.then(async () => {
            if (ch.dead || !ch.conn.open) throw new Error('channel closed');
            if (ch.sendSeq >= 0xFFFFFFFF) throw new Error('sequence exhausted');
            const header = new Uint8Array(HEADER_LEN);
            header[0] = PROTO_VERSION;
            new DataView(header.buffer).setUint32(4, ch.sendSeq);
            ch.sendSeq++;
            const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
            const pt = new TextEncoder().encode(JSON.stringify(obj));
            const ct = new Uint8Array(await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv, additionalData: header }, ch.keys.send, pt));
            const packet = new Uint8Array(HEADER_LEN + IV_LEN + ct.length);
            packet.set(header, 0);
            packet.set(iv, HEADER_LEN);
            packet.set(ct, HEADER_LEN + IV_LEN);
            ch.conn.send(packet.buffer.slice(0));
            return packet;
        });
        ch.sendChain = job.catch(() => {});
        return job;
    }

    async function toBytes(data) {
        if (data instanceof ArrayBuffer) return new Uint8Array(data);
        if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        if (typeof Blob !== 'undefined' && data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
        return null;
    }

    // Wirft bei jeder Unregelmäßigkeit (falscher Schlüssel, Manipulation, Replay, Umordnung).
    async function openFrame(ch, bytes) {
        if (!bytes || bytes.length < HEADER_LEN + IV_LEN + TAG_LEN || bytes.length > MAX_PACKET_BYTES) {
            throw new Error('malformed packet');
        }
        const header = bytes.slice(0, HEADER_LEN);
        if (header[0] !== PROTO_VERSION || header[1] || header[2] || header[3]) throw new Error('bad header');
        const seq = new DataView(header.buffer).getUint32(4);
        if (seq !== ch.recvSeq) throw new Error('sequence mismatch (replay/reorder)');
        const iv = bytes.slice(HEADER_LEN, HEADER_LEN + IV_LEN);
        const ct = bytes.slice(HEADER_LEN + IV_LEN);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header }, ch.keys.recv, ct);
        ch.recvSeq++;
        const obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pt));
        if (!obj || typeof obj.t !== 'string') throw new Error('bad payload');
        return obj;
    }

    function sameBytes(a, b) {
        if (!a || !b || a.length !== b.length) return false;
        let d = 0;
        for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
        return d === 0;
    }

    function randomHex(nBytes) {
        return Array.from(crypto.getRandomValues(new Uint8Array(nBytes)), (b) => b.toString(16).padStart(2, '0')).join('');
    }

    // =======================================================================
    // ICE / TURN
    // =======================================================================

    function isValidIceUrl(u) {
        return typeof u === 'string' && /^(stun|turn|turns):[^\s]+$/i.test(u) && !/:53(\?|$)/.test(u);
    }

    function sanitizeIceServers(list) {
        if (!Array.isArray(list)) return [];
        const out = [];
        for (const srv of list) {
            if (!srv || typeof srv !== 'object') continue;
            const urls = (Array.isArray(srv.urls) ? srv.urls : [srv.urls]).filter(isValidIceUrl);
            if (!urls.length) continue;
            const entry = { urls };
            if (typeof srv.username === 'string') entry.username = srv.username;
            if (typeof srv.credential === 'string') entry.credential = srv.credential;
            out.push(entry);
        }
        return out;
    }

    async function buildRtcConfig(statusFn) {
        const stun = sanitizeIceServers([{ urls: CFG.stunServers || [] }]);
        let iceServers = stun;
        let haveTurn = false;

        if (CFG.turnCredentialsUrl) {
            const ctrl = new AbortController();
            const t = setTimeout(() => ctrl.abort(), TURN_FETCH_TIMEOUT_MS);
            try {
                const res = await fetch(CFG.turnCredentialsUrl, {
                    method: 'POST',
                    cache: 'no-store',
                    credentials: 'omit',
                    referrerPolicy: 'no-referrer',
                    signal: ctrl.signal
                });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const json = await res.json();
                const fetched = sanitizeIceServers(json && json.iceServers);
                haveTurn = fetched.some((s) => s.urls.some((u) => /^turns?:/i.test(u)) && s.username && s.credential);
                if (fetched.length) iceServers = fetched;
                dbg('TURN credentials fetched, relay available:', haveTurn);
            } catch (e) {
                dbg('TURN credential fetch failed:', e);
                statusFn('[WARN] TURN endpoint unreachable — direct connection only');
            } finally {
                clearTimeout(t);
            }
        }

        if (CFG.forceRelay && !haveTurn) {
            throw new Error('RELAY_REQUIRED');
        }
        return {
            iceServers,
            iceTransportPolicy: CFG.forceRelay ? 'relay' : 'all'
        };
    }

    function peerOptions(rtcConfig) {
        const sig = CFG.signaling || {};
        return {
            host: sig.host, port: sig.port, path: sig.path, secure: sig.secure, key: sig.key,
            config: rtcConfig,
            debug: CFG.debug ? 2 : 0
        };
    }

    function watchIce(conn, statusFn, label) {
        const pc = conn.peerConnection;
        if (!pc) return;
        pc.addEventListener('iceconnectionstatechange', () => {
            const state = pc.iceConnectionState;
            dbg('[ICE]', label, state);
            if (state === 'failed') statusFn('[ICE FAILED] check TURN/network');
            else if (state === 'checking') statusFn('NEGOTIATING ICE...');
        });
        if (CFG.debug) {
            // Kandidaten enthalten IP-Adressen — nur im Debug-Modus loggen.
            pc.addEventListener('icecandidate', (ev) => {
                dbg('[ICE-CANDIDATE]', label, ev.candidate ? ev.candidate.candidate : 'gathering complete');
            });
        }
    }

    // =======================================================================
    // UI-HELFER
    // =======================================================================

    function getTimestamp() {
        const now = new Date();
        const p = (n) => String(n).padStart(2, '0');
        return `[${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}]`;
    }

    function appendMessage(text, className) {
        const box = $('messages');
        const div = document.createElement('div');
        div.className = className;
        div.textContent = `${getTimestamp()} ${text}`;
        box.appendChild(div);
        box.scrollTop = box.scrollHeight;
    }

    function setStatus(state) {
        const led = $('statusLed');
        const text = $('statusText');
        led.className = 'led led-' + state;
        if (state === 'yellow') { text.textContent = 'WAITING FOR PEER'; text.style.color = '#ffb000'; }
        if (state === 'green') { text.textContent = 'SECURE P2P ACTIVE (AUTHENTICATED)'; text.style.color = '#00ff66'; }
        if (state === 'red') { text.textContent = 'DISCONNECTED'; text.style.color = '#ff3333'; }
    }

    function showPage(id) {
        document.querySelectorAll('.container').forEach((c) => { c.style.display = 'none'; });
        $(id).style.display = 'flex';
    }

    function show(el, visible) { el.classList.toggle('hidden', !visible); }

    async function writeClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* fallback */ }
        }
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        return ok;
    }

    function flashButton(btn, label) {
        const original = btn.textContent;
        btn.textContent = label;
        btn.classList.add('flash');
        setTimeout(() => { btn.textContent = original; btn.classList.remove('flash'); }, 2000);
    }

    // =======================================================================
    // KANAL-LOGIK (gemeinsam für Host und Guest)
    // =======================================================================

    function killChannel(s, ch) {
        if (ch.dead) return;
        ch.dead = true;
        if (ch.handshakeTimer) sClearTimeout(s, ch.handshakeTimer);
        s.candidates.delete(ch);
        try { ch.conn.close(); } catch (e) { /* ignore */ }
    }

    function onAuthenticated(s, ch) {
        ch.authed = true;
        if (ch.handshakeTimer) sClearTimeout(s, ch.handshakeTimer);
        s.candidates.delete(ch);
        s.active = ch;
        // Alle anderen (unauthentifizierten) Verbindungsversuche schließen.
        for (const other of Array.from(s.candidates)) killChannel(s, other);
        if (s.expiryTimer) sClearTimeout(s, s.expiryTimer);
        // Signaling wird nicht mehr gebraucht: vom Broker abmelden, P2P-Kanal bleibt bestehen.
        try { s.peer.disconnect(); } catch (e) { /* ignore */ }

        setStatus('green');
        appendMessage('[SYS] Peer authenticated (key confirmation OK). Directional keys + replay protection active.', 'msg-system');
        if (s.role === 'host') {
            $('hostStatusBox').textContent = '[PEER AUTHENTICATED]';
            $('hostConnectBtn').disabled = false;
        } else {
            $('joinStatusBox').textContent = '[CONNECTED & AUTHENTICATED]';
            $('joinConnectBtn').disabled = false;
        }
    }

    function onChannelBroken(s, ch, reason) {
        const wasActive = s.active === ch;
        killChannel(s, ch);
        if (wasActive) {
            s.active = null;
            setStatus('red');
            appendMessage('[SYS] ' + reason, 'msg-warn');
            $('sendBtn').disabled = true;
        }
    }

    const NONCE_RE = /^[0-9a-f]{32}$/;

    // Sendet das zuletzt erzeugte Handshake-Paket byte-identisch erneut (gleiche
    // Sequenznummer), bis die Gegenseite antwortet — frühe Pakete direkt nach
    // 'open' gehen bei manchen Browser-Kombinationen verloren.
    function retransmitHandshake(s, ch, stillNeeded) {
        const resend = () => {
            if (ch.dead || !stillNeeded()) return;
            try { ch.conn.send(ch.hsSent.buffer.slice(0)); } catch (e) { /* ignore */ }
            sTimeout(s, resend, 1000);
        };
        sTimeout(s, resend, 1000);
    }

    // Wechsel von Handshake- auf Verbindungsschlüssel; Sequenzzähler beginnen neu.
    function switchToConnectionKeys(ch, connKeys) {
        ch.keys = connKeys;
        ch.sendSeq = 0;
        ch.recvSeq = 0;
    }

    // Handshake (alle Pakete unter den Handshake-Schlüsseln):
    //   Guest -> Host : hello {g: nonceGuest}
    //   Host  -> Guest: chal  {g: nonceGuest, n: nonceHost}   (beweist Frische + Schlüsselbesitz des Hosts)
    //   Guest -> Host : resp  {n: nonceHost}                  (beweist Frische + Schlüsselbesitz des Guests)
    // Danach beide: Verbindungsschlüssel = HKDF(master, nonceGuest || nonceHost).
    async function handleFrame(s, ch, obj) {
        if (s.role === 'host' && !ch.authed) {
            if (obj.t === 'hello' && ch.nonceHost === null) {
                if (typeof obj.g !== 'string' || !NONCE_RE.test(obj.g)) throw new Error('bad hello');
                ch.nonceGuest = obj.g;
                ch.nonceHost = randomHex(16);
                ch.hsSent = await sendFrame(ch, { t: 'chal', g: ch.nonceGuest, n: ch.nonceHost });
                retransmitHandshake(s, ch, () => !ch.authed);
                return;
            }
            if (obj.t === 'resp' && ch.nonceHost !== null) {
                if (obj.n !== ch.nonceHost) throw new Error('handshake response mismatch');
                if (s.active) throw new Error('room already occupied');
                switchToConnectionKeys(ch, await deriveConnectionKeys(ch.keys, ch.nonceGuest, ch.nonceHost));
                onAuthenticated(s, ch);
                return;
            }
            throw new Error('unexpected handshake frame');
        }
        if (s.role === 'guest' && !ch.authed) {
            if (obj.t !== 'chal' || obj.g !== ch.nonceGuest || typeof obj.n !== 'string' || !NONCE_RE.test(obj.n)) {
                throw new Error('unexpected or stale handshake frame');
            }
            ch.nonceHost = obj.n;
            ch.hsSent = await sendFrame(ch, { t: 'resp', n: ch.nonceHost });
            switchToConnectionKeys(ch, await deriveConnectionKeys(ch.keys, ch.nonceGuest, ch.nonceHost));
            onAuthenticated(s, ch);
            return;
        }
        // Authentifizierter Kanal (Verbindungsschlüssel): nur Chat-Nachrichten.
        if (obj.t === 'msg' && typeof obj.d === 'string') {
            appendMessage('PEER: ' + obj.d.substring(0, MAX_MSG_LENGTH), 'msg-peer');
        } else if (obj.t === 'bye') {
            onChannelBroken(s, ch, 'Peer ended the session.');
        } else {
            throw new Error('unexpected frame type');
        }
    }

    function attachChannel(s, conn, statusFn) {
        const ch = makeChannel(conn, s.keys);
        s.candidates.add(ch);

        conn.on('open', () => {
            if (!isCurrent(s) || ch.dead) return;
            statusFn('CHANNEL OPEN, VERIFYING KEY...');
            // Ab Kanalöffnung bleibt nur begrenzt Zeit für den Schlüsselnachweis.
            ch.handshakeTimer = sTimeout(s, () => {
                if (!ch.authed) {
                    dbg('handshake timeout, closing connection');
                    killChannel(s, ch);
                    if (s.role === 'guest') statusFn('[ERROR] Handshake failed — wrong key or tampered connection');
                }
            }, HANDSHAKE_TIMEOUT_MS);
            if (s.role === 'guest') {
                ch.nonceGuest = randomHex(16);
                sendFrame(ch, { t: 'hello', g: ch.nonceGuest }).then((pkt) => {
                    ch.hsSent = pkt;
                    retransmitHandshake(s, ch, () => ch.nonceHost === null);
                }).catch((e) => { dbg('hello send failed:', e && e.message); killChannel(s, ch); });
            }
        });

        conn.on('data', (data) => {
            ch.recvChain = ch.recvChain.then(async () => {
                if (!isCurrent(s) || ch.dead) return;
                const bytes = await toBytes(data);
                // Byte-identisches Duplikat eines bereits akzeptierten Handshake-Pakets
                // (Neuversand der Gegenseite): ignorieren. Der Guest schickt seine Antwort
                // erneut, falls sie verloren ging. Inhalte enthalten diese Pakete nicht.
                if (bytes && ch.hsSeen.some((seen) => sameBytes(bytes, seen))) {
                    if (s.role === 'guest' && ch.authed && ch.hsSent) {
                        try { ch.conn.send(ch.hsSent.buffer.slice(0)); } catch (e) { /* ignore */ }
                    }
                    return;
                }
                let obj;
                try {
                    obj = await openFrame(ch, bytes);
                    if (!ch.authed) ch.hsSeen.push(bytes);
                } catch (e) {
                    dbg('frame rejected:', e && e.message);
                    if (ch.authed) {
                        onChannelBroken(s, ch, '[SECURITY] Invalid/replayed packet received — connection terminated.');
                    } else {
                        killChannel(s, ch);
                        if (s.role === 'guest') statusFn('[ERROR] Key verification failed');
                    }
                    return;
                }
                try {
                    await handleFrame(s, ch, obj);
                } catch (e) {
                    dbg('protocol violation:', e && e.message);
                    if (ch.authed) onChannelBroken(s, ch, '[SECURITY] Protocol violation — connection terminated.');
                    else {
                        killChannel(s, ch);
                        if (s.role === 'guest') statusFn('[ERROR] Handshake rejected — stale or tampered data');
                    }
                }
            }).catch((e) => {
                dbg('receive pipeline error:', e && e.message);
                if (isCurrent(s)) onChannelBroken(s, ch, '[SYS] Receive error — connection terminated.');
            });
        });

        conn.on('close', () => {
            if (!isCurrent(s)) return;
            onChannelBroken(s, ch, 'P2P link terminated by remote peer.');
        });

        conn.on('error', (err) => {
            dbg('connection error', err);
            if (!isCurrent(s)) return;
            onChannelBroken(s, ch, 'Connection error.');
        });

        watchIce(conn, (t) => { if (!ch.authed) statusFn(t); }, s.role);
        return ch;
    }

    function friendlyPeerError(err) {
        switch (err && err.type) {
            case 'peer-unavailable': return '[ERROR] Host not reachable — wrong key or host offline';
            case 'unavailable-id': return '[ERROR] Room ID already in use — generate a new key';
            case 'network':
            case 'server-error':
            case 'socket-error':
            case 'socket-closed': return '[ERROR] Signaling server unreachable';
            case 'browser-incompatible': return '[ERROR] Browser does not support WebRTC';
            default: return '[ERROR] ' + ((err && err.type) || 'unknown');
        }
    }

    // =======================================================================
    // HOST
    // =======================================================================

    async function startHosting() {
        const s = newSession('host');
        const status = (t) => { if (isCurrent(s)) $('hostStatusBox').textContent = t; };

        showPage('host-setup');
        resetChatView();
        $('hostConnectBtn').disabled = true;
        show($('hostRegenerateBtn'), false);

        const code = generateRoomKey();
        $('hostRoomCode').textContent = code;
        status('DERIVING KEYS...');

        let rtcConfig;
        try {
            s.keys = await deriveSessionKeys(code, 'host');
            if (!isCurrent(s)) return;
            status('FETCHING RELAY CREDENTIALS...');
            rtcConfig = await buildRtcConfig(status);
        } catch (e) {
            if (!isCurrent(s)) return;
            status(e.message === 'RELAY_REQUIRED'
                ? '[ERROR] forceRelay active but no TURN available — check config.js'
                : '[ERROR] Initialisation failed');
            show($('hostRegenerateBtn'), true);
            return;
        }
        if (!isCurrent(s)) return;

        s.peer = new Peer(s.keys.peerId, peerOptions(rtcConfig));
        status('REGISTERING WITH SIGNALING SERVER...');

        s.peer.on('open', () => {
            status('WAITING FOR PEER...');
            appendMessage('[SYS] Room open. Waiting for peer.', 'msg-system');
        });

        s.peer.on('connection', (incoming) => {
            if (!isCurrent(s)) { try { incoming.close(); } catch (e) { /* ignore */ } return; }
            // Raum ist belegt: weitere Verbindungen sofort ablehnen (kein Überschreiben).
            if (s.active || s.candidates.size >= MAX_PENDING_CONNECTIONS) {
                try { incoming.close(); } catch (e) { /* ignore */ }
                return;
            }
            status('PEER FOUND, NEGOTIATING...');
            attachChannel(s, incoming, status);
        });

        s.peer.on('error', (err) => {
            dbg('peer error', err);
            if (!isCurrent(s) || s.active) return;
            status(friendlyPeerError(err));
            show($('hostRegenerateBtn'), true);
        });

        s.expiryTimer = sTimeout(s, () => {
            if (s.active) return;
            status('[EXPIRED] Room Key no longer valid — generate a new one');
            show($('hostRegenerateBtn'), true);
            for (const ch of Array.from(s.candidates)) killChannel(s, ch);
            try { s.peer.destroy(); } catch (e) { /* ignore */ }
        }, SESSION_TIMEOUT_MS);
    }

    // =======================================================================
    // GUEST
    // =======================================================================

    async function startGuest(code) {
        const s = newSession('guest');
        s.code = code;
        const status = (t) => {
            if (!isCurrent(s)) return;
            if (t.startsWith('[ERROR]') || t.startsWith('[EXPIRED]')) s.failed = true;
            $('joinStatusBox').textContent = t;
        };

        resetChatView();
        $('joinConnectBtn').disabled = true;
        show($('joinRetryBtn'), false);
        status('DERIVING KEYS...');

        let rtcConfig;
        try {
            s.keys = await deriveSessionKeys(code, 'guest');
            if (!isCurrent(s)) return;
            status('FETCHING RELAY CREDENTIALS...');
            rtcConfig = await buildRtcConfig(status);
        } catch (e) {
            if (!isCurrent(s)) return;
            status(e.message === 'RELAY_REQUIRED'
                ? '[ERROR] forceRelay active but no TURN available — check config.js'
                : '[ERROR] Initialisation failed');
            show($('joinRetryBtn'), true);
            return;
        }
        if (!isCurrent(s)) return;

        s.peer = new Peer(peerOptions(rtcConfig));
        status('CONNECTING TO SIGNALING SERVER...');

        s.peer.on('open', () => {
            if (!isCurrent(s)) return;
            const conn = s.peer.connect(s.keys.peerId, { reliable: true, serialization: 'raw' });
            status('CONTACTING HOST...');
            attachChannel(s, conn, status);
        });

        s.peer.on('error', (err) => {
            dbg('peer error', err);
            if (!isCurrent(s) || s.active) return;
            status(friendlyPeerError(err));
            show($('joinRetryBtn'), true);
        });

        s.expiryTimer = sTimeout(s, () => {
            if (s.active) return;
            status('[EXPIRED] Room Key no longer valid — ask for a new one');
            show($('joinRetryBtn'), true);
            for (const ch of Array.from(s.candidates)) killChannel(s, ch);
            try { s.peer.destroy(); } catch (e) { /* ignore */ }
        }, SESSION_TIMEOUT_MS);
    }

    function resetGuestView() {
        $('joinRoomCode').value = '';
        $('joinStatusBox').textContent = 'WAITING FOR ROOM KEY...';
        $('joinConnectBtn').disabled = true;
        show($('joinRetryBtn'), false);
    }

    // =======================================================================
    // CHAT
    // =======================================================================

    function resetChatView() {
        $('messages').textContent = '';
        appendMessage('[SYS_INIT] P2P Node Listening...', 'msg-system');
        $('messageInput').value = '';
        $('sendBtn').disabled = false;
        setStatus('yellow');
    }

    async function sendMessage() {
        const input = $('messageInput');
        const text = input.value.trim();
        if (!text) return;
        if (text.length > MAX_MSG_LENGTH) {
            appendMessage(`[SYS_ERR] Payload size limit reached (${MAX_MSG_LENGTH} chars).`, 'msg-system');
            return;
        }
        const s = session;
        if (!isCurrent(s) || !s.active || s.active.dead) {
            appendMessage('[SYS_ERR] No authenticated P2P channel.', 'msg-system');
            return;
        }
        input.value = '';
        try {
            await sendFrame(s.active, { t: 'msg', d: text });
            appendMessage('YOU: ' + text, 'msg-me');
        } catch (e) {
            appendMessage('[SYS_ERR] Message could not be sent.', 'msg-system');
        }
    }

    // =======================================================================
    // PANIC PURGE
    // =======================================================================

    async function panicPurge() {
        const s = session;
        if (isCurrent(s) && s.active && !s.active.dead) {
            // Gegenseite informieren (best effort), dann alles abbauen.
            try { await Promise.race([sendFrame(s.active, { t: 'bye' }), new Promise((r) => setTimeout(r, 300))]); } catch (e) { /* ignore */ }
        }
        teardown();

        $('hostRoomCode').textContent = '';
        $('hostStatusBox').textContent = 'INITIALIZING P2P NODE...';
        $('hostConnectBtn').disabled = true;
        show($('hostRegenerateBtn'), false);
        resetGuestView();
        resetChatView();
        $('messages').textContent = '';
        appendMessage('[SYS_INIT] Session purged. Node standby.', 'msg-system');

        // Room Key könnte noch in der Zwischenablage liegen — überschreiben (best effort).
        try { if (navigator.clipboard) await navigator.clipboard.writeText(' '); } catch (e) { /* ignore */ }

        showPage('menu');
        alert('[PANIC PURGE COMPLETE] Connections closed, session keys released, chat history wiped. Clipboard overwritten (if permitted). Note: browsers cannot guarantee memory is physically overwritten — close the tab for best effect.');
    }

    // =======================================================================
    // EVENT-BINDUNGEN (keine Inline-Handler, damit die CSP greifen kann)
    // =======================================================================

    function dismissSplash() {
        $('splash-screen').classList.add('splash-hidden');
    }

    function backToMenu() {
        teardown();
        $('hostRoomCode').textContent = '';
        resetGuestView();
        showPage('menu');
    }

    $('splashEnterBtn').addEventListener('click', dismissSplash);
    setTimeout(dismissSplash, 5000);

    $('menuHostBtn').addEventListener('click', startHosting);
    $('menuJoinBtn').addEventListener('click', () => { teardown(); resetGuestView(); showPage('join-setup'); });

    $('hostCopyBtn').addEventListener('click', async (ev) => {
        const code = $('hostRoomCode').textContent;
        if (!code) return;
        const ok = await writeClipboard(code);
        flashButton(ev.currentTarget, ok ? '[ COPIED! ]' : '[ COPY FAILED ]');
    });
    $('hostConnectBtn').addEventListener('click', () => {
        if (!session || !session.active) return;
        $('hostRoomCode').textContent = ''; // Room Key wird nach dem Handshake nicht mehr gebraucht
        showPage('chat-room');
        $('messageInput').focus();
    });
    $('hostRegenerateBtn').addEventListener('click', startHosting);
    $('hostBackBtn').addEventListener('click', backToMenu);

    $('joinRoomCode').addEventListener('input', () => {
        const code = $('joinRoomCode').value.trim();
        if (code.length < ROOM_KEY_LEN) return;
        if (!isValidRoomKey(code)) {
            $('joinStatusBox').textContent = '[ERROR] Invalid Room Key (must be exactly 100 valid characters)';
            return;
        }
        // Läuft bereits ein Versuch mit genau diesem Key, nichts tun; ein neuer Key startet neu.
        if (session && session.role === 'guest' && session.code === code && !session.failed) return;
        startGuest(code);
    });
    $('joinConnectBtn').addEventListener('click', () => {
        if (!session || !session.active) return;
        $('joinRoomCode').value = ''; // Room Key nicht länger als nötig im DOM halten
        showPage('chat-room');
        $('messageInput').focus();
    });
    $('joinRetryBtn').addEventListener('click', () => { teardown(); resetGuestView(); });
    $('joinBackBtn').addEventListener('click', backToMenu);

    $('panicBtn').addEventListener('click', panicPurge);
    $('sendBtn').addEventListener('click', sendMessage);
    $('messageInput').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') sendMessage(); });

    $('donateBtn').addEventListener('click', async (ev) => {
        const ok = await writeClipboard($('donateAddress').textContent);
        flashButton(ev.currentTarget, ok ? '[ ✓ ADDRESS COPIED! ]' : '[ COPY FAILED ]');
    });

    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
        alert('This page must be served over HTTPS (secure context required for Web Crypto / WebRTC).');
    }
    if (typeof window.Peer !== 'function') {
        alert('PeerJS failed to load (integrity check failed or file missing). Refusing to continue.');
    }
})();
