// P2P Terminal — Anwendungslogik (Protokoll v3)
// ---------------------------------------------------------------------------
// Sicherheitsmodell (Kurzfassung, Details in technical_documentation.md):
//  * Room Key (100 Zeichen, ~617 Bit) -> PBKDF2 -> HKDF -> Handshake-Schlüssel je
//    Richtung + PeerJS-ID (die einzige vom Room Key abgeleitete Größe, die der Broker sieht).
//  * Handshake hello/chal/resp unter den Handshake-Schlüsseln: tauscht frische Nonces
//    und ephemere ECDH-P-256-Schlüssel aus und beweist beidseitig den Besitz des Room Keys.
//  * Chat-Schlüssel = HKDF(ECDH-Geheimnis || Room-Key-Bindung, salt = Transkript-Hash):
//    Forward Secrecy und ein Sicherheitscode (6 Emojis), den beide Seiten vergleichen.
//    Abweichende Codes = jemand hat den Room Key abgefangen und sitzt dazwischen.
//  * Jedes Paket: Header (Version + Sequenznummer, als AAD authentifiziert) || IV || Ciphertext.
//    Getrennte Richtungsschlüssel verhindern Reflection, Sequenznummern Replay/Umordnung.
//  * Der Host akzeptiert genau EINEN authentifizierten Peer.
// ---------------------------------------------------------------------------
(() => {
    'use strict';

    const CFG = window.ZTT_CONFIG || {};
    const PROTO_VERSION = 3;
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
            { name: 'PBKDF2', salt: enc.encode('ztt-v3-pbkdf2-salt'), iterations: 100000, hash: 'SHA-256' },
            pbkdfBase, 256
        );
        const hkdfBase = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
        const hkdf = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) });
        const aes = { name: 'AES-GCM', length: 256 };

        // Handshake-Schlüssel: nur für hello/chal/resp. Chat-Nachrichten laufen über
        // Verbindungsschlüssel, die zusätzlich von zwei frischen Nonces abhängen.
        const h2g = await crypto.subtle.deriveKey(hkdf('ztt-v3 handshake host->guest'), hkdfBase, aes, false, ['encrypt', 'decrypt']);
        const g2h = await crypto.subtle.deriveKey(hkdf('ztt-v3 handshake guest->host'), hkdfBase, aes, false, ['encrypt', 'decrypt']);
        const idBits = new Uint8Array(await crypto.subtle.deriveBits(hkdf('ztt-v3 peer-id'), hkdfBase, 128));
        const peerId = 'ztt3-' + Array.from(idBits, (b) => b.toString(16).padStart(2, '0')).join('');

        return role === 'host'
            ? { send: h2g, recv: g2h, base: hkdfBase, role, peerId }
            : { send: g2h, recv: h2g, base: hkdfBase, role, peerId };
    }

    // ----- Ephemerer ECDH-Schlüsseltausch (P-256) -----
    // Pro Verbindung ein frisches Schlüsselpaar. Der private Schlüssel ist nicht
    // exportierbar und wird nach der Ableitung verworfen -> Forward Secrecy:
    // Wird der Room Key später bekannt, bleibt aufgezeichneter Verkehr geheim.
    const ECDH_ALG = { name: 'ECDH', namedCurve: 'P-256' };

    async function newEcdhKeyPair() {
        const kp = await crypto.subtle.generateKey(ECDH_ALG, false, ['deriveBits']);
        const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
        return { privateKey: kp.privateKey, pubRaw };
    }

    async function importPeerPublicKey(b64) {
        if (typeof b64 !== 'string' || b64.length > 200) throw new Error('bad public key');
        const raw = b64ToBytes(b64);
        if (raw.length !== 65 || raw[0] !== 0x04) throw new Error('bad public key');
        // importKey prüft, ob der Punkt auf der Kurve liegt.
        const key = await crypto.subtle.importKey('raw', raw, ECDH_ALG, false, []);
        return { key, raw };
    }

    // Verbindungsschlüssel = HKDF(ikm = ECDH-Geheimnis || Room-Key-Bindung,
    //                             salt = SHA-256(Transkript), info = Richtung)
    // Das Transkript bindet beide Nonces und beide öffentlichen Schlüssel.
    // Zusätzlich wird ein Sicherheitscode (SAS) abgeleitet, den beide Seiten
    // mündlich vergleichen: Wer den Room Key abgefangen hat und sich dazwischen
    // schaltet, erzeugt zwangsläufig unterschiedliche Codes.
    async function deriveConnectionKeys(sessKeys, ch) {
        const enc = new TextEncoder();
        const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'ECDH', public: ch.peerPub.key }, ch.ecdh.privateKey, 256));
        const roomBinding = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('ztt-v3 ecdh binding') },
            sessKeys.base, 256));
        const ikm = new Uint8Array(64);
        ikm.set(ecdhSecret, 0);
        ikm.set(roomBinding, 32);
        ecdhSecret.fill(0);
        roomBinding.fill(0);

        const pubGuest = sessKeys.role === 'guest' ? ch.ecdh.pubRaw : ch.peerPub.raw;
        const pubHost = sessKeys.role === 'host' ? ch.ecdh.pubRaw : ch.peerPub.raw;
        const transcript = concatBytes(enc.encode('ztt-v3 transcript'),
            hexToBytes(ch.nonceGuest), hexToBytes(ch.nonceHost), pubGuest, pubHost);
        const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', transcript));

        const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey', 'deriveBits']);
        ikm.fill(0);
        const params = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) });
        const aes = { name: 'AES-GCM', length: 256 };
        const h2g = await crypto.subtle.deriveKey(params('ztt-v3 conn host->guest'), base, aes, false, ['encrypt', 'decrypt']);
        const g2h = await crypto.subtle.deriveKey(params('ztt-v3 conn guest->host'), base, aes, false, ['encrypt', 'decrypt']);
        const sasBits = new Uint8Array(await crypto.subtle.deriveBits(params('ztt-v3 sas'), base, 48));

        // Ephemeren privaten Schlüssel verwerfen.
        ch.ecdh = null;
        ch.peerPub = null;

        const keys = sessKeys.role === 'host' ? { send: h2g, recv: g2h } : { send: g2h, recv: h2g };
        keys.sas = Array.from(sasBits, (b) => SAS_EMOJI[b & 63]);
        return keys;
    }

    // 64 Symbole (6 Bit je Symbol, 6 Symbole = 36 Bit).
    const SAS_EMOJI = [
        ['🐶', 'Dog'], ['🐱', 'Cat'], ['🦁', 'Lion'], ['🐎', 'Horse'], ['🦄', 'Unicorn'], ['🐷', 'Pig'], ['🐘', 'Elephant'], ['🐰', 'Rabbit'],
        ['🐼', 'Panda'], ['🐓', 'Rooster'], ['🐧', 'Penguin'], ['🐢', 'Turtle'], ['🐟', 'Fish'], ['🐙', 'Octopus'], ['🦋', 'Butterfly'], ['🌷', 'Flower'],
        ['🌳', 'Tree'], ['🌵', 'Cactus'], ['🍄', 'Mushroom'], ['🌏', 'Globe'], ['🌙', 'Moon'], ['☁️', 'Cloud'], ['🔥', 'Fire'], ['🍌', 'Banana'],
        ['🍎', 'Apple'], ['🍓', 'Strawberry'], ['🌽', 'Corn'], ['🍕', 'Pizza'], ['🎂', 'Cake'], ['❤️', 'Heart'], ['😀', 'Smiley'], ['🤖', 'Robot'],
        ['🎩', 'Hat'], ['👓', 'Glasses'], ['🔧', 'Spanner'], ['🎅', 'Santa'], ['👍', 'Thumbs Up'], ['☂️', 'Umbrella'], ['⌛', 'Hourglass'], ['⏰', 'Clock'],
        ['🎁', 'Gift'], ['💡', 'Light Bulb'], ['📕', 'Book'], ['✏️', 'Pencil'], ['📎', 'Paperclip'], ['✂️', 'Scissors'], ['🔒', 'Lock'], ['🔑', 'Key'],
        ['🔨', 'Hammer'], ['☎️', 'Telephone'], ['🏁', 'Flag'], ['🚂', 'Train'], ['🚲', 'Bicycle'], ['✈️', 'Aeroplane'], ['🚀', 'Rocket'], ['🏆', 'Trophy'],
        ['⚽', 'Ball'], ['🎸', 'Guitar'], ['🎺', 'Trumpet'], ['🔔', 'Bell'], ['⚓', 'Anchor'], ['🎧', 'Headphones'], ['📁', 'Folder'], ['📌', 'Pin']
    ];

    async function sha256Hex(bytes) {
        const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
        return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
    }

    function concatBytes(...parts) {
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    }

    function bytesToB64(bytes) {
        return btoa(String.fromCharCode(...bytes));
    }

    function b64ToBytes(b64) {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
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
            ecdh: null,     // eigenes ephemeres Schlüsselpaar
            peerPub: null,  // öffentlicher Schlüssel der Gegenseite
            peerCommit: null, // Host: SHA-256 des Guest-Schlüssels aus "hello"
            sas: null,      // Sicherheitscode zum Vergleichen
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

    // TURN-Zugangsdaten nach dem "TURN REST API"-Schema (coturn use-auth-secret):
    // username = "<ablaufzeit>:<label>", credential = base64(HMAC-SHA1(secret, username)).
    // Für einen eigenen coturn mit "use-auth-secret". Achtung: Das Secret steht dann
    // in der öffentlichen config.js; die Ablaufzeit begrenzt nur die Gültigkeit der
    // erzeugten Zugangsdaten. coturn daher mit Bandbreitenlimit betreiben.
    async function staticAuthCredentials(secret, ttlSeconds) {
        const username = `${Math.floor(Date.now() / 1000) + ttlSeconds}:ztt`;
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
        const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(username)));
        return { username, credential: btoa(String.fromCharCode(...sig)) };
    }

    async function fetchEndpointIceServers() {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), TURN_FETCH_TIMEOUT_MS);
        try {
            const res = await fetch(CFG.turnCredentialsUrl, {
                method: (CFG.turnCredentialsMethod || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
                cache: 'no-store', credentials: 'omit',
                referrerPolicy: 'no-referrer', signal: ctrl.signal
            });
            if (!res.ok) throw new Error('HTTP ' + res.status);
            const json = await res.json();
            // Akzeptiert {"iceServers":[...]} (eigener Worker) und ein reines Array [...].
            return sanitizeIceServers(Array.isArray(json) ? json : (json && json.iceServers));
        } finally {
            clearTimeout(t);
        }
    }

    const hasRelay = (list) => list.some((s) => s.username && s.credential && s.urls.some((u) => /^turns?:/i.test(u)));

    async function buildRtcConfig(statusFn) {
        let iceServers = [];

        // 1) Optional: eigener Credential-Endpunkt (hat Vorrang, wird zuerst probiert).
        if (CFG.turnCredentialsUrl) {
            try {
                const fetched = await fetchEndpointIceServers();
                iceServers.push(...fetched);
                dbg('endpoint ICE servers:', fetched.length);
            } catch (e) {
                dbg('TURN credential fetch failed:', e);
                statusFn('[WARN] TURN endpoint unreachable — trying direct connection');
            }
        }

        // 2) Öffentliche TURN-Relays aus config.js (Static Auth oder feste Zugangsdaten).
        for (const relay of (CFG.turnServers || [])) {
            if (!relay || !relay.urls) continue;
            let creds = {};
            if (relay.staticAuthSecret) {
                creds = await staticAuthCredentials(relay.staticAuthSecret, relay.ttlSeconds || 86400);
            } else if (relay.username && relay.credential) {
                creds = { username: relay.username, credential: relay.credential };
            } else if (relay.usernameB64 && relay.credentialB64) {
                // Nur Verschleierung gegen automatische Repo-Scanner, keine Sicherheit.
                try {
                    creds = { username: atob(relay.usernameB64), credential: atob(relay.credentialB64) };
                } catch (e) {
                    dbg('invalid base64 TURN credentials');
                }
            }
            iceServers.push(...sanitizeIceServers([{ urls: relay.urls, ...creds }]));
        }

        // 3) STUN (nur IP-Ermittlung, kein Relay).
        iceServers.push(...sanitizeIceServers([{ urls: CFG.stunServers || [] }]));

        if (CFG.forceRelay && !hasRelay(iceServers)) {
            throw new Error('RELAY_REQUIRED');
        }
        dbg('ICE servers configured:', iceServers.length, 'relay:', hasRelay(iceServers));
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
            if (state === 'failed') {
                statusFn(hasRelay((conn.peerConnection.getConfiguration().iceServers) || [])
                    ? '[ICE FAILED] No path found, even via relay — check network'
                    : '[NO DIRECT PATH] A firewall/NAT blocks direct connections. Try another network (e.g. mobile data instead of guest/company Wi-Fi) or configure a TURN relay.');
            }
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
        if (state === 'green') { text.textContent = 'ENCRYPTED — NOT YET VERIFIED'; text.style.color = '#ffb000'; }
        if (state === 'verified') { led.className = 'led led-green'; text.textContent = 'ENCRYPTED & VERIFIED ✓'; text.style.color = '#00ff66'; }
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

    // ----- Sicherheitscode (SAS) -----
    function showSas(sas) {
        const box = $('sasBox');
        const wrap = $('sasEmojis');
        wrap.textContent = '';
        for (const [glyph, name] of sas) {
            const item = document.createElement('div');
            item.className = 'sas-emoji';
            const g = document.createElement('span'); g.className = 'glyph'; g.textContent = glyph;
            const n = document.createElement('span'); n.className = 'name'; n.textContent = name;
            item.append(g, n);
            wrap.appendChild(item);
        }
        box.classList.remove('verified');
        $('sasBox').querySelector('.sas-title').textContent = '> VERIFY: compare these symbols with your peer by voice or in person';
        show($('sasMatchBtn'), true);
        show(box, true);
    }

    function hideSas() {
        show($('sasBox'), false);
        $('sasEmojis').textContent = '';
    }

    // ----- Einladungslink / QR-Code -----
    // Der Room Key steht im Fragment (#k=...). Fragmente werden vom Browser nie an
    // den Server übertragen; die Seite entfernt es nach dem Auslesen sofort.
    function inviteLink(code) {
        const base = CFG.shareBaseUrl || (location.origin + location.pathname);
        return base + '#k=' + encodeURIComponent(code);
    }

    function renderQr(canvas, text) {
        const qr = window.qrcode(0, 'M');
        qr.addData(text, 'Byte');
        qr.make();
        const n = qr.getModuleCount();
        const scale = Math.max(3, Math.floor(260 / n));
        canvas.width = canvas.height = n * scale;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#000000';
        for (let r = 0; r < n; r++) {
            for (let c = 0; c < n; c++) {
                if (qr.isDark(r, c)) ctx.fillRect(c * scale, r * scale, scale, scale);
            }
        }
    }

    function clearQr() {
        const canvas = $('hostQrCanvas');
        canvas.width = canvas.height = 10;
        show($('hostQrWrap'), false);
        $('hostQrBtn').textContent = '[ SHOW QR CODE ]';
    }

    // ----- Netzwerk-Check -----
    // Prüft lokal, ob Signaling, STUN (IPv4/IPv6, NAT-Typ) und das TURN-Relay
    // erreichbar sind. Zeigt keine IP-Adressen an.
    let netCheckRunning = false;

    function gatherCandidates(iceServers, policy, ms) {
        return new Promise(async (resolve) => {
            const out = [];
            let pc;
            try {
                pc = new RTCPeerConnection({ iceServers, iceTransportPolicy: policy });
                pc.createDataChannel('probe');
                pc.onicecandidate = (e) => { if (e.candidate) out.push(e.candidate); };
                await pc.setLocalDescription(await pc.createOffer());
            } catch (e) { resolve(out); return; }
            const done = () => { try { pc.close(); } catch (e) { /* ignore */ } resolve(out); };
            const t = setTimeout(done, ms);
            pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); done(); } };
        });
    }

    async function relayLoopback(iceServers, ms) {
        const cfg = { iceServers, iceTransportPolicy: 'relay' };
        const a = new RTCPeerConnection(cfg);
        const b = new RTCPeerConnection(cfg);
        try {
            a.onicecandidate = (e) => { if (e.candidate) b.addIceCandidate(e.candidate).catch(() => {}); };
            b.onicecandidate = (e) => { if (e.candidate) a.addIceCandidate(e.candidate).catch(() => {}); };
            const dc = a.createDataChannel('loop');
            const received = new Promise((r) => { b.ondatachannel = (e) => { e.channel.onmessage = () => r(true); }; });
            const opened = new Promise((r) => { dc.onopen = () => { dc.send('ping'); r(true); }; });
            await a.setLocalDescription(await a.createOffer());
            await b.setRemoteDescription(a.localDescription);
            await b.setLocalDescription(await b.createAnswer());
            await a.setRemoteDescription(b.localDescription);
            return await Promise.race([opened.then(() => received), new Promise((r) => setTimeout(() => r(false), ms))]);
        } catch (e) {
            return false;
        } finally {
            try { a.close(); } catch (e) { /* ignore */ }
            try { b.close(); } catch (e) { /* ignore */ }
        }
    }

    async function runNetworkCheck() {
        if (netCheckRunning) return;
        netCheckRunning = true;
        const box = $('netResults');
        const verdictBox = $('netVerdict');
        box.textContent = '';
        show(verdictBox, false);
        const line = (cls, text) => {
            const d = document.createElement('div');
            d.className = cls;
            d.textContent = text;
            box.appendChild(d);
        };
        $('netRunBtn').disabled = true;
        try {
            const runningLine = document.createElement('div');
            runningLine.className = 'net-info';
            runningLine.textContent = '> Running checks (about 20 s)...';
            box.appendChild(runningLine);

            // 1) Signaling-Server
            const sig = CFG.signaling || {};
            let sigOk = false;
            try {
                const url = `${sig.secure === false ? 'http' : 'https'}://${sig.host}:${sig.port}${(sig.path || '/').replace(/\/$/, '')}/${sig.key || 'peerjs'}/id?ts=${Date.now()}`;
                const res = await fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
                sigOk = res.ok;
            } catch (e) { sigOk = false; }
            line(sigOk ? 'net-ok' : 'net-fail', `[${sigOk ? ' OK ' : 'FAIL'}] Signaling server (${sig.host})`);

            // 2) STUN: IPv4/IPv6 und NAT-Verhalten
            const stun = sanitizeIceServers([{ urls: CFG.stunServers || [] }]);
            const stunCands = stun.length ? await gatherCandidates(stun.flatMap((sv) => sv.urls.map((u) => ({ urls: u }))), 'all', 6000) : [];
            const srflx = stunCands.filter((c) => c.type === 'srflx');
            const isV6 = (c) => (c.address || '').includes(':');
            const v4 = srflx.filter((c) => !isV6(c));
            const hasV6 = srflx.some(isV6);
            const ports = {};
            v4.forEach((c) => { (ports[c.relatedPort] = ports[c.relatedPort] || new Set()).add(c.port); });
            const symmetric = Object.values(ports).some((set) => set.size > 1);
            line(v4.length ? 'net-ok' : 'net-fail', `[${v4.length ? ' OK ' : 'FAIL'}] STUN via IPv4${v4.length ? (symmetric ? ' — strict (symmetric) NAT' : ' — NAT allows hole punching') : ' — UDP probably blocked'}`);
            line(hasV6 ? 'net-ok' : 'net-info', `[${hasV6 ? ' OK ' : 'INFO'}] IPv6 ${hasV6 ? 'available' : 'not available'}`);

            // 3) TURN-Relay
            let relayCands = [];
            let relayLoop = false;
            let haveRelayCfg = false;
            try {
                const rtc = await buildRtcConfig(() => {});
                const relays = rtc.iceServers.filter((sv) => sv.username && sv.credential && sv.urls.some((u) => /^turns?:/i.test(u)));
                haveRelayCfg = relays.length > 0;
                if (haveRelayCfg) {
                    relayCands = (await gatherCandidates(relays, 'relay', 10000)).filter((c) => c.type === 'relay');
                    if (relayCands.length) relayLoop = await relayLoopback(relays, 10000);
                }
            } catch (e) { /* ignore */ }
            if (!haveRelayCfg) {
                line('net-info', '[INFO] No TURN relay configured');
            } else {
                const proto = [...new Set(relayCands.map((c) => c.relayProtocol || c.protocol))].join('/');
                line(relayCands.length ? 'net-ok' : 'net-fail', `[${relayCands.length ? ' OK ' : 'FAIL'}] TURN relay reachable${proto ? ' (' + proto + ')' : ''}`);
                if (relayCands.length) line(relayLoop ? 'net-ok' : 'net-fail', `[${relayLoop ? ' OK ' : 'FAIL'}] Data through relay`);
            }

            // Fazit
            let verdict;
            let cls;
            if (!sigOk) {
                verdict = 'This network blocks the signaling server — the app cannot work here. Try another network or mobile data.';
                cls = 'net-fail';
            } else if (relayLoop) {
                verdict = 'Good: the relay works from this network. Connections should succeed (if the other device can reach the relay too).';
                cls = 'net-ok';
            } else if (v4.length && !symmetric) {
                verdict = 'Relay not usable here, but direct connections are possible in many cases.';
                cls = 'net-info';
            } else if (hasV6) {
                verdict = 'Relay not usable here. A direct connection only works if the other device also has IPv6.';
                cls = 'net-info';
            } else {
                verdict = 'Relay blocked and NAT/firewall strict: connections from this network will most likely fail. A firewall or TLS inspection probably blocks WebRTC/TURN. Use mobile data.';
                cls = 'net-fail';
            }
            runningLine.textContent = '> Checks complete.';
            verdictBox.className = 'code-box ' + cls;
            verdictBox.textContent = '> ' + verdict;
            show(verdictBox, true);
        } finally {
            $('netRunBtn').disabled = false;
            netCheckRunning = false;
        }
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

        s.verified = false;
        setStatus('green');
        appendMessage('[SYS] Peer authenticated. Ephemeral ECDH keys, forward secrecy + replay protection active.', 'msg-system');
        showSas(ch.sas);
        if (s.role === 'host') {
            clearQr();
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
        ch.sas = connKeys.sas;
        ch.keys = { send: connKeys.send, recv: connKeys.recv };
        ch.sendSeq = 0;
        ch.recvSeq = 0;
    }

    // Handshake (alle Pakete unter den Handshake-Schlüsseln):
    //   Guest -> Host : hello {g: nonceGuest, c: SHA-256(ECDH-Public-Key Guest)}   (Commitment)
    //   Host  -> Guest: chal  {g: nonceGuest, n: nonceHost, pk: ECDH-Public-Key Host}
    //   Guest -> Host : resp  {n: nonceHost, pk: ECDH-Public-Key Guest}           (Aufdecken)
    // Durch das Commitment kann ein Angreifer mit Room Key die Sicherheitscodes
    // nicht durch Ausprobieren vieler Schlüssel angleichen (wie bei ZRTP).
    // Danach beide: Verbindungsschlüssel aus ECDH + Room Key + Transkript (siehe deriveConnectionKeys).
    async function handleFrame(s, ch, obj) {
        if (s.role === 'host' && !ch.authed) {
            if (obj.t === 'hello' && ch.nonceHost === null) {
                if (typeof obj.g !== 'string' || !NONCE_RE.test(obj.g)) throw new Error('bad hello');
                if (typeof obj.c !== 'string' || !/^[0-9a-f]{64}$/.test(obj.c)) throw new Error('bad commitment');
                ch.peerCommit = obj.c;
                ch.ecdh = await newEcdhKeyPair();
                ch.nonceGuest = obj.g;
                ch.nonceHost = randomHex(16);
                ch.hsSent = await sendFrame(ch, { t: 'chal', g: ch.nonceGuest, n: ch.nonceHost, pk: bytesToB64(ch.ecdh.pubRaw) });
                retransmitHandshake(s, ch, () => !ch.authed);
                return;
            }
            if (obj.t === 'resp' && ch.nonceHost !== null) {
                if (obj.n !== ch.nonceHost) throw new Error('handshake response mismatch');
                if (s.active) throw new Error('room already occupied');
                // Commitment prüfen: der Guest hat sich auf seinen Schlüssel festgelegt,
                // BEVOR er den des Hosts kannte (verhindert das Durchprobieren von SAS-Werten).
                const peer = await importPeerPublicKey(obj.pk);
                if ((await sha256Hex(peer.raw)) !== ch.peerCommit) throw new Error('commitment mismatch');
                ch.peerPub = peer;
                switchToConnectionKeys(ch, await deriveConnectionKeys(s.keys, ch));
                onAuthenticated(s, ch);
                return;
            }
            throw new Error('unexpected handshake frame');
        }
        if (s.role === 'guest' && !ch.authed) {
            if (obj.t !== 'chal' || obj.g !== ch.nonceGuest || typeof obj.n !== 'string' || !NONCE_RE.test(obj.n)) {
                throw new Error('unexpected or stale handshake frame');
            }
            ch.peerPub = await importPeerPublicKey(obj.pk);
            ch.nonceHost = obj.n;
            ch.hsSent = await sendFrame(ch, { t: 'resp', n: ch.nonceHost, pk: bytesToB64(ch.ecdh.pubRaw) });
            switchToConnectionKeys(ch, await deriveConnectionKeys(s.keys, ch));
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

        // Kommt der Datenkanal nicht zustande, nicht endlos "negotiating" anzeigen.
        sTimeout(s, () => {
            if (!ch.dead && !conn.open && !ch.authed) {
                statusFn('[NO PATH] No connection after 45 s — a firewall probably blocks it. Run [3] NETWORK CHECK on both devices.');
            }
        }, 45000);

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
                newEcdhKeyPair().then((kp) => {
                    ch.ecdh = kp;
                    return sha256Hex(kp.pubRaw).then((commit) =>
                        sendFrame(ch, { t: 'hello', g: ch.nonceGuest, c: commit }));
                }).then((pkt) => {
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
        hideSas();
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

    async function panicPurge(reasonAlert) {
        const s = session;
        if (isCurrent(s) && s.active && !s.active.dead) {
            // Gegenseite informieren (best effort), dann alles abbauen.
            try { await Promise.race([sendFrame(s.active, { t: 'bye' }), new Promise((r) => setTimeout(r, 300))]); } catch (e) { /* ignore */ }
        }
        teardown();

        $('hostRoomCode').textContent = '';
        clearQr();
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
        alert(typeof reasonAlert === 'string' ? reasonAlert : '[PANIC PURGE COMPLETE] Connections closed, session keys released, chat history wiped. Clipboard overwritten (if permitted). Note: browsers cannot guarantee memory is physically overwritten — close the tab for best effect.');
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
        clearQr();
        resetGuestView();
        showPage('menu');
    }

    $('splashEnterBtn').addEventListener('click', dismissSplash);
    setTimeout(dismissSplash, 5000);

    $('menuHostBtn').addEventListener('click', startHosting);
    $('menuJoinBtn').addEventListener('click', () => { teardown(); resetGuestView(); showPage('join-setup'); });
    $('menuNetBtn').addEventListener('click', () => { teardown(); showPage('net-check'); runNetworkCheck(); });
    $('netRunBtn').addEventListener('click', () => runNetworkCheck());
    $('netBackBtn').addEventListener('click', () => showPage('menu'));

    $('hostCopyBtn').addEventListener('click', async (ev) => {
        const btn = ev.currentTarget;
        const code = $('hostRoomCode').textContent;
        if (!code) return;
        const ok = await writeClipboard(code);
        flashButton(btn, ok ? '[ COPIED! ]' : '[ COPY FAILED ]');
    });
    $('hostCopyLinkBtn').addEventListener('click', async (ev) => {
        const btn = ev.currentTarget;
        const code = $('hostRoomCode').textContent;
        if (!code) return;
        const ok = await writeClipboard(inviteLink(code));
        flashButton(btn, ok ? '[ LINK COPIED! ]' : '[ COPY FAILED ]');
    });
    $('hostQrBtn').addEventListener('click', () => {
        const code = $('hostRoomCode').textContent;
        if (!code) return;
        if (!$('hostQrWrap').classList.contains('hidden')) { clearQr(); return; }
        try {
            renderQr($('hostQrCanvas'), inviteLink(code));
            show($('hostQrWrap'), true);
            $('hostQrBtn').textContent = '[ HIDE QR CODE ]';
        } catch (e) {
            dbg('QR render failed', e);
            flashButton($('hostQrBtn'), '[ QR FAILED ]');
        }
    });
    $('hostConnectBtn').addEventListener('click', () => {
        if (!session || !session.active) return;
        $('hostRoomCode').textContent = ''; // Room Key wird nach dem Handshake nicht mehr gebraucht
        clearQr();
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

    $('panicBtn').addEventListener('click', () => panicPurge());

    $('sasMatchBtn').addEventListener('click', () => {
        const s = session;
        if (!isCurrent(s) || !s.active) return;
        s.verified = true;
        $('sasBox').classList.add('verified');
        $('sasBox').querySelector('.sas-title').textContent = '> VERIFIED: symbols confirmed identical by you';
        show($('sasMatchBtn'), false);
        setStatus('verified');
        appendMessage('[SYS] Security code confirmed. No one is in the middle.', 'msg-system');
    });
    $('sasMismatchBtn').addEventListener('click', () => {
        panicPurge('[SECURITY ALERT] The security codes differ: someone has probably intercepted the Room Key and is sitting between you and your peer. The session was terminated. Create a new Room Key and hand it over through a different channel (ideally in person via QR code).');
    });
    $('sendBtn').addEventListener('click', sendMessage);
    $('messageInput').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') sendMessage(); });


    // Schutz gegen Einbetten in fremde Seiten (Clickjacking): GitHub Pages kann keine
    // frame-ancestors-Header setzen, daher Prüfung im Skript.
    if (window.top !== window.self) {
        document.body.textContent = 'This page must not be embedded in another site.';
        throw new Error('framed');
    }

    // Einladungslink: Room Key aus dem Fragment übernehmen und das Fragment sofort
    // aus Adresszeile und aktuellem Verlaufseintrag entfernen.
    function consumeInviteFragment() {
        const m = /^#k=([^&]+)/.exec(location.hash || '');
        if (!m) return;
        let code = '';
        try { code = decodeURIComponent(m[1]); } catch (e) { code = ''; }
        try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { location.hash = ''; }
        if (!isValidRoomKey(code)) return;
        if (typeof window.Peer !== 'function' || !window.isSecureContext) return;
        dismissSplash();
        teardown();
        resetGuestView();
        showPage('join-setup');
        $('joinRoomCode').value = code;
        $('joinStatusBox').textContent = 'ROOM KEY RECEIVED VIA INVITE LINK...';
        startGuest(code);
    }
    consumeInviteFragment();
    // Link in einem bereits geöffneten Tab (nur das Fragment ändert sich, kein Neuladen).
    window.addEventListener('hashchange', consumeInviteFragment);

    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
        alert('This page must be served over HTTPS (secure context required for Web Crypto / WebRTC).');
    }
    if (typeof window.Peer !== 'function' || typeof window.qrcode !== 'function') {
        alert('PeerJS failed to load (integrity check failed or file missing). Refusing to continue.');
    }
})();
