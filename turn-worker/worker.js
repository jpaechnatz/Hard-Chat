// P2P Terminal — TURN-Credential-Worker (Cloudflare Workers)
// ---------------------------------------------------------------------------
// Liefert dem Browser KURZLEBIGE TURN-Zugangsdaten. Die eigentlichen Geheimnisse
// (Cloudflare-API-Token bzw. coturn-Shared-Secret) bleiben im Worker und landen
// nie im öffentlichen Repository.
//
// Zwei Betriebsarten (per Secrets/Variablen gewählt):
//   A) Cloudflare Realtime TURN   -> Secrets TURN_KEY_ID + TURN_KEY_API_TOKEN
//   B) Eigener coturn-Server      -> Secret COTURN_SECRET + Variable COTURN_URLS
//      (coturn mit "use-auth-secret" und "static-auth-secret=<COTURN_SECRET>")
//
// Variablen:
//   ALLOWED_ORIGIN  z.B. "https://jpaechnatz.github.io" (Pflicht)
//   CRED_TTL        Gültigkeit in Sekunden (Standard 7200)
// ---------------------------------------------------------------------------

export default {
    async fetch(request, env) {
        const origin = request.headers.get('Origin') || '';
        const allowed = (env.ALLOWED_ORIGIN || '').trim();
        const cors = {
            'Access-Control-Allow-Origin': allowed,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Max-Age': '600',
            'Vary': 'Origin',
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff'
        };

        // Nur Aufrufe von der eigenen Seite. Hinweis: Origin lässt sich außerhalb
        // eines Browsers fälschen — das ist ein Missbrauchs-Bremsklotz, kein Schutz.
        // Für echten Schutz zusätzlich Rate Limiting aktivieren (siehe README).
        if (!allowed || origin !== allowed) {
            return new Response('forbidden', { status: 403, headers: { 'Cache-Control': 'no-store' } });
        }
        if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
        if (request.method !== 'POST' && request.method !== 'GET') return new Response('method not allowed', { status: 405, headers: cors });

        if (env.RATE_LIMITER) {
            const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
            const { success } = await env.RATE_LIMITER.limit({ key: ip });
            if (!success) return new Response('rate limited', { status: 429, headers: cors });
        }

        const ttl = Math.min(Math.max(parseInt(env.CRED_TTL || '7200', 10) || 7200, 300), 86400);

        try {
            let iceServers;
            if (env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) {
                iceServers = await cloudflareTurn(env, ttl);
            } else if (env.COTURN_SECRET && env.COTURN_URLS) {
                iceServers = await coturnCredentials(env, ttl);
            } else {
                return json({ error: 'worker not configured' }, 500, cors);
            }
            return json({ iceServers }, 200, cors);
        } catch (e) {
            return json({ error: 'upstream failure' }, 502, cors);
        }
    }
};

function json(obj, status, headers) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: { ...headers, 'Content-Type': 'application/json' }
    });
}

// A) Cloudflare Realtime TURN — https://developers.cloudflare.com/realtime/turn/generate-credentials/
async function cloudflareTurn(env, ttl) {
    const res = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.TURN_KEY_ID)}/credentials/generate-ice-servers`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${env.TURN_KEY_API_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ttl })
        }
    );
    if (!res.ok) throw new Error('cloudflare ' + res.status);
    const data = await res.json();
    // Port 53 wird von Browsern blockiert und verzögert nur den Verbindungsaufbau.
    return (data.iceServers || []).map((s) => ({
        ...s,
        urls: (Array.isArray(s.urls) ? s.urls : [s.urls]).filter((u) => !/:53(\?|$)/.test(u))
    })).filter((s) => s.urls.length);
}

// B) coturn "TURN REST API" (use-auth-secret): username = "<ablauf>:<label>",
//    credential = base64(HMAC-SHA1(secret, username)).
async function coturnCredentials(env, ttl) {
    const expiry = Math.floor(Date.now() / 1000) + ttl;
    const username = `${expiry}:ztt`;
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(env.COTURN_SECRET),
        { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(username));
    const credential = btoa(String.fromCharCode(...new Uint8Array(sig)));
    const urls = env.COTURN_URLS.split(',').map((u) => u.trim()).filter((u) => u && !/:53(\?|$)/.test(u));
    const stun = urls.filter((u) => u.startsWith('stun:'));
    const turn = urls.filter((u) => /^turns?:/.test(u));
    const out = [];
    if (stun.length) out.push({ urls: stun });
    if (turn.length) out.push({ urls: turn, username, credential });
    return out;
}
