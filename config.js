// Zero-Trace Terminal — Konfiguration
// ---------------------------------------------------------------------------
// Diese Datei ist die EINZIGE Stelle, die du für deinen Betrieb anpassen musst.
// WICHTIG: Jeder Host, den du hier einträgst, muss auch in der Content Security
// Policy (connect-src) in index.html stehen, sonst blockiert der Browser ihn.
// ---------------------------------------------------------------------------
window.ZTT_CONFIG = Object.freeze({

    // URL deines eigenen TURN-Credential-Endpunkts (siehe turn-worker/README.md).
    // Der Endpunkt liefert kurzlebige TURN-Zugangsdaten als {"iceServers":[...]}.
    // Leer lassen = kein TURN, nur STUN (direkte Verbindung; scheitert hinter
    // restriktiven NATs wie manchen Mobilfunk- oder Firmennetzen).
    // Beispiel: "https://hard-chat-turn.DEIN-ACCOUNT.workers.dev/ice"
    turnCredentialsUrl: "",

    // STUN-Server, wenn kein Credential-Endpunkt gesetzt oder erreichbar ist.
    // STUN sieht nur deine öffentliche IP, keine Inhalte.
    stunServers: ["stun:stun.cloudflare.com:3478"],

    // true = Verbindung ausschließlich über dein TURN-Relay. Dann erfährt das
    // Gegenüber deine IP-Adresse nicht (nur der TURN-Betreiber, also du selbst
    // bzw. dein Anbieter). Erfordert turnCredentialsUrl; ohne TURN schlägt die
    // Verbindung dann bewusst fehl (fail closed).
    forceRelay: false,

    // PeerJS-Signaling-Server. Standard: öffentlicher PeerJS-Cloud-Broker.
    // Für vollständige Kontrolle eigenen peerjs-server betreiben
    // (https://github.com/peers/peerjs-server) und hier eintragen.
    signaling: { host: "0.peerjs.com", port: 443, path: "/", secure: true, key: "peerjs" },

    // true = ausführliches Logging in der Browser-Konsole (enthält IP-Adressen!).
    // Nur zur Fehlersuche einschalten.
    debug: false
});
