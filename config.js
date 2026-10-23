// Zero-Trace Terminal — Konfiguration
// ---------------------------------------------------------------------------
// Die App läuft ohne Änderungen. Für Verbindungen hinter restriktiven Netzen
// (Mobilfunk, Firmen-WLAN) brauchst du nur EINE Zeile: turnCredentialsUrl.
// ---------------------------------------------------------------------------
window.ZTT_CONFIG = Object.freeze({

    // TURN-Relay: leitet die Verbindung weiter, wenn keine direkte Verbindung möglich ist.
    // Ein Relay sieht IP-Adressen und Datenmenge, aber KEINE Inhalte: Nachrichten
    // sind Ende-zu-Ende verschlüsselt (ECDH + AES-GCM).
    //
    // Empfohlen: kostenloses Konto bei Metered (https://www.metered.ca/stun-turn),
    // dort eine TURN-Credential anlegen und die angezeigte API-URL hier eintragen:
    //   turnCredentialsUrl: "https://DEIN-APPNAME.metered.live/api/v1/turn/credentials?apiKey=DEIN_API_KEY",
    // Der API-Key ist laut Metered für den Einsatz im Browser gedacht (nicht der Secret Key!).
    // *.metered.live ist in der Content Security Policy bereits freigegeben.
    //
    // Alternativ eigener Endpunkt (turn-worker/), dann zusätzlich in index.html unter
    // connect-src eintragen und ggf. turnCredentialsMethod: "POST".
    turnCredentialsUrl: "",
    turnCredentialsMethod: "GET",

    // Weitere TURN-Server mit festen Zugangsdaten oder Static-Auth-Secret (coturn
    // "use-auth-secret"); die App erzeugt daraus zeitlich begrenzte Zugangsdaten.
    // Beispiel: { urls: ["turn:turn.example.org:3478"], staticAuthSecret: "...", ttlSeconds: 86400 }
    turnServers: [],

    // STUN-Server (ermitteln nur die öffentliche IP, leiten nichts weiter).
    // adminForge: laut Betreiber ohne IP-Logging (https://adminforge.de/service-stun-server).
    stunServers: [
        "stun:relay.adminforge.de:443",
        "stun:relay2.adminforge.de:443"
    ],

    // true = Verbindung ausschließlich über ein TURN-Relay. Dann erfährt das
    // Gegenüber deine IP-Adresse nicht (nur der Relay-Betreiber).
    // Nachteil: Ohne funktionierendes Relay kommt keine Verbindung zustande.
    forceRelay: false,

    // PeerJS-Signaling-Server. Standard: öffentlicher PeerJS-Cloud-Broker.
    signaling: { host: "0.peerjs.com", port: 443, path: "/", secure: true, key: "peerjs" },

    // Basis-URL für Einladungslink/QR-Code. Leer = aktuelle Seitenadresse.
    shareBaseUrl: "",

    // true = ausführliches Logging in der Browser-Konsole (enthält IP-Adressen!).
    debug: false
});
