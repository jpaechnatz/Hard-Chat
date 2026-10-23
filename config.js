// P2P Terminal — Konfiguration
// ---------------------------------------------------------------------------
// Die App läuft ohne Änderungen: direkte Verbindungen, kein Relay eines Dritten.
// Alles hier ist optional.
// ---------------------------------------------------------------------------
window.ZTT_CONFIG = Object.freeze({

    // Standard: KEIN TURN-Relay. Die App verbindet direkt (IPv6 oder IPv4 mit
    // Hole-Punching über STUN). Das klappt in den meisten Heim- und Mobilfunknetzen,
    // scheitert aber oft in Firmen-, Hotel- und Gäste-WLANs mit strikter Firewall.
    //
    // Optional: eigener TURN-Server. Ein Relay sieht IP-Adressen und Datenmenge,
    // aber KEINE Inhalte (Ende-zu-Ende-Verschlüsselung mit ECDH + AES-GCM).
    //   a) Endpunkt, der kurzlebige Zugangsdaten liefert (z. B. turn-worker/):
    //      URL hier eintragen UND in index.html unter connect-src ergänzen.
    //   b) Eigener coturn mit "use-auth-secret": unten in turnServers eintragen.
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
