// P2P Terminal — Konfiguration
// ---------------------------------------------------------------------------
// Verbindungen laufen direkt von Browser zu Browser. Nur wenn das nicht geht
// (strikte Firewall, Carrier-NAT), springt das TURN-Relay von Metered ein.
// ---------------------------------------------------------------------------
window.ZTT_CONFIG = Object.freeze({

    // Optional: Endpunkt, der kurzlebige TURN-Zugangsdaten liefert (z. B. turn-worker/).
    // URL hier eintragen UND in index.html unter connect-src ergänzen.
    turnCredentialsUrl: "",
    turnCredentialsMethod: "GET",

    // TURN-Relays. Ein Relay sieht IP-Adressen und Datenmenge, aber KEINE Inhalte
    // (Ende-zu-Ende-Verschlüsselung mit ECDH + AES-GCM). Wird nur genutzt, wenn
    // keine Direktverbindung möglich ist (außer bei forceRelay: true).
    //
    // Metered (Free Tier, Workspace "p2ptermin"): nur TURNS = TURN über TLS auf
    // Port 443 — die TURN-Verbindung selbst ist verschlüsselt und kommt auch durch
    // die meisten Firewalls. Zugangsdaten Base64-kodiert: das ist NUR Verschleierung
    // gegen automatische Scanner, jeder kann sie dekodieren. Bei Missbrauch im
    // Metered-Dashboard löschen und neu anlegen.
    //
    // Mögliche Felder je Eintrag: username/credential (Klartext),
    // usernameB64/credentialB64 (Base64) oder staticAuthSecret (coturn use-auth-secret).
    turnServers: [
        {
            urls: ["turns:global.relay.metered.ca:443?transport=tcp"],
            usernameB64: "N2RmN2EyMjlhN2I0MzIwM2Y0MTQ2N2Ji",
            credentialB64: "aHpXRlRoRkppZ0FCY1llSg=="
        }
    ],

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
