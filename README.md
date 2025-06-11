🐚 ShellHop
===========

**A Single-Hop SSH Relay Network Designed to Circumvent Censorship and Access Controls.**

ShellHop is a minimal, peer-assisted SSH tunneling system that helps users access restricted services---such as IRC bridges---by routing connections through trusted, volunteer-run relay nodes. These relays forward SSH traffic to a gateway under your control, which injects **PROXY protocol headers** to preserve the user's original IP without exposing internal services directly.

🔐 Features
-----------

-   🔁 **Single-Hop Simplicity**\
    Fast, efficient design that routes traffic through a single trusted relay---no complex chain hopping.

-   🛰️ **Peer-Based Relay System** \
    Designed for a distributed, peer-assisted model where clients discover relays automatically.

-   🛡️ **Relay Authentication via HMAC**\
    Uses a challenge-response mechanism with HMAC to ensure only trusted relays can forward traffic.

-   📡 **PROXY Protocol Support**\
    The gateway injects PROXY headers when forwarding traffic, preserving the client's original IP. This is critical for downstream services like `nickgate`, a custom SSH server that authenticates to an Ergo IRC server, preserving the IP address for bans/access control.

-   🧠 **Censorship Resistance**\
    Built to withstand IP blocks, firewalls, and deep packet inspection using trusted, volunteer-run nodes.

-   💻 **User-Focused, Embedded SSH Client**\
    Includes built-in SSH functionality, reducing user setup overhead and improving accessibility.

ShellHop is purpose-built for projects like [**transirc.chat**](https://transirc.chat), where users need **censorship-resistant**, **privacy-preserving**, and **reliable** access to community services---even from hostile networks.

* * * * *

🔒 Key Management, Relay Authentication, and Peer Map Obfuscation
----------------------------------------------------------------

### Key Storage and Authentication

- **Gateway** loads all relay keys from its `keys/` directory, each named `<relayname>.key` and containing a 256-bit hex-encoded secret.
- **Relays** embed their key using a generated Go source file (`relay_key.go`), which applies **XOR obfuscation** to the key bytes. The relay also embeds its key name, which is sent to the gateway upon connection.
- **Authentication** uses a **HMAC-SHA256 challenge-response** protocol. Only relays with a valid key can authenticate and forward traffic.

### Peer Map Tracking and Exchange

- **Gateway** maintains a **peer map** (a list of currently active relay IPs and last-seen timestamps) in memory and persists it as `peer_map.json`.
- During a **health check**, a relay connects to the gateway and sends its relay ID, followed by a health check message.
- The **gateway** responds with:
    1. `"OK\n"` (status),
    2. the peer map as **XOR-obfuscated JSON** (using the relay's key),
    3. and an HMAC-SHA256 signature of the obfuscated data (again, keyed with the relay's secret).

- The **relay**:
    - Deobfuscates and verifies the peer map in memory using the HMAC.
    - Updates its in-memory list of active relays with each health check.

### Peer Map Distribution to Clients

- When a **client** connects to a relay, the relay serves the current peer map **before** the SSH handshake.
- The relay sends the peer map as:
    - `PEERMAP\n`
    - hex-encoded, **XOR-obfuscated JSON** (but **using a static, public obfuscation key**: `"SHELLHOPPEERMAP"`)
    - `ENDPEERMAP\n`
- The relay never sends its private key to clients; the client-only obfuscation is basic and not secret.

### Client Peer Map Handling

- **Client** receives the obfuscated peer map, deobfuscates it in memory, **then immediately saves the obfuscated (not plaintext) version to disk** (overwriting `peer_map.json` in the client binary's directory).
    - Any time the client loads or uses the peer map, it first deobfuscates it with the static key.
- On next startup, the client loads the peer map, deobfuscates it, and can select a random relay from the list, providing basic, automatic relay discovery.

- **The peer map is never stored in plaintext on disk by the client**---it is always XOR-obfuscated using the known static key.

* * * * *

🛠️ Setup Steps
---------------

### 1\. 🗝️ Generate a Gateway Key

On the **gateway server**:

```
cd gateway
./shellhop-gateway -keygen my_relay_key.key
```

This will:

-   Generate a **256-bit random key**.
-   Save it to `keys/my_relay_key.key`.

✅ You can create multiple keys---one per relay---for easier revocation.

* * * * *

### 2\. 🚚 Transfer and Obfuscate the Key on the Relay

1.  **Securely copy** the key file to the relay:

    ```
    scp gateway/keys/my_relay_key.key user@relay:/path/to/relay/
    ```

2.  On the **relay server**:

```
cd relay
go run preparekey.go my_relay_key.key
```

This:

-   Reads the key file.
-   Applies an **XOR obfuscation**.
-   Outputs a `relay_key.go` file with the obfuscated key and runtime logic to decode it.

> ⚠️ Do **not** commit `relay_key.go` if you're concerned about secret leakage. It embeds the secret in obfuscated but recoverable form.

* * * * *

### 3\. 🏗️ Build the Relay Binary

```
go build -o shellhop-relay
```

The resulting binary includes the embedded key and is ready to connect to your gateway.

* * * * *

✅ Summary
---------

| Component   | Description |
|-------------| --- |
| **Gateway** | Accepts relay connections, verifies HMAC auth, injects PROXY headers, tracks relays, and securely distributes the peer map |
| **Relay**   | Connects to gateway, authenticates via HMAC, receives and verifies an obfuscated peer map, stores it in memory, and forwards it to clients with basic obfuscation |
| **Client**  | Connects via SSH to a relay, receives an obfuscated peer map, stores it obfuscated on disk, and loads/deobfuscates it at runtime for automatic relay discovery |
 | **Forge**  | Not currently open-sourced, forge builds relay binaries and generates keys for NickServ / IRC Authenticated users with the Ergo API.

*For full implementation details, see the current source.