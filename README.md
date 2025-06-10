🐚 ShellHop
===========

**A Single-Hop SSH Relay Network Designed to Circumvent Censorship and Access Controls.**

ShellHop is a minimal, peer-assisted SSH tunneling system that helps users access restricted services---such as IRC bridges---by routing connections through trusted, volunteer-run relay nodes. These relays forward SSH traffic to a gateway under your control, which injects **PROXY protocol headers** to preserve the user's original IP without exposing internal services directly.

🔐 Features
-----------

-   🔁 **Single-Hop Simplicity**\
    Fast, efficient design that routes traffic through a single trusted relay---no complex chain hopping.

-   🛰️ **Peer-Based Relay System** *(WIP)*\
    Designed for a distributed, peer-assisted model where clients discover relays automatically.

    > ℹ️ Currently, relay and gateway IPs are hardcoded for testing. You can even connect directly via raw SSH. Dynamic relay discovery via P2P logic is planned.

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

🧪 Key Generation and Relay Obfuscation
---------------------------------------

ShellHop uses **HMAC** for authenticating relays to the gateway. Only relays with a shared secret key can forward traffic. The key is never transmitted --- instead, relays respond to challenges using HMAC signatures. The secret is **obfuscated** into the compiled relay binary.

* * * * *

🛠️ Setup Steps
---------------

### 1\. 🗝️ Generate a Gateway Key

On the **gateway server**:

```
cd gateway
./shellhop-gateway --keygen my_relay_key

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
go run prepare_key.go my_relay_key.key

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
| **Gateway** | Accepts relay connections, verifies HMAC auth, injects PROXY headers |
| **Relay**   | Connects to gateway, authenticates via HMAC, forwards SSH traffic |
| **client**  | Connects via SSH to a relay, which tunnels traffic to the gateway |

