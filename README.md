🐚 ShellHop
-----------

**A Single-Hop SSH Relay Network Designed to Circumvent Censorship and Access Controls.**

Shellhop is a minimal, peer-assisted SSH tunneling system that helps users access restricted services --- such as IRC bridges --- by routing connections through trusted, volunteer-run relay nodes. These relays forward SSH traffic to a gateway under your control, which injects PROXY protocol headers to preserve the user's original IP without exposing internal services directly.

🔐 **Features**

-   🔁 **Single-hop architecture** for simplicity and speed

-   🛰️ **Peer-based relays** with client reachability checks

-   🛡️ **Relay Authentication** ensuring only trusted relays can forward proxy protocol ips

-   🧠 **Resilient design** to withstand network filtering and IP blocks

-   💻 **User-focused** with embedded SSH client

Shellhop is built for projects like [transirc.chat](https://transirc.chat), where users need reliable, censorship-resistant access --- even from hostile networks.
