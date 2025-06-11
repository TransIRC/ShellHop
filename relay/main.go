package main

import (
        "bufio"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net"
        "strings"
        "sync"
        "time"
)

const (
        ListenPort     = "50022"              // Relay listens here for client
        GatewayAddress = "YOUR_GATEWAY_IP_OR_DOMAIN_HERE:51022" // Gateway target (use localhost for testing)
        ReadTimeout    = 5 * time.Second
        HealthCheckMessage = "HEALTHCHECK\n"   // Must match gateway's constant
        HealthCheckOKPrefix = "OK\n"           // Expected prefix from gateway
        HealthCheckInterval = 5 * time.Minute  // Interval for periodic health checks
        PeerMapObfuscationKey = "SHELLHOPPEERMAP"
)

var (
        peerMap     map[string]int64
        peerMapLock sync.RWMutex
)

func main() {
        relayKey := getRelayKey()
        relayKeyName := getRelayKeyName()
        if len(relayKey) == 0 {
                log.Fatalf("Relay: Embedded key is empty or invalid.")
        }
        if relayKeyName == "" {
                log.Fatalf("Relay: Embedded key name is empty or invalid.")
        }

        // Initial health check
        doHealthCheck(relayKey, relayKeyName)

        // Periodic health checks in background
        go func() {
                for {
                        time.Sleep(HealthCheckInterval)
                        doHealthCheck(relayKey, relayKeyName)
                }
        }()

        // Start listening for clients
        listener, err := net.Listen("tcp", ":"+ListenPort)
        if err != nil {
                log.Fatalf("Relay: Failed to listen: %v", err)
        }
        log.Printf("Relay: Listening on port %s", ListenPort)

        for {
                clientConn, err := listener.Accept()
                if err != nil {
                        log.Printf("Relay: Failed to accept client: %v", err)
                        continue
                }
                go handleClient(clientConn, relayKey, relayKeyName)
        }
}

func generateHMAC(key, data []byte) string {
        h := hmac.New(sha256.New, key)
        h.Write(data)
        return hex.EncodeToString(h.Sum(nil))
}

func xorDeobfuscate(data, key []byte) []byte {
        res := make([]byte, len(data))
        for i := 0; i < len(data); i++ {
                res[i] = data[i] ^ key[i%len(key)]
        }
        return res
}

// XOR obfuscation for client peer map (with static string)
func xorObfuscateClient(data []byte) []byte {
        key := []byte(PeerMapObfuscationKey)
        res := make([]byte, len(data))
        for i := 0; i < len(data); i++ {
                res[i] = data[i] ^ key[i%len(key)]
        }
        return res
}

// doHealthCheck performs a health check with the gateway and updates the in-memory peer map
func doHealthCheck(relayKey []byte, relayKeyName string) {
        log.Printf("Relay: Performing health check with gateway at %s", GatewayAddress)
        healthConn, err := net.DialTimeout("tcp", GatewayAddress, 5*time.Second)
        if err != nil {
                log.Printf("Relay: Failed to connect to gateway for health check: %v", err)
                return
        }
        defer healthConn.Close()

        healthConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
        // Send relay ID first
        _, err = healthConn.Write([]byte(fmt.Sprintf("RELAYID %s\n", relayKeyName)))
        if err != nil {
                log.Printf("Relay: Failed to send relay ID to gateway: %v", err)
                return
        }
        // Then send health check message
        _, err = healthConn.Write([]byte(HealthCheckMessage))
        healthConn.SetWriteDeadline(time.Time{})
        if err != nil {
                log.Printf("Relay: Failed to send health check message to gateway: %v", err)
                return
        }

        healthConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        reader := bufio.NewReader(healthConn)
        okLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("Relay: Failed to read health check response from gateway: %v", err)
                return
        }
        if okLine != HealthCheckOKPrefix {
                log.Printf("Relay: Unexpected health check response from gateway: %q", okLine)
                return
        }

        // Read next line: obfuscated peer map (hex)
        obfHexLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("Relay: Failed to read obfuscated peer map from gateway: %v", err)
                return
        }
        obfHex := strings.TrimSpace(obfHexLine)
        obfBytes, err := hex.DecodeString(obfHex)
        if err != nil {
                log.Printf("Relay: Failed to decode obfuscated peer map hex: %v", err)
                return
        }
        deobfJSON := xorDeobfuscate(obfBytes, relayKey)

        // Read next line: HMAC (hex)
        hmacLine, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("Relay: Failed to read HMAC from gateway: %v", err)
                return
        }
        hmacHex := strings.TrimSpace(hmacLine)

        // Validate HMAC
        wantHMAC := generateHMAC(relayKey, obfBytes)
        if !hmac.Equal([]byte(hmacHex), []byte(wantHMAC)) {
                log.Printf("Relay: Peer map HMAC verification failed! Ignoring this peer map.")
                return
        }

        // Parse JSON into peerMap
        var newPeerMap map[string]int64
        if err := json.Unmarshal(deobfJSON, &newPeerMap); err != nil {
                log.Printf("Relay: Failed to parse peer map JSON: %v", err)
                return
        }

        // Store in memory
        peerMapLock.Lock()
        peerMap = newPeerMap
        peerMapLock.Unlock()

        log.Printf("Relay: Health check successful: %d peers in peer map.", len(peerMap))
}

func handleClient(clientConn net.Conn, relayKey []byte, relayKeyName string) {
        defer clientConn.Close()
        clientIP, clientPort, err := net.SplitHostPort(clientConn.RemoteAddr().String())
        if err != nil {
                log.Printf("Relay: Failed to get client IP: %v", err)
                return
        }

        log.Printf("Relay: Client connected from %s:%s", clientIP, clientPort)

        // --- Send peer map to client before SSH ---
        peerMapLock.Lock()
        peerMapCopy := peerMap
        peerMapLock.Unlock()
        peerMapJSON, err := json.Marshal(peerMapCopy)
        if err != nil {
                log.Printf("Relay: Failed to marshal peer map for client: %v", err)
                // Continue anyway
        } else {
                // Obfuscate and send the peer map to the client before SSH handshake
                obf := xorObfuscateClient(peerMapJSON)
                obfHex := hex.EncodeToString(obf)
                // Send as: PEERMAP\n<hex>\nENDPEERMAP\n
                clientConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
                fmt.Fprintf(clientConn, "PEERMAP\n%s\nENDPEERMAP\n", obfHex)
                clientConn.SetWriteDeadline(time.Time{})
        }

        // Connect to the gateway
        gatewayConn, err := net.Dial("tcp", GatewayAddress)
        if err != nil {
                log.Printf("Relay: Failed to connect to gateway: %v", err)
                return
        }
        defer gatewayConn.Close()

        gatewayReader := bufio.NewReader(gatewayConn)

        // Send relay ID first
        gatewayConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
        _, err = gatewayConn.Write([]byte(fmt.Sprintf("RELAYID %s\n", relayKeyName)))
        gatewayConn.SetWriteDeadline(time.Time{})
        if err != nil {
                log.Printf("Relay: Failed to send relay ID to gateway: %v", err)
                return
        }

        // 1. Receive challenge from gateway
        gatewayConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        challengeLine, err := gatewayReader.ReadString('\n')
        if err != nil {
                log.Printf("Relay: Failed to read challenge from gateway: %v", err)
                return
        }
        gatewayConn.SetReadDeadline(time.Time{}) // clear deadline
        challengeHex := strings.TrimSpace(challengeLine)
        challenge, err := hex.DecodeString(challengeHex)
        if err != nil {
                log.Printf("Relay: Failed to decode challenge from gateway: %v", err)
                return
        }

        // 2. Calculate HMAC and send response
        hmacSignature := generateHMAC(relayKey, challenge)
        response := fmt.Sprintf("%s:%s\n", challengeHex, hmacSignature)
        gatewayConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
        if _, err := gatewayConn.Write([]byte(response)); err != nil {
                log.Printf("Relay: Failed to send HMAC response to gateway: %v", err)
                return
        }
        gatewayConn.SetWriteDeadline(time.Time{}) // Clear write deadline
        log.Printf("Relay: Sent HMAC response to gateway for %s:%s", clientIP, clientPort)

        // 3. Send Proxy Protocol v1 header
        localIP := "127.0.0.1" // This should ideally be the gateway's internal IP if it's acting as a proxy to localhost
        proxyLine := fmt.Sprintf("PROXY TCP4 %s %s %s 2222\r\n", clientIP, localIP, clientPort)
        _, err = gatewayConn.Write([]byte(proxyLine))
        if err != nil {
                log.Printf("Relay: Failed to write proxy header to gateway: %v", err)
                return
        }
        log.Printf("Relay: Sent Proxy Protocol header for %s:%s", clientIP, clientPort)

        // Start piping data
        go io.Copy(gatewayConn, clientConn)
        io.Copy(clientConn, gatewayConn)
}
