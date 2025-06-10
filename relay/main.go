package main

import (
        "bufio"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/hex"
        "fmt"
        "io"
        "log"
        "net"
        "strings"
        "time"
)

const (
        ListenPort     = "50022"         // Relay listens here for client
        GatewayAddress = "transirc.chat:51022" // Gateway target (use localhost for testing)
        ReadTimeout    = 5 * time.Second
        HealthCheckMessage = "HEALTHCHECK\n" // Must match gateway's constant
        HealthCheckResponse = "OK\n"        // Expected response from gateway
)


func main() {
        relayKey := getRelayKey() // Get the de-obfuscated key
        if len(relayKey) == 0 {
                log.Fatalf("Relay: Embedded key is empty or invalid.")
        }

        // --- Health Check Logic ---
        log.Printf("Relay: Performing health check with gateway at %s", GatewayAddress)
        healthConn, err := net.DialTimeout("tcp", GatewayAddress, 5*time.Second)
        if err != nil {
                log.Fatalf("Relay: Failed to connect to gateway for health check: %v", err)
        }
        defer healthConn.Close() // Ensure health check connection is closed

        healthConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
        _, err = healthConn.Write([]byte(HealthCheckMessage))
        healthConn.SetWriteDeadline(time.Time{}) // Clear deadline
        if err != nil {
                log.Fatalf("Relay: Failed to send health check message to gateway: %v", err)
        }

        healthConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        reader := bufio.NewReader(healthConn)
        response, err := reader.ReadString('\n')
        healthConn.SetReadDeadline(time.Time{}) // Clear deadline
        if err != nil {
                log.Fatalf("Relay: Failed to read health check response from gateway: %v", err)
        }

        if strings.TrimSpace(response) != strings.TrimSpace(HealthCheckResponse) {
                log.Fatalf("Relay: Unexpected health check response from gateway: '%s'", strings.TrimSpace(response))
        }
        log.Println("Relay: Gateway health check successful. Starting relay...")
        // --- End Health Check Logic ---

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
                go handleClient(clientConn, relayKey)
        }
}

func generateHMAC(key, data []byte) string {
        h := hmac.New(sha256.New, key)
        h.Write(data)
        return hex.EncodeToString(h.Sum(nil))
}

func handleClient(clientConn net.Conn, relayKey []byte) {
        defer clientConn.Close()
        clientIP, clientPort, err := net.SplitHostPort(clientConn.RemoteAddr().String())
        if err != nil {
                log.Printf("Relay: Failed to get client IP: %v", err)
                return
        }

        log.Printf("Relay: Client connected from %s:%s", clientIP, clientPort)

        // Connect to the gateway
        gatewayConn, err := net.Dial("tcp", GatewayAddress)
        if err != nil {
                log.Printf("Relay: Failed to connect to gateway: %v", err)
                return
        }
        defer gatewayConn.Close()

        gatewayReader := bufio.NewReader(gatewayConn)

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
