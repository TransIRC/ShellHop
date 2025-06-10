package main

import (
        "fmt"
        "io"
        "log"
        "net"
        "time"
)

const (
        ListenPort     = "50022"             // Relay listens here for client
        GatewayAddress = "transirc.chat:51022" // Gateway target
)

func main() {
        // Attempt to connect to the gateway once at startup
        log.Printf("Relay: Checking connectivity to gateway at %s", GatewayAddress)
        conn, err := net.DialTimeout("tcp", GatewayAddress, 5*time.Second)
        if err != nil {
                log.Fatalf("Relay: Unable to reach gateway at startup: %v", err)
        }
        conn.Close()
        log.Println("Relay: Successfully reached gateway, starting relay...")

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
                go handleClient(clientConn)
        }
}

func handleClient(clientConn net.Conn) {
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

        // Send Proxy Protocol v1 header
        localIP := "127.0.0.1"
        proxyLine := fmt.Sprintf("PROXY TCP4 %s %s %s 2222\r\n", clientIP, localIP, clientPort)
        _, err = gatewayConn.Write([]byte(proxyLine))
        if err != nil {
                log.Printf("Relay: Failed to write proxy header: %v", err)
                return
        }

        // Start piping data
        go io.Copy(gatewayConn, clientConn)
        io.Copy(clientConn, gatewayConn)
}
