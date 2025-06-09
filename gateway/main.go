package main

import (
        "bufio"
        "io"
        "log"
        "net"
        "strings"
        "time"
)

const (
        GatewayListenPort  = "51022"           // External port relays connect to
        InternalSSHAddress = "127.0.0.1:2222"  // Internal SSH target
        ReadTimeout        = 5 * time.Second
)

func main() {
        listener, err := net.Listen("tcp", ":"+GatewayListenPort)
        if err != nil {
                log.Fatalf("Gateway: Failed to listen on :%s: %v", GatewayListenPort, err)
        }
        log.Printf("Gateway: Listening on port %s", GatewayListenPort)

        for {
                relayConn, err := listener.Accept()
                if err != nil {
                        log.Printf("Gateway: Failed to accept connection: %v", err)
                        continue
                }
                go handleRelay(relayConn)
        }
}

func handleRelay(relayConn net.Conn) {
    defer relayConn.Close()

    relayReader := bufio.NewReader(relayConn)

    relayConn.SetReadDeadline(time.Now().Add(ReadTimeout))
    proxyLine, err := relayReader.ReadString('\n')
    if err != nil {
        log.Printf("Gateway: Failed to read proxy line: %v", err)
        return
    }
    if !strings.HasPrefix(proxyLine, "PROXY ") {
        log.Printf("Gateway: Invalid proxy line: %s", proxyLine)
        return
    }
    relayConn.SetReadDeadline(time.Time{}) // clear deadline

    sshConn, err := net.Dial("tcp", InternalSSHAddress)
    if err != nil {
        log.Printf("Gateway: Failed to connect to internal SSH: %v", err)
        return
    }
    defer sshConn.Close()

    _, err = sshConn.Write([]byte(proxyLine))
    if err != nil {
        log.Printf("Gateway: Failed to forward proxy line to SSH: %v", err)
        return
    }

    log.Printf("Gateway: Relaying connection from %s to internal SSH", relayConn.RemoteAddr())

    // Bidirectional copy with half-close support
    done := make(chan struct{})

    go func() {
        // Copy relay -> ssh
        _, err := io.Copy(sshConn, relayConn)
        if err != nil {
            log.Printf("Gateway: Error copying from relay to SSH: %v", err)
        }
        // Half-close the write side of SSH connection to signal EOF
        if tcpConn, ok := sshConn.(*net.TCPConn); ok {
            tcpConn.CloseWrite()
        } else {
            sshConn.Close()
        }
        done <- struct{}{}
    }()

    // Copy ssh -> relay
    _, err = io.Copy(relayConn, sshConn)
    if err != nil {
        log.Printf("Gateway: Error copying from SSH to relay: %v", err)
    }

    // Wait for the other copy to finish
    <-done
}
