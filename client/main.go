package main

import (
        "bufio"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "math/rand"
        "net"
        "os"
        "path/filepath"
        "strings"
        "time"

        "golang.org/x/crypto/ssh"
        "golang.org/x/term"
)

const (
        RelayPort          = "50022" // All relays use this port
        ReadTimeout        = 10 * time.Second
        WriteTimeout       = 10 * time.Second
        SSHServerHost      = "gateway" // Used for host key callbacks, doesn't affect stream
        PeerMapObfuscationKey = "SHELLHOPPEERMAP"
        PeerMapFileName    = "peer_map.json"
)

// xorDeobfuscateClient undoes the XOR obfuscation using the static key for peer map
func xorDeobfuscateClient(data []byte) []byte {
        key := []byte(PeerMapObfuscationKey)
        res := make([]byte, len(data))
        for i := 0; i < len(data); i++ {
                res[i] = data[i] ^ key[i%len(key)]
        }
        return res
}

// xorObfuscateClient obfuscates the peer map using the same static key
func xorObfuscateClient(data []byte) []byte {
        // This is identical to xorDeobfuscateClient (XOR is symmetric)
        return xorDeobfuscateClient(data)
}

// getSeedRelay returns a random relay from the list or from peer_map.json if present
func getSeedRelay() string {
        exePath, err := os.Executable()
        if err != nil {
                log.Fatalf("Failed to get executable path: %v", err)
        }
        exeDir := filepath.Dir(exePath)
        peerMapPath := filepath.Join(exeDir, PeerMapFileName)

        // If peer_map.json exists and is valid, try to read relays from it
        if data, err := os.ReadFile(peerMapPath); err == nil {
                deobf := xorDeobfuscateClient(data)
                var peerMap map[string]int64
                if json.Unmarshal(deobf, &peerMap) == nil && len(peerMap) > 0 {
                        // Pick a random peer (as relay IP)
                        keys := make([]string, 0, len(peerMap))
                        for k := range peerMap {
                                keys = append(keys, k)
                        }
                        rand.Seed(time.Now().UnixNano())
                        relay := keys[rand.Intn(len(keys))]
                        // Always append the port
                        relay = relay + ":" + RelayPort
                        return relay
                }
        }
        // Otherwise, pick a random relay from the hardcoded seed list and append port
        rand.Seed(time.Now().UnixNano())
        relay := SeedRelays[rand.Intn(len(SeedRelays))]
        return relay + ":" + RelayPort
}

func performHealthCheckAndUpdatePeerMap(relayAddr string) {
        // Connect to the relay for health check and peer map update
        conn, err := net.Dial("tcp", relayAddr)
        if err != nil {
                log.Printf("Unable to connect to relay at %s for peer map update: %v", relayAddr, err)
                return
        }
        defer conn.Close()

        // --- Receive peer map before SSH handshake ---
        conn.SetReadDeadline(time.Now().Add(ReadTimeout))
        reader := bufio.NewReader(conn)
        line, err := reader.ReadString('\n')
        if err != nil {
                log.Printf("Failed to read from relay: %v", err)
                return
        }
        updated := false
        if strings.TrimSpace(line) == "PEERMAP" {
                // Read obfuscated peer map hex
                obfHexLine, err := reader.ReadString('\n')
                if err != nil {
                        log.Printf("Failed to read peer map hex from relay: %v", err)
                        return
                }
                obfHex := strings.TrimSpace(obfHexLine)
                // Read end marker
                endLine, err := reader.ReadString('\n')
                if err != nil || strings.TrimSpace(endLine) != "ENDPEERMAP" {
                        log.Printf("Failed to read peer map end marker from relay: %v", err)
                        return
                }
                obfBytes, err := hex.DecodeString(obfHex)
                if err != nil {
                        log.Printf("Failed to decode peer map hex: %v", err)
                        return
                }
                deobf := xorDeobfuscateClient(obfBytes)
                // Write peer_map.json in same dir as binary, but obfuscated!
                exePath, err := os.Executable()
                if err != nil {
                        log.Printf("Failed to get executable path: %v", err)
                        return
                }
                exeDir := filepath.Dir(exePath)
                peerMapPath := filepath.Join(exeDir, PeerMapFileName)
                obfToSave := xorObfuscateClient(deobf) // (Re-)obfuscate before saving (no-op here but explicit)
                if err := os.WriteFile(peerMapPath, obfToSave, 0644); err != nil {
                        log.Printf("Failed to write peer_map.json: %v", err)
                        return
                }
                fmt.Println("Peermap Updated from Relay")
                updated = true
        }
        conn.SetReadDeadline(time.Time{})
        if !updated {
                // Unexpected; rewind to use this line as SSH (shouldn't happen on health check)
                _ = line // Just ignore
        }
}

func main() {
        // Pick a relay (random from seed list or peer map)
        relayAddr := getSeedRelay()

        // Health check and peer_map update before user input
        performHealthCheckAndUpdatePeerMap(relayAddr)

        // Prompt for SSH username
        fmt.Print("SSH Username: ")
        var sshUser string
        _, err := fmt.Scanln(&sshUser)
        if err != nil {
                log.Fatalf("Failed to read username: %v", err)
        }

        // Connect to the relay for SSH
        conn, err := net.Dial("tcp", relayAddr)
        if err != nil {
                log.Fatalf("Failed to connect to relay at %s: %v", relayAddr, err)
        }
        defer conn.Close()

        // --- Receive peer map before SSH handshake (again, in case relay sends it again) ---
        conn.SetReadDeadline(time.Now().Add(ReadTimeout))
        reader := bufio.NewReader(conn)
        line, err := reader.ReadString('\n')
        if err != nil {
                log.Fatalf("Failed to read from relay: %v", err)
        }
        if strings.TrimSpace(line) == "PEERMAP" {
                obfHexLine, err := reader.ReadString('\n')
                if err != nil {
                        log.Fatalf("Failed to read peer map hex from relay: %v", err)
                }
                obfHex := strings.TrimSpace(obfHexLine)
                endLine, err := reader.ReadString('\n')
                if err != nil || strings.TrimSpace(endLine) != "ENDPEERMAP" {
                        log.Fatalf("Failed to read peer map end marker from relay: %v", err)
                }
                obfBytes, err := hex.DecodeString(obfHex)
                if err != nil {
                        log.Fatalf("Failed to decode peer map hex: %v", err)
                }
                deobf := xorDeobfuscateClient(obfBytes)
                exePath, err := os.Executable()
                if err != nil {
                        log.Fatalf("Failed to get executable path: %v", err)
                }
                exeDir := filepath.Dir(exePath)
                peerMapPath := filepath.Join(exeDir, PeerMapFileName)
                obfToSave := xorObfuscateClient(deobf)
                if err := os.WriteFile(peerMapPath, obfToSave, 0644); err != nil {
                        log.Fatalf("Failed to write peer_map.json: %v", err)
                }
                // fmt.Println("Peermap Updated from Relay")
        } else {
                // Unexpected; rewind to use this line as SSH
                reader = bufio.NewReader(io.MultiReader(strings.NewReader(line), conn))
        }
        conn.SetReadDeadline(time.Time{})

        // SSH auth
        config := &ssh.ClientConfig{
                User: sshUser,
                Auth: []ssh.AuthMethod{
                        ssh.PasswordCallback(func() (string, error) {
                                // Prompt for SSH password
                                fmt.Print("SSH Password: ")
                                password, err := term.ReadPassword(int(os.Stdin.Fd()))
                                fmt.Println()
                                return string(password), err
                        }),
                },
                HostKeyCallback: ssh.InsecureIgnoreHostKey(),
                Timeout:         30 * time.Second,
        }

        // Start SSH client connection
        sshConn, chans, reqs, err := ssh.NewClientConn(conn, SSHServerHost, config)
        if err != nil {
                log.Fatalf("Failed to establish SSH connection: %v", err)
        }
        client := ssh.NewClient(sshConn, chans, reqs)
        defer client.Close()

        session, err := client.NewSession()
        if err != nil {
                log.Fatalf("Failed to create SSH session: %v", err)
        }
        defer session.Close()

        // Set terminal mode to raw
        fd := int(os.Stdin.Fd())
        oldState, err := term.MakeRaw(fd)
        if err != nil {
                log.Fatalf("Failed to set raw terminal: %v", err)
        }
        defer term.Restore(fd, oldState)

        session.Stdout = os.Stdout
        session.Stderr = os.Stderr
        session.Stdin = os.Stdin

        // Use OS-specific getTerminalSize
        width, height := getTerminalSize()

        // Request PTY
        err = session.RequestPty("xterm", height, width, ssh.TerminalModes{})
        if err != nil {
                log.Fatalf("Request for PTY failed: %v", err)
        }

        // Setup OS-specific resize handler
        resizeChan := make(chan os.Signal, 1)
        setupResizeHandler(resizeChan)

        go func() {
                for range resizeChan {
                        w, h := getTerminalSize()
                        err := session.WindowChange(h, w)
                        if err != nil {
                                log.Printf("Failed to send window change request: %v", err)
                        }
                }
        }()

        // Start the shell
        if err := session.Shell(); err != nil {
                log.Fatalf("Failed to start shell: %v", err)
        }
        session.Wait()
}
