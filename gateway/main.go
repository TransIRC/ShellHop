package main

import (
        "bufio"
        "crypto/hmac"
        "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "log"
        "net"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"
)

const (
        GatewayListenPort  = "51022"      // External port relays connect to
        InternalSSHAddress = "127.0.0.1:2222" // Internal SSH target
        ReadTimeout        = 5 * time.Second
        HMACChallengeSize  = 16 // Size of the random challenge for HMAC
        HMACSignatureSize  = sha256.Size * 2 // SHA256 in hex (2 hex chars per byte)
        KeysDirectory      = "keys" // The fixed directory for keys
        HealthCheckMessage = "HEALTHCHECK\n" // New: Health check message
        PeerMapFileName    = "peer_map.json" // Peer map file in same dir as gateway binary
        PeerTimeout        = 10 * time.Minute // Timeout for relay peer entries
)

var (
        keygenName string // This will hold the name provided after -keygen
        loadedKeys map[string][]byte // keyname -> key bytes

        peerMap     = make(map[string]int64) // map[ip]=lastSeenUnix
        peerMapLock sync.Mutex
        peerMapPath string
)

// PeerMapData is for saving/loading peer_map.json
type PeerMapData map[string]int64

func init() {
        flag.StringVar(&keygenName, "keygen", "", "Generate a new random key and store it as <value>.key in the 'keys/' directory.")
}

func main() {
        flag.Parse()

        // Determine peer_map.json path (same dir as the gateway binary)
        exePath, err := os.Executable()
        if err != nil {
                log.Fatalf("Gateway: Failed to determine executable path: %v", err)
        }
        exeDir := filepath.Dir(exePath)
        peerMapPath = filepath.Join(exeDir, PeerMapFileName)

        if keygenName != "" {
                if !strings.HasSuffix(keygenName, ".key") {
                        keygenName += ".key"
                }
                fullKeyPath := filepath.Join(KeysDirectory, keygenName)
                if err := generateAndSaveKey(fullKeyPath); err != nil {
                        log.Fatalf("Gateway: Failed to generate and save key to %s: %v", fullKeyPath, err)
                }
                log.Printf("Gateway: Generated new key and saved to %s", fullKeyPath)
                return
        }

        var loadErr error
        loadedKeys, loadErr = loadAllKeysFromDir(KeysDirectory)
        if loadErr != nil {
                log.Fatalf("Gateway: Error loading keys from '%s' directory: %v", KeysDirectory, loadErr)
        }

        if len(loadedKeys) == 0 {
                log.Fatalf("Gateway: No secret keys found in the '%s/' directory. " +
                        "Please generate at least one key by running: './gateway -keygen <your_key_name>'", KeysDirectory)
        }
        log.Printf("Gateway: Loaded %d secret key(s) from '%s/' directory.", len(loadedKeys), KeysDirectory)

        // Load existing peer map from file (if exists)
        if err := loadPeerMap(); err != nil {
                log.Printf("Gateway: Warning: Failed to load peer map: %v (continuing with empty map)", err)
        }

        // Start goroutine for cleaning peers
        go peerMapCleaner()

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

// generateAndSaveKey creates a new random key and saves it to the specified full path.
// It ensures the directory exists.
func generateAndSaveKey(fullPath string) error {
        key := make([]byte, 32) // 256-bit key
        if _, err := rand.Read(key); err != nil {
                return fmt.Errorf("failed to generate random key: %w", err)
        }

        dir := filepath.Dir(fullPath)
        if err := os.MkdirAll(dir, 0700); err != nil {
                return fmt.Errorf("failed to create directory %s: %w", dir, err)
        }

        return os.WriteFile(fullPath, []byte(hex.EncodeToString(key)), 0600)
}

// loadAllKeysFromDir returns map of keyname (filename without .key) to key bytes
func loadAllKeysFromDir(dir string) (map[string][]byte, error) {
        keys := make(map[string][]byte)

        if err := os.MkdirAll(dir, 0700); err != nil {
                return nil, fmt.Errorf("could not create key directory %s: %w", dir, err)
        }

        files, err := os.ReadDir(dir)
        if err != nil {
                if os.IsNotExist(err) {
                        return keys, nil
                }
                return nil, fmt.Errorf("failed to read key directory %s: %w", dir, err)
        }

        for _, file := range files {
                if file.IsDir() {
                        continue
                }
                name := file.Name()
                if !strings.HasSuffix(name, ".key") {
                        continue
                }
                keyname := strings.TrimSuffix(name, ".key")
                filePath := filepath.Join(dir, name)
                keyBytes, err := os.ReadFile(filePath)
                if err != nil {
                        log.Printf("Gateway: Warning: Failed to read key file %s: %v", filePath, err)
                        continue
                }
                decodedKey, err := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
                if err != nil {
                        log.Printf("Gateway: Warning: Failed to decode hex key from file %s: %v", filePath, err)
                        continue
                }
                if len(decodedKey) != 32 {
                        log.Printf("Gateway: Warning: Invalid key length in file %s: expected 32 bytes, got %d", filePath, len(decodedKey))
                        continue
                }
                keys[keyname] = decodedKey
                log.Printf("Gateway: Loaded key: %s as %s", filePath, keyname)
        }
        return keys, nil
}

func verifyHMACAgainstKey(key []byte, data []byte, signature string) bool {
        h := hmac.New(sha256.New, key)
        h.Write(data)
        expectedMAC := hex.EncodeToString(h.Sum(nil))
        return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// Save peerMap to peer_map.json
func savePeerMap() error {
        peerMapLock.Lock()
        defer peerMapLock.Unlock()
        f, err := os.Create(peerMapPath)
        if err != nil {
                return err
        }
        defer f.Close()
        enc := json.NewEncoder(f)
        return enc.Encode(peerMap)
}

// Load peerMap from peer_map.json
func loadPeerMap() error {
        peerMapLock.Lock()
        defer peerMapLock.Unlock()
        data, err := os.ReadFile(peerMapPath)
        if err != nil {
                if os.IsNotExist(err) {
                        return nil // no file, ignore
                }
                return err
        }
        return json.Unmarshal(data, &peerMap)
}

// Periodically remove old peers and save peer_map.json
func peerMapCleaner() {
        for {
                time.Sleep(1 * time.Minute)
                now := time.Now().Unix()
                changed := false

                peerMapLock.Lock()
                for ip, lastSeen := range peerMap {
                        if now-lastSeen > int64(PeerTimeout.Seconds()) {
                                delete(peerMap, ip)
                                changed = true
                        }
                }
                peerMapLock.Unlock()
                if changed {
                        if err := savePeerMap(); err != nil {
                                log.Printf("Gateway: Error saving peer map during cleanup: %v", err)
                        }
                }
        }
}

// Get relay's remote IP as string (without port)
func remoteIPOnly(addr net.Addr) string {
        host, _, err := net.SplitHostPort(addr.String())
        if err != nil {
                return addr.String()
        }
        return host
}

// Marshal peerMap to JSON for hmac sending
func marshalPeerMapJSON() ([]byte, error) {
        peerMapLock.Lock()
        defer peerMapLock.Unlock()
        return json.Marshal(peerMap)
}

func xorObfuscate(data, key []byte) []byte {
        obfuscated := make([]byte, len(data))
        for i := 0; i < len(data); i++ {
                obfuscated[i] = data[i] ^ key[i%len(key)]
        }
        return obfuscated
}

func handleRelay(relayConn net.Conn) {
        defer relayConn.Close()

        relayReader := bufio.NewReader(relayConn)

        // Read relay ID first
        relayConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        relayIDLine, err := relayReader.ReadString('\n')
        if err != nil {
                log.Printf("Gateway: Failed to read relay ID from %s: %v", relayConn.RemoteAddr(), err)
                return
        }
        relayConn.SetReadDeadline(time.Time{})

        relayIDLine = strings.TrimSpace(relayIDLine)
        if !strings.HasPrefix(relayIDLine, "RELAYID ") {
                log.Printf("Gateway: Missing RELAYID header from %s: %q", relayConn.RemoteAddr(), relayIDLine)
                return
        }
        relayKeyName := strings.TrimSpace(strings.TrimPrefix(relayIDLine, "RELAYID "))

        relayKey, ok := loadedKeys[relayKeyName]
        if !ok {
                log.Printf("Gateway: Unknown relay key name '%s' from %s", relayKeyName, relayConn.RemoteAddr())
                return
        }

        // Peek to see if this is a health check
        relayConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
        peekedBytes, err := relayReader.Peek(len(HealthCheckMessage))
        relayConn.SetReadDeadline(time.Time{})

        if err == nil && string(peekedBytes) == HealthCheckMessage {
                // Health Check
                _, _ = relayReader.ReadString('\n')
                relayIP := remoteIPOnly(relayConn.RemoteAddr())

                // Update peer map
                now := time.Now().Unix()
                peerMapLock.Lock()
                peerMap[relayIP] = now
                peerMapLock.Unlock()
                if err := savePeerMap(); err != nil {
                        log.Printf("Gateway: Failed to save peer map after health check: %v", err)
                }

                peerMapJSON, err := marshalPeerMapJSON()
                if err != nil {
                        log.Printf("Gateway: Failed to marshal peer map JSON: %v", err)
                        relayConn.Write([]byte("ERROR\n"))
                        return
                }

                obfuscated := xorObfuscate(peerMapJSON, relayKey)
                obfHex := hex.EncodeToString(obfuscated)
                h := hmac.New(sha256.New, relayKey)
                h.Write(obfuscated)
                hmacSig := hex.EncodeToString(h.Sum(nil))

                relayConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
                _, writeErr := relayConn.Write([]byte(fmt.Sprintf("OK\n%s\n%s\n", obfHex, hmacSig)))
                relayConn.SetWriteDeadline(time.Time{})
                if writeErr != nil {
                        log.Printf("Gateway: Failed to send health check response to %s: %v", relayConn.RemoteAddr(), writeErr)
                } else {
                        log.Printf("Gateway: Sent obfuscated peer map to relay %s (health check, key %s)", relayIP, relayKeyName)
                }
                return
        }

        // Not a health check, proceed with HMAC authentication

        // 1. Send challenge
        challenge := make([]byte, HMACChallengeSize)
        if _, err := rand.Read(challenge); err != nil {
                log.Printf("Gateway: Failed to generate challenge for %s: %v", relayConn.RemoteAddr(), err)
                return
        }
        challengeHex := hex.EncodeToString(challenge) + "\n"
        relayConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
        if _, err := relayConn.Write([]byte(challengeHex)); err != nil {
                log.Printf("Gateway: Failed to send challenge to %s: %v", relayConn.RemoteAddr(), err)
                return
        }
        relayConn.SetWriteDeadline(time.Time{})

        // 2. Receive HMAC response (challenge + signature)
        relayConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        responseLine, err := relayReader.ReadString('\n')
        if err != nil {
                log.Printf("Gateway: Failed to read HMAC response from %s: %v", relayConn.RemoteAddr(), err)
                return
        }
        relayConn.SetReadDeadline(time.Time{})

        parts := strings.SplitN(strings.TrimSpace(responseLine), ":", 2)
        if len(parts) != 2 {
                log.Printf("Gateway: Invalid HMAC response format from %s: %s", relayConn.RemoteAddr(), responseLine)
                return
        }
        receivedChallengeHex := parts[0]
        receivedHMACSignature := parts[1]

        if receivedChallengeHex != hex.EncodeToString(challenge) {
                log.Printf("Gateway: Challenge mismatch from %s. Expected %s, Got %s", relayConn.RemoteAddr(), hex.EncodeToString(challenge), receivedChallengeHex)
                return
        }

        if !verifyHMACAgainstKey(relayKey, challenge, receivedHMACSignature) {
                log.Printf("Gateway: Invalid HMAC signature from %s (relay key: %s)", relayConn.RemoteAddr(), relayKeyName)
                return
        }
        log.Printf("Gateway: Successfully authenticated relay from %s using key %s", relayConn.RemoteAddr(), relayKeyName)

        // 4. Read proxy line
        relayConn.SetReadDeadline(time.Now().Add(ReadTimeout))
        proxyLine, err := relayReader.ReadString('\n')
        if err != nil {
                log.Printf("Gateway: Failed to read proxy line from %s after authentication: %v", relayConn.RemoteAddr(), err)
                return
        }
        if !strings.HasPrefix(proxyLine, "PROXY ") {
                log.Printf("Gateway: Invalid proxy line from %s: %s", relayConn.RemoteAddr(), proxyLine)
                return
        }
        relayConn.SetReadDeadline(time.Time{})

        sshConn, err := net.Dial("tcp", InternalSSHAddress)
        if err != nil {
                log.Printf("Gateway: Failed to connect to internal SSH for %s: %v", relayConn.RemoteAddr(), err)
                return
        }
        defer sshConn.Close()

        _, err = sshConn.Write([]byte(proxyLine))
        if err != nil {
                log.Printf("Gateway: Failed to forward proxy line to SSH for %s: %v", relayConn.RemoteAddr(), err)
                return
        }

        log.Printf("Gateway: Relaying authenticated connection from %s to internal SSH", relayConn.RemoteAddr())

        done := make(chan struct{})

        go func() {
                _, err := io.Copy(sshConn, relayReader)
                if err != nil {
                        log.Printf("Gateway: Error copying from relay to SSH for %s: %v", relayConn.RemoteAddr(), err)
                }
                if tcpConn, ok := sshConn.(*net.TCPConn); ok {
                        tcpConn.CloseWrite()
                } else {
                        sshConn.Close()
                }
                done <- struct{}{}
        }()

        _, err = io.Copy(relayConn, sshConn)
        if err != nil {
                log.Printf("Gateway: Error copying from SSH to relay for %s: %v", relayConn.RemoteAddr(), err)
        }

        <-done
}
