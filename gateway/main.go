package main

import (
        "bufio"
        "crypto/hmac"
        "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "flag"
        "fmt"
        "io"
        "log"
        "net"
        "os"
        "path/filepath"
        "strings"
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
)

var (
        keygenName string // This will hold the name provided after -keygen
        loadedKeys [][]byte // Slice to hold all loaded secret keys
)

func init() {
        flag.StringVar(&keygenName, "keygen", "", "Generate a new random key and store it as <value>.key in the 'keys/' directory.")
}

func main() {
        flag.Parse()

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

        var err error
        loadedKeys, err = loadAllKeysFromDir(KeysDirectory)
        if err != nil {
                log.Fatalf("Gateway: Error loading keys from '%s' directory: %v", KeysDirectory, err)
        }

        if len(loadedKeys) == 0 {
                log.Fatalf("Gateway: No secret keys found in the '%s/' directory. " +
                        "Please generate at least one key by running: './gateway -keygen <your_key_name>'", KeysDirectory)
        }
        log.Printf("Gateway: Loaded %d secret key(s) from '%s/' directory.", len(loadedKeys), KeysDirectory)

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

// loadAllKeysFromDir reads all files in the specified directory,
// attempts to decode them as hex-encoded keys, and returns a slice of valid keys.
func loadAllKeysFromDir(dir string) ([][]byte, error) {
        var keys [][]byte

        // Create the directory if it doesn't exist, ignore if it does
        if err := os.MkdirAll(dir, 0700); err != nil {
                return nil, fmt.Errorf("could not create key directory %s: %w", dir, err)
        }

        files, err := os.ReadDir(dir)
        if err != nil {
                // If directory doesn't exist, treat as no keys found, not a fatal error here
                if os.IsNotExist(err) {
                        return nil, nil
                }
                return nil, fmt.Errorf("failed to read key directory %s: %w", dir, err)
        }

        for _, file := range files {
                if file.IsDir() {
                        continue // Skip subdirectories
                }
                filePath := filepath.Join(dir, file.Name())
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
                keys = append(keys, decodedKey)
                log.Printf("Gateway: Loaded key: %s", filePath) // Log successful key load
        }
        return keys, nil
}

// verifyHMACAgainstAny checks if the provided signature is valid against any of the given keys.
func verifyHMACAgainstAny(keys [][]byte, data []byte, signature string) bool {
        for _, k := range keys {
                h := hmac.New(sha256.New, k)
                h.Write(data)
                expectedMAC := hex.EncodeToString(h.Sum(nil))
                if hmac.Equal([]byte(signature), []byte(expectedMAC)) {
                        return true // Authentication successful with this key
                }
        }
        return false // No key matched the HMAC
}

func handleRelay(relayConn net.Conn) {
        defer relayConn.Close()

        relayReader := bufio.NewReader(relayConn)

        // First, try to read a potential health check message without a deadline
        // or with a very short one to avoid blocking.
        // We'll set a short deadline here to quickly determine if it's a health check
        // or a regular connection attempting HMAC.
        relayConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) // Very short timeout for health check
        peekedBytes, err := relayReader.Peek(len(HealthCheckMessage))
        relayConn.SetReadDeadline(time.Time{}) // Clear deadline

        if err == nil && string(peekedBytes) == HealthCheckMessage {
                // It's a health check! Read the message fully and respond.
                _, _ = relayReader.ReadString('\n') // Consume the health check message
                log.Printf("Gateway: Received health check from %s. Responding with 'OK'.", relayConn.RemoteAddr())
                relayConn.SetWriteDeadline(time.Now().Add(ReadTimeout))
                _, writeErr := relayConn.Write([]byte("OK\n"))
                relayConn.SetWriteDeadline(time.Time{})
                if writeErr != nil {
                        log.Printf("Gateway: Failed to send health check response to %s: %v", relayConn.RemoteAddr(), writeErr)
                }
                return // Health check handled, close connection
        }

        // If it's not a health check, proceed with HMAC authentication.
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

        // Verify the received challenge matches the sent challenge
        if receivedChallengeHex != hex.EncodeToString(challenge) {
                log.Printf("Gateway: Challenge mismatch from %s. Expected %s, Got %s", relayConn.RemoteAddr(), hex.EncodeToString(challenge), receivedChallengeHex)
                return
        }

        // 3. Verify HMAC against any loaded key
        if !verifyHMACAgainstAny(loadedKeys, challenge, receivedHMACSignature) {
                log.Printf("Gateway: Invalid HMAC signature from %s", relayConn.RemoteAddr())
                return
        }
        log.Printf("Gateway: Successfully authenticated relay from %s", relayConn.RemoteAddr())

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
