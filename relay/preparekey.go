//go:build ignore

package main

import (
        "crypto/rand"
        "encoding/hex"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "path/filepath"
        "strings"
)

var (
        gatewayKeyFileFlag string
)

func init() {
        flag.StringVar(&gatewayKeyFileFlag, "gatewaykey", "", "Path to the gateway key file to embed in the relay. If not provided, the first positional argument will be used.")
}

func main() {
        flag.Parse()

        // Determine the actual key file path
        var keyFilePath string
        if gatewayKeyFileFlag != "" {
                keyFilePath = gatewayKeyFileFlag
        } else if len(flag.Args()) > 0 {
                keyFilePath = flag.Args()[0]
        } else {
                keyFilePath = "relay.key"
        }

        // Extract the base name (without extension) as the key name for relay/gateway protocol
        keyfileBase := filepath.Base(keyFilePath)
        keyName := strings.TrimSuffix(keyfileBase, filepath.Ext(keyfileBase))

        keyHex, err := ioutil.ReadFile(keyFilePath)
        if err != nil {
                log.Fatalf("Failed to read key file %s: %v", keyFilePath, err)
        }
        key, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
        if err != nil {
                log.Fatalf("Failed to decode key hex from %s: %v", keyFilePath, err)
        }
        if len(key) != 32 {
                log.Fatalf("Invalid key length in %s: expected 32 bytes, got %d", keyFilePath, len(key))
        }

        obfuscatedKey := make([]byte, len(key))
        xorKey := make([]byte, len(key))
        if _, err := rand.Read(xorKey); err != nil {
                log.Fatalf("Failed to generate XOR key: %v", err)
        }

        for i := 0; i < len(key); i++ {
                obfuscatedKey[i] = key[i] ^ xorKey[i]
        }

        output := fmt.Sprintf(`// Code generated by preparekey.go. DO NOT EDIT.
package main

var (
        obfuscatedRelayKey = []byte{ %s }
        xorRelayKey        = []byte{ %s }
        relayKeyName       = "%s"
)

func getRelayKey() []byte {
        key := make([]byte, len(obfuscatedRelayKey))
        for i := 0; i < len(obfuscatedRelayKey); i++ {
                key[i] = obfuscatedRelayKey[i] ^ xorRelayKey[i]
        }
        return key
}

func getRelayKeyName() string {
        return relayKeyName
}
`, byteSliceToHexString(obfuscatedKey), byteSliceToHexString(xorKey), keyName)

        if err := ioutil.WriteFile("relay_key.go", []byte(output), 0644); err != nil {
                log.Fatalf("Failed to write relay_key.go: %v", err)
        }
        log.Println("Successfully generated relay_key.go")
}

func byteSliceToHexString(data []byte) string {
        parts := make([]string, len(data))
        for i, b := range data {
                parts[i] = fmt.Sprintf("0x%02x", b)
        }
        return strings.Join(parts, ", ")
}
