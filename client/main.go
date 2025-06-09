package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	RelayAddress  = "signalseverywhere.net:50022" // Change to your relay IP:port
	ReadTimeout   = 10 * time.Second
	WriteTimeout  = 10 * time.Second
	SSHServerHost = "gateway" // Used for host key callbacks, doesn't affect stream
)

func main() {
	fmt.Print("SSH Username: ")
	var sshUser string
	_, err := fmt.Scanln(&sshUser)
	if err != nil {
		log.Fatalf("Failed to read username: %v", err)
	}

	conn, err := net.Dial("tcp", RelayAddress)
	if err != nil {
		log.Fatalf("Failed to connect to relay at %s: %v", RelayAddress, err)
	}
	defer conn.Close()

	// SSH auth
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) {
				fmt.Print("SSH Password: ")
				password, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				return string(password), err
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

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

	if err := session.Shell(); err != nil {
		log.Fatalf("Failed to start shell: %v", err)
	}
	session.Wait()
}
