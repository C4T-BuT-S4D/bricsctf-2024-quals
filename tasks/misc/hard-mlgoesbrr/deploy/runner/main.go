package main

import (
	"archive/zip"
	"bytes"
	"context"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var addr = flag.String("addr", ":8000", "listen address")
var ydfCodePath = flag.String("ydf", "", "path to ydfcode code")

func copyZipArchieve(zipReader *zip.Reader) (string, error) {
	dir, err := os.MkdirTemp("", "models")
	if err != nil {
		return "", fmt.Errorf("error creating temp dir: %w", err)
	}

	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		destPath := filepath.Join(dir, file.Name)

		if !strings.HasPrefix(destPath, dir) {
			return "", fmt.Errorf("invalid file path: %s", file.Name)
		}

		zipFile, err := file.Open()
		if err != nil {
			return "", fmt.Errorf("error opening file: %w", err)
		}
		defer zipFile.Close()

		destFile, err := os.Create(destPath)
		if err != nil {
			return "", fmt.Errorf("error creating file: %w", err)
		}

		_, err = io.Copy(destFile, zipFile)
		if err != nil {
			return "", fmt.Errorf("error copying file: %w", err)
		}
	}

	return dir, nil
}

func prepareRustCode(modelPath string) (string, error) {
	t, err := template.ParseFiles(filepath.Join(*ydfCodePath, "predictor/src/main.rs.tmpl"))
	if err != nil {
		return "", fmt.Errorf("error parsing template: %w", err)
	}

	f, err := os.Create(filepath.Join(*ydfCodePath, "predictor/src/main.rs"))
	if err != nil {
		return "", fmt.Errorf("error creating main.rs file: %w", err)
	}

	config := map[string]string{
		"modelPath": modelPath,
	}

	err = t.Execute(f, config)
	if err != nil {
		return "", fmt.Errorf("error executing template: %w", err)
	}

	return *ydfCodePath, nil
}

func processConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	write := func(msg string, args ...interface{}) {
		fmt.Fprintf(conn, msg, args...)
	}
	read := func(msg string, args ...interface{}) (int, error) {
		return fmt.Fscanf(conn, msg, args...)
	}

	write("Send me the number of bytes in your model zip archive\n")
	var numBytes int
	_, err := read("%d", &numBytes)
	if err != nil {
		write("Error reading input")
		return
	}

	if numBytes <= 0 {
		write("Invalid number of bytes\n")
		return
	}

	write("Send me the zip archive with your model\n")
	buf := make([]byte, numBytes)
	n, err := conn.Read(buf)
	if err != nil {
		write("Error reading input")
		return
	}

	if n != numBytes {
		write("Bytes mismatch: expected %d, got %d\n", numBytes, n)
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(buf), int64(numBytes))
	if err != nil {
		write("Error reading zip archive: %v\n", err)
		return
	}

	modelDir, err := copyZipArchieve(zipReader)
	if err != nil {
		write("Error copying zip archive: %v\n", err)
		return
	}
	defer os.RemoveAll(modelDir)

	write("Model uploaded successfully\n")

	rustDir, err := prepareRustCode(modelDir)
	if err != nil {
		write("Error preparing rust code: %v\n", err)
		return
	}

	write("Starting execution\n")

	ctx, cancel := context.WithTimeout(ctx, 1200000*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cargo", "run", "--release")
	cmd.Dir = filepath.Join(rustDir, "predictor")
	cmd.Stdout = conn
	cmd.Stdin = conn

	err = cmd.Run()
	if err != nil {
		write("Error running command: %v\n", err)
		return
	}
}

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Error starting TCP server: %v", err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s\n", *addr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					// Server is shutting down, stop accepting connections
					break
				default:
					log.Printf("Error accepting connection: %v\n", err)
				}
				continue
			}
			go processConnection(ctx, conn)
		}
	}()

	<-signalChan
	cancel()
}
