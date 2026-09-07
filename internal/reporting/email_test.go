package reporting

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestDeliverEmailUsesExplicitLocalSMTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go fakeSMTP(listener, received)

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "email.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "scan-email", Type: "host", Value: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := DeliverEmail(ctx, db, "scan-email", listener.Addr().String(), "enumscan@example.test", "team@example.test", "", ""); err != nil {
		t.Fatal(err)
	}
	message := <-received
	if !strings.Contains(message, "Subject: [enumscan] evidence summary: scan-email") || !strings.Contains(message, "Assets: 1") {
		t.Fatalf("unexpected email body: %q", message)
	}
}

func TestSMTPInputValidation(t *testing.T) {
	if _, err := validateSMTPInputs("smtp.example.test:587", "from@example.test", "to@example.test", "user", ""); err == nil {
		t.Fatal("expected missing password to be rejected")
	}
	if _, err := validateSMTPInputs("not-a-server", "from@example.test", "to@example.test", "", ""); err == nil {
		t.Fatal("expected malformed server to be rejected")
	}
}

func fakeSMTP(listener net.Listener, received chan<- string) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	write := func(format string, args ...any) { _, _ = fmt.Fprintf(writer, format, args...); _ = writer.Flush() }
	write("220 enumscan local SMTP\r\n")
	inData := false
	var body strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if inData {
			if trimmed == "." {
				inData = false
				received <- body.String()
				write("250 queued\r\n")
				continue
			}
			body.WriteString(line)
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToUpper(trimmed), "EHLO"):
			write("250-localhost\r\n250 OK\r\n")
		case strings.HasPrefix(strings.ToUpper(trimmed), "MAIL FROM"), strings.HasPrefix(strings.ToUpper(trimmed), "RCPT TO"):
			write("250 OK\r\n")
		case strings.EqualFold(trimmed, "DATA"):
			inData = true
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
		case strings.EqualFold(trimmed, "QUIT"):
			write("221 bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}
