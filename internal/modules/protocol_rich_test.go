package modules

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestRichProtocolProbing(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "rich.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	guard := scope.New([]string{"127.0.0.1"})
	scanner := NewRichProtocolScanner(db, guard)

	// 1. Mock SSH Server
	lSSH, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lSSH.Close()
	go func() {
		for {
			conn, err := lSSH.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n"))
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			conn.Close()
		}
	}()

	sshPort := lSSH.Addr().(*net.TCPAddr).Port
	sshRes, err := scanner.ProbeSSH(ctx, "127.0.0.1", sshPort)
	if err != nil || !strings.Contains(sshRes, "OpenSSH_9.3p1") {
		t.Errorf("expected OpenSSH_9.3p1, got %q (err: %v)", sshRes, err)
	}

	// 2. Mock FTP Server
	lFTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lFTP.Close()
	go func() {
		for {
			conn, err := lFTP.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("220 ProFTPD 1.3.8 Server Ready\r\n"))
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("211-Features:\r\n AUTH TLS\r\n SIZE\r\n211 End\r\n"))
			conn.Close()
		}
	}()

	ftpPort := lFTP.Addr().(*net.TCPAddr).Port
	ftpRes, err := scanner.ProbeFTP(ctx, "127.0.0.1", ftpPort)
	if err != nil || !strings.Contains(ftpRes, "ProFTPD") || !strings.Contains(ftpRes, "AUTH TLS") {
		t.Errorf("unexpected FTP result: %q (err: %v)", ftpRes, err)
	}

	// 3. Mock Redis Server
	lRedis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lRedis.Close()
	go func() {
		for {
			conn, err := lRedis.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("+PONG\r\n"))
			conn.Close()
		}
	}()

	redisPort := lRedis.Addr().(*net.TCPAddr).Port
	redisRes, err := scanner.ProbeRedis(ctx, "127.0.0.1", redisPort)
	if err != nil || !strings.Contains(redisRes, "+PONG") {
		t.Errorf("unexpected Redis result: %q (err: %v)", redisRes, err)
	}

	// 4. Mock Cloud IMDS
	imdsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") == "true" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"compute":{"vmId":"azure-vm-1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer imdsServer.Close()

	scanner.IMDSHost = imdsServer.URL
	imdsRes, err := scanner.ProbeCloudIMDS(ctx, imdsServer.Client())
	if err != nil || !strings.Contains(imdsRes, "Azure") {
		t.Errorf("expected Azure IMDS, got: %q (err: %v)", imdsRes, err)
	}
}
