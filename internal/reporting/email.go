package reporting

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"enumscan/internal/store"
)

// DeliverEmail sends a compact evidence summary only when explicitly requested
// by the operator. Non-local SMTP servers must advertise STARTTLS; a password
// is supplied through the caller rather than configuration or command history.
func DeliverEmail(ctx context.Context, db *store.SQLiteCLI, scanID, server, from, to, username, password string) error {
	host, err := validateSMTPInputs(server, from, to, username, password)
	if err != nil {
		return err
	}
	assets, err := db.Assets(ctx, scanID)
	if err != nil {
		return err
	}
	findings, err := db.Findings(ctx, scanID)
	if err != nil {
		return err
	}
	counts := severityCounts(findings)
	subject := "[enumscan] evidence summary: " + headerSafe(scanID)
	body := fmt.Sprintf("Enumscan evidence summary\n\nScan: %s\nAssets: %d\nFindings: %d\nCritical: %d\nHigh: %d\nMedium: %d\n\n%s", scanID, len(assets), len(findings), counts["critical"], counts["high"], counts["medium"], ExecutiveSummary(report{ScanID: scanID, Assets: assets, Findings: findings}))
	if len(body) > 64*1024 {
		body = body[:64*1024] + "\n[summary truncated; retrieve the local report for full evidence]"
	}
	message := []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n"))

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return fmt.Errorf("connect SMTP server: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Quit()

	if !isLoopbackHost(host) {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not advertise STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	return nil
}

func validateSMTPInputs(server, from, to, username, password string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(server))
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("SMTP server must be host:port")
	}
	if _, err := mail.ParseAddress(from); err != nil || strings.ContainsAny(from, "\r\n") {
		return "", fmt.Errorf("invalid sender address")
	}
	if _, err := mail.ParseAddress(to); err != nil || strings.ContainsAny(to, "\r\n") {
		return "", fmt.Errorf("invalid recipient address")
	}
	if (username == "") != (password == "") {
		return "", fmt.Errorf("SMTP username and password must be provided together")
	}
	return host, nil
}

func headerSafe(value string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(value) }
