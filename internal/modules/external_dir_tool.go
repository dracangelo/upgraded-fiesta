package modules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

var (
	ErrToolNotApproved    = errors.New("external directory tool is not in approved tool list")
	ErrTargetOutOfScope   = errors.New("target URL or host is out of authorized scan scope")
	ErrWordlistLimitLimit = errors.New("wordlist exceeds maximum allowed bounded entries")
)

// ExternalDirectoryToolWrapper executes approved directory tools (gobuster, dirb, ffuf)
// with strict scope validation, request ceilings, and provenance tracking.
type ExternalDirectoryToolWrapper struct {
	mu           sync.RWMutex
	db           store.RuntimeStore
	guard        scope.Guard
	approvedList map[string]bool
	maxEntries   int
	client       *http.Client
}

// NewExternalDirectoryToolWrapper initializes the directory tool wrapper.
func NewExternalDirectoryToolWrapper(db store.RuntimeStore, guard scope.Guard) *ExternalDirectoryToolWrapper {
	return &ExternalDirectoryToolWrapper{
		db:    db,
		guard: guard,
		approvedList: map[string]bool{
			"gobuster": true,
			"dirb":     true,
			"ffuf":     true,
		},
		maxEntries: 100,
		client:     scopedHTTPClient(guard, 4*time.Second, nil),
	}
}

// ExecuteScopedDirectoryScan executes or simulates a bounded external directory tool run.
func (w *ExternalDirectoryToolWrapper) ExecuteScopedDirectoryScan(
	ctx context.Context,
	scanID, targetURL, toolName, wordlistPath string,
) ([]models.Asset, error) {
	toolName = strings.ToLower(strings.TrimSpace(toolName))

	w.mu.RLock()
	approved := w.approvedList[toolName]
	w.mu.RUnlock()

	if !approved {
		return nil, fmt.Errorf("%w: %s", ErrToolNotApproved, toolName)
	}

	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid target URL")
	}

	if !w.guard.Allowed(parsed.Hostname()) {
		return nil, fmt.Errorf("%w: %s", ErrTargetOutOfScope, parsed.Hostname())
	}

	// Read and bound wordlist
	words, err := w.readBoundedWordlist(wordlistPath)
	if err != nil {
		return nil, err
	}

	var discovered []models.Asset

	// If the binary exists on system PATH, invoke it with bounded parameters
	if binPath, err := exec.LookPath(toolName); err == nil && binPath != "" {
		discovered, err = w.executeBinary(ctx, scanID, binPath, targetURL, toolName, words)
		if err == nil && len(discovered) > 0 {
			return discovered, nil
		}
	}

	// Safe integrated bounded fallback runner with provenance tagging
	for _, word := range words {
		select {
		case <-ctx.Done():
			return discovered, ctx.Err()
		default:
		}

		path := "/" + strings.TrimPrefix(word, "/")
		fullURL := strings.TrimRight(targetURL, "/") + path

		req, err := http.NewRequestWithContext(ctx, http.MethodHead, fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			metadata := fmt.Sprintf("status=%d;provenance=external_wrapper;tool=%s", resp.StatusCode, toolName)
			asset := models.Asset{
				ScanID:    scanID,
				Type:      "directory_path",
				Value:     fullURL,
				Parent:    targetURL,
				Metadata:  metadata,
				CreatedAt: time.Now().UTC(),
			}
			if w.db != nil {
				_ = w.db.AddAsset(ctx, asset)
			}
			discovered = append(discovered, asset)
		}
	}

	return discovered, nil
}

func (w *ExternalDirectoryToolWrapper) readBoundedWordlist(path string) ([]string, error) {
	if path == "" {
		// Default bounded discovery list
		return []string{"admin", "login", "api", "health", "metrics", "robots.txt"}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
		if len(words) > w.maxEntries {
			return nil, fmt.Errorf("%w: limit is %d", ErrWordlistLimitLimit, w.maxEntries)
		}
	}
	return words, scanner.Err()
}

func (w *ExternalDirectoryToolWrapper) executeBinary(
	ctx context.Context,
	scanID, binPath, targetURL, toolName string,
	words []string,
) ([]models.Asset, error) {
	// Create temporary bounded wordlist file
	tmpFile, err := os.CreateTemp("", "enumscan-wordlist-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	for _, w := range words {
		_, _ = tmpFile.WriteString(w + "\n")
	}
	_ = tmpFile.Close()

	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch toolName {
	case "gobuster":
		cmd = exec.CommandContext(timeoutCtx, binPath, "dir", "-u", targetURL, "-w", tmpFile.Name(), "-q", "-t", "5")
	case "dirb":
		cmd = exec.CommandContext(timeoutCtx, binPath, targetURL, tmpFile.Name(), "-r", "-z", "100")
	default:
		return nil, fmt.Errorf("runner not configured for tool: %s", toolName)
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var discovered []models.Asset
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.Contains(trimmed, "==>") || strings.Contains(trimmed, "Found:") || strings.HasPrefix(trimmed, "+") {
			asset := models.Asset{
				ScanID:    scanID,
				Type:      "directory_path",
				Value:     trimmed,
				Parent:    targetURL,
				Metadata:  fmt.Sprintf("provenance=external_wrapper;tool=%s", toolName),
				CreatedAt: time.Now().UTC(),
			}
			if w.db != nil {
				_ = w.db.AddAsset(ctx, asset)
			}
			discovered = append(discovered, asset)
		}
	}

	return discovered, nil
}
