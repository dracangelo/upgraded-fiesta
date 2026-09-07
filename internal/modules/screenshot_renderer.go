package modules

import (
	"context"
	"crypto/sha256"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

const maxScreenshotBytes int64 = 10 << 20

// BrowserScreenshotRenderer invokes an operator-supplied, local browser
// wrapper. The wrapper must enforce any browser-network policy required by an
// engagement. Enumscan neither guesses a renderer nor records a gallery item
// until an image file is present and its checksum has been verified.
type BrowserScreenshotRenderer struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	config models.HTTPConfig
	mu     sync.Mutex
	counts map[string]int
}

// NewBrowserScreenshotRenderer preserves the disabled default for callers
// that have not provided a renderer configuration.
func NewBrowserScreenshotRenderer(db *store.SQLiteCLI, guard scope.Guard) *BrowserScreenshotRenderer {
	return NewBrowserScreenshotRendererWithConfig(db, guard, models.HTTPConfig{})
}

func NewBrowserScreenshotRendererWithConfig(db *store.SQLiteCLI, guard scope.Guard, config models.HTTPConfig) *BrowserScreenshotRenderer {
	if config.MaxScreenshotsPerScan <= 0 {
		config.MaxScreenshotsPerScan = 25
	}
	return &BrowserScreenshotRenderer{db: db, guard: guard, config: config, counts: make(map[string]int)}
}

func (m *BrowserScreenshotRenderer) Name() string { return "browser_screenshot_renderer" }

func (m *BrowserScreenshotRenderer) Subscriptions() []string { return []string{EventHTTPURL} }

func (m *BrowserScreenshotRenderer) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.config.EnableScreenshots || !m.guard.Allowed(evt.Target) {
		return nil, nil
	}
	parsed, err := url.Parse(evt.Target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !m.guard.Allowed(parsed.Hostname()) {
		return nil, nil
	}
	if !m.reserve(evt.ScanID) {
		return nil, nil
	}

	output, err := m.outputPath(evt.ScanID, evt.Target)
	if err != nil {
		m.recordError(ctx, evt, err)
		return nil, nil
	}
	args := make([]string, len(m.config.ScreenshotRendererArgs))
	for i, arg := range m.config.ScreenshotRendererArgs {
		args[i] = strings.ReplaceAll(strings.ReplaceAll(arg, "{url}", evt.Target), "{output}", output)
	}
	renderCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if outputBytes, err := exec.CommandContext(renderCtx, m.config.ScreenshotRenderer, args...).CombinedOutput(); err != nil {
		m.recordError(ctx, evt, fmt.Errorf("renderer failed: %w; output=%s", err, cleanEvidence(string(outputBytes))))
		return nil, nil
	}

	format, width, height, checksum, err := verifyScreenshot(output)
	if err != nil {
		m.recordError(ctx, evt, err)
		return nil, nil
	}
	if err := m.db.AddAsset(ctx, models.Asset{
		ScanID: evt.ScanID,
		Type:   "screenshot",
		Value:  output,
		Parent: evt.Target,
		Metadata: fmt.Sprintf("sha256=%s;format=%s;width=%d;height=%d;renderer=operator_configured",
			checksum, format, width, height),
	}); err != nil {
		return nil, fmt.Errorf("persist verified screenshot: %w", err)
	}
	return nil, nil
}

func (m *BrowserScreenshotRenderer) reserve(scanID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts[scanID] >= m.config.MaxScreenshotsPerScan {
		return false
	}
	m.counts[scanID]++
	return true
}

func (m *BrowserScreenshotRenderer) outputPath(scanID, target string) (string, error) {
	if !filepath.IsAbs(m.config.ScreenshotOutputDir) {
		return "", fmt.Errorf("screenshot output directory is not absolute")
	}
	if err := os.MkdirAll(m.config.ScreenshotOutputDir, 0700); err != nil {
		return "", fmt.Errorf("create screenshot root directory: %w", err)
	}
	if err := os.Chmod(m.config.ScreenshotOutputDir, 0700); err != nil {
		return "", fmt.Errorf("restrict screenshot root directory permissions: %w", err)
	}
	scanDir := filepath.Join(m.config.ScreenshotOutputDir, safeScreenshotComponent(scanID))
	if err := os.MkdirAll(scanDir, 0700); err != nil {
		return "", fmt.Errorf("create screenshot output directory: %w", err)
	}
	if err := os.Chmod(scanDir, 0700); err != nil {
		return "", fmt.Errorf("restrict screenshot output directory permissions: %w", err)
	}
	digest := sha256.Sum256([]byte(target))
	output := filepath.Join(scanDir, fmt.Sprintf("%x.png", digest[:8]))
	if rel, err := filepath.Rel(m.config.ScreenshotOutputDir, output); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("screenshot output escaped configured directory")
	}
	return output, nil
}

func verifyScreenshot(path string) (format string, width, height int, checksum string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("renderer did not create a screenshot: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxScreenshotBytes {
		return "", 0, 0, "", fmt.Errorf("screenshot size %d is outside permitted bounds", info.Size())
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", 0, 0, "", fmt.Errorf("restrict screenshot permissions: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, 0, "", err
	}
	defer file.Close()
	config, format, err := image.DecodeConfig(file)
	if err != nil || format != "png" || config.Width < 1 || config.Height < 1 {
		return "", 0, 0, "", fmt.Errorf("renderer output is not a valid PNG screenshot")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, 0, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxScreenshotBytes+1)); err != nil {
		return "", 0, 0, "", err
	}
	return format, config.Width, config.Height, fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (m *BrowserScreenshotRenderer) recordError(ctx context.Context, evt models.Event, err error) {
	_ = m.db.AddAsset(ctx, models.Asset{
		ScanID: evt.ScanID, Type: "screenshot_capture_error", Value: evt.Target, Parent: evt.Target,
		Metadata: "error=" + cleanEvidence(err.Error()),
	})
}

func safeScreenshotComponent(value string) string {
	if value == "" {
		return "scan"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
