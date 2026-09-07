package modules

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestConfiguredRendererStoresOnlyVerifiedPNG(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "shots")
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "shots.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENUMSCAN_SCREENSHOT_TEST_HELPER", "1")
	renderer := NewBrowserScreenshotRendererWithConfig(db, scope.New([]string{"127.0.0.1"}), models.HTTPConfig{
		EnableScreenshots:      true,
		ScreenshotRenderer:     os.Args[0],
		ScreenshotRendererArgs: []string{"-test.run=TestScreenshotRendererHelper", "--", "{url}", "{output}"},
		ScreenshotOutputDir:    outputDir,
		MaxScreenshotsPerScan:  1,
	})
	_, err = renderer.Handle(context.Background(), models.Event{ScanID: "shot-test", Type: EventHTTPURL, Target: "http://127.0.0.1:8080/"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := db.ScreenshotAssets(context.Background(), "shot-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || !strings.Contains(assets[0].Metadata, "sha256=") {
		t.Fatalf("expected one verified screenshot asset, got %#v", assets)
	}
	if _, err := os.Stat(assets[0].Value); err != nil {
		t.Fatalf("renderer did not retain artifact: %v", err)
	}
}

func TestScreenshotRendererHelper(t *testing.T) {
	if os.Getenv("ENUMSCAN_SCREENSHOT_TEST_HELPER") != "1" {
		return
	}
	var output string
	for _, arg := range os.Args {
		if strings.HasSuffix(arg, ".png") {
			output = arg
		}
	}
	if output == "" {
		os.Exit(2)
	}
	data, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL9WQAAAABJRU5ErkJggg==")
	if err != nil || os.WriteFile(output, data, 0600) != nil {
		os.Exit(3)
	}
	os.Exit(0)
}
