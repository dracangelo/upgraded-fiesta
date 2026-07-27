package modules

import (
	"net/url"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
)

func TestDirectoryAPIWordlistIsTechnologyAwareAndBounded(t *testing.T) {
	m := NewDirectoryAPIEnumerator(nil, scope.New([]string{"example.test"}), models.HTTPConfig{
		DirectoryWordlist: []string{"/custom", "/admin"},
		MaxDirectoryPaths: 50,
	})
	paths := m.wordlist(`<html>WordPress wp-content</html>`)
	want := map[string]bool{"/wp-admin/": true, "/wp-json/": true, "/custom": true}
	for _, path := range paths {
		delete(want, path)
	}
	if len(want) != 0 {
		t.Fatalf("missing technology-aware paths: %#v", want)
	}
	if got := uniquePaths([]string{"/b", "/a", "/a"}, 2); len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("unexpected unique paths: %#v", got)
	}
}

func TestScopedPathRejectsExternalTargets(t *testing.T) {
	root, _ := url.Parse("https://example.test")
	if item, ok := scopedPath(root, "/api"); !ok || item.String() != "https://example.test/api" {
		t.Fatalf("expected scoped relative path, got %v %v", item, ok)
	}
	if _, ok := scopedPath(root, "https://outside.test/api"); ok {
		t.Fatal("external path must be rejected")
	}
}
