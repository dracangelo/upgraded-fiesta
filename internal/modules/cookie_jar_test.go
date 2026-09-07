package modules

import (
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestCookieJarIsOptInForScopedHTTPModules(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "cookies.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	guard := scope.New([]string{"example.test"})
	if NewHTTP(db, guard, models.HTTPConfig{}).client.Jar != nil {
		t.Fatal("cookie jar must default off")
	}
	if NewHTTP(db, guard, models.HTTPConfig{EnableCookieJar: true}).client.Jar == nil {
		t.Fatal("HTTP cookie jar was not enabled")
	}
	if NewDirectoryAPIEnumerator(db, guard, models.HTTPConfig{EnableCookieJar: true}).client.Jar == nil {
		t.Fatal("directory cookie jar was not enabled")
	}
}
