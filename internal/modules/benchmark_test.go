package modules

import (
	"strings"
	"testing"

	"enumscan/internal/scope"
)

func BenchmarkScopeCheck(b *testing.B) {
	guard := scope.New([]string{"127.0.0.1", "10.0.0.0/8", "example.com", "*.internal.net"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = guard.Allowed("sub.internal.net")
	}
}

func BenchmarkEvidenceCleaning(b *testing.B) {
	sample := strings.Repeat("Server: Apache/2.4.41 (Ubuntu)\r\nLocation: https://example.com/admin/login.php\r\n", 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cleanEvidence(sample)
	}
}
