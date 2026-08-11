package scope

import (
	"testing"
)

func TestGuardAllowed(t *testing.T) {
	guard := New([]string{
		"  ",
		"192.168.1.1",
		"10.0.0.0/24",
		"example.com",
		"*.test.local",
	})

	tests := []struct {
		target   string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.1:8080", true},
		{"http://192.168.1.1/path", true},
		{"10.0.0.45", true},
		{"10.0.0.45:22", true},
		{"10.0.1.1", false},
		{"example.com", true},
		{"sub.example.com", true},
		{"http://api.sub.example.com:8080/v1/users", true},
		{"other.com", false},
		{"sub.test.local", true},
		{"test.local", true},
		{"unrelated.local", false},
	}

	for _, tt := range tests {
		if got := guard.Allowed(tt.target); got != tt.expected {
			t.Errorf("Allowed(%q) = %v; want %v", tt.target, got, tt.expected)
		}
	}
}
