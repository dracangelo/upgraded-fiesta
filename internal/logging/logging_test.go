package logging

import (
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := New()
	if logger == nil {
		t.Fatal("expected non-nil slog.Logger")
	}
	logger.Info("test log message")
}
