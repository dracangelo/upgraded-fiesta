package modules

import (
	"strings"
	"testing"
)

func TestReadBoundedHTTPBodyHonorsLimitAndReturnsIndependentBytes(t *testing.T) {
	body, err := readBoundedHTTPBody(strings.NewReader("abcdef"), 4)
	if err != nil || string(body) != "abcd" {
		t.Fatalf("unexpected body: %q, %v", body, err)
	}
	body[0] = 'z'
	fresh, err := readBoundedHTTPBody(strings.NewReader("hello"), 5)
	if err != nil || string(fresh) != "hello" {
		t.Fatalf("pooled buffer leaked content: %q, %v", fresh, err)
	}
}
