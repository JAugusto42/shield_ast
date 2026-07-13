package reporter

import (
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"Short string", "hello", 10, "hello"},
		{"Exact length string", "hello world", 11, "hello world"},
		{"Long string", "this is a very long string", 10, "this is..."},
		{"Empty string", "", 5, "-"},
		{"String with newlines", "hello\nworld", 20, "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.max)

			if result != tt.expected {
				t.Errorf("truncate(%q, %d) = %q; want %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}
