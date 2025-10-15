package utilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertBoolToString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    bool
		expected string
	}{
		{
			name:     "true_value",
			input:    true,
			expected: "true",
		},
		{
			name:     "false_value",
			input:    false,
			expected: "false",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := ConvertBoolToString(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConvertStringToBool(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "true_string",
			input:    "true",
			expected: true,
		},
		{
			name:     "false_string",
			input:    "false",
			expected: false,
		},
		{
			name:     "empty_string",
			input:    "",
			expected: false,
		},
		{
			name:     "invalid_string",
			input:    "invalid",
			expected: false,
		},
		{
			name:     "uppercase_true",
			input:    "TRUE",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := ConvertStringToBool(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
