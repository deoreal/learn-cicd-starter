package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name            string
		headers         http.Header
		expectedKey     string
		expectedError   error
		shouldHaveError bool
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey:     "abc123",
			expectedError:   nil,
			shouldHaveError: false,
		},
		{
			name:            "missing authorization header",
			headers:         http.Header{},
			expectedKey:     "",
			expectedError:   ErrNoAuthHeaderIncluded,
			shouldHaveError: true,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			expectedKey:     "",
			expectedError:   nil,
			shouldHaveError: true,
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:     "",
			expectedError:   nil,
			shouldHaveError: true,
		},
		{
			name: "malformed header - empty authorization value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:     "",
			expectedError:   ErrNoAuthHeaderIncluded,
			shouldHaveError: true,
		},
		{
			name: "valid API key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey xyz789 extra"},
			},
			expectedKey:     "xyz789",
			expectedError:   nil,
			shouldHaveError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.shouldHaveError {
				if err == nil {
					t.Errorf("GetAPIKey() expected an error but got none")
				}
				if tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
					t.Errorf("GetAPIKey() error = %v, expectedError %v", err, tt.expectedError)
				}
			} else {
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
			}

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, expectedKey %v", key, tt.expectedKey)
			}
		})
	}
}

func TestGetAPIKey_EdgeCases(t *testing.T) {
	t.Run("case sensitive ApiKey prefix", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"apikey test123"},
		}
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Error("GetAPIKey() should fail with lowercase 'apikey'")
		}
	})

	t.Run("multiple authorization headers", func(t *testing.T) {
		headers := http.Header{
			"Authorization": []string{"ApiKey first123", "ApiKey second456"},
		}
		key, err := GetAPIKey(headers)
		if err != nil {
			t.Errorf("GetAPIKey() unexpected error = %v", err)
		}
		// http.Header.Get() returns the first value
		if key != "first123" {
			t.Errorf("GetAPIKey() key = %v, expected %v", key, "first123")
		}
	})
}
