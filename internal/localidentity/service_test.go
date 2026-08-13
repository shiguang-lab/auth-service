package localidentity

import "testing"

func TestSafeReturnToAcceptsOnlyLocalPathsAndConfiguredOrigin(t *testing.T) {
	service := &Service{cfg: Config{Origin: "http://127.0.0.1:18080"}}
	tests := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/applications?status=active", "/applications?status=active"},
		{"http://127.0.0.1:18080/applications", "http://127.0.0.1:18080/applications"},
		{"//attacker.example/path", "/"},
		{"https://attacker.example/path", "/"},
		{"http://user@127.0.0.1:18080/path", "/"},
	}
	for _, test := range tests {
		if got := service.safeReturnTo(test.input); got != test.want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
