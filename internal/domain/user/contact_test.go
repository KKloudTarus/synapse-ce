package user

import "testing"

func TestNormalizeContactEmail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"A.B+tag@EXAMPLE.COM", "A.B+tag@example.com"},
		{"alice@bücher.example", "alice@xn--bcher-kva.example"},
		{"alice@example.com", "alice@example.com"},
	} {
		got, err := NormalizeContactEmail(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("NormalizeContactEmail(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, value := range []string{"", "alice@example.com\r\nBcc: bad@example.com", " alice@example.com", "alice@@example.com", "Alice <alice@example.com>", "alice@example.com, bob@example.com", "alice@example.com\x00"} {
		if _, err := NormalizeContactEmail(value); err == nil {
			t.Errorf("accepted invalid mailbox %q", value)
		}
	}
}
