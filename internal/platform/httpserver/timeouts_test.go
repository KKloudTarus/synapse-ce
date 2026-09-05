package httpserver

import (
	"testing"
	"time"
)

// TestTimeoutsWithDefaults pins the connection ceilings. ReadHeaderTimeout is the
// slowloris guard; WriteTimeout reaps a stuck request or response; IdleTimeout reaps an
// idle keep-alive connection. Zero means "take the default", never "no limit".
func TestTimeoutsWithDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   Timeouts
		want Timeouts
	}{
		{
			name: "zero value takes every default",
			in:   Timeouts{},
			want: Timeouts{ReadHeader: defaultReadHeaderTimeout, Write: defaultWriteTimeout, Idle: defaultIdleTimeout},
		},
		{
			name: "negative values take the defaults",
			in:   Timeouts{ReadHeader: -1, Write: -1, Idle: -1},
			want: Timeouts{ReadHeader: defaultReadHeaderTimeout, Write: defaultWriteTimeout, Idle: defaultIdleTimeout},
		},
		{
			name: "explicit values win",
			in:   Timeouts{ReadHeader: time.Second, Write: 2 * time.Second, Idle: 3 * time.Second},
			want: Timeouts{ReadHeader: time.Second, Write: 2 * time.Second, Idle: 3 * time.Second},
		},
		{
			name: "a single override keeps the other defaults",
			in:   Timeouts{Write: 30 * time.Minute},
			want: Timeouts{ReadHeader: defaultReadHeaderTimeout, Write: 30 * time.Minute, Idle: defaultIdleTimeout},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.withDefaults(); got != tc.want {
				t.Errorf("withDefaults() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestDefaultWriteTimeoutFitsALargeUpload guards the one interaction that makes a write
// timeout dangerous here: in Go the write deadline also covers reading the request body,
// so the default has to leave room for the largest body the API accepts on a slow link.
func TestDefaultWriteTimeoutFitsALargeUpload(t *testing.T) {
	const largestBodyBytes = 600 << 20 // the source-archive transport ceiling
	const slowLinkBytesPerSecond = 2 << 20
	need := time.Duration(largestBodyBytes/slowLinkBytesPerSecond) * time.Second
	if defaultWriteTimeout < need {
		t.Errorf("defaultWriteTimeout = %s, want at least %s so a %d MiB upload at %d MiB/s survives",
			defaultWriteTimeout, need, largestBodyBytes>>20, slowLinkBytesPerSecond>>20)
	}
}
