package httpapi

import (
	"net/http"
	"time"
)

// releaseWriteDeadline lifts the listener's write timeout for a long-lived response.
//
// http.Server.WriteTimeout is set once, when the response begins, and it is a deadline rather
// than an idle timer: a server-sent-event stream that outlives it has its connection closed
// mid-stream, whatever it is still sending. The listener default is sized to reap a stuck
// ordinary request, which is much shorter than the ceilings the stream handlers set for
// themselves, so a stream must opt out explicitly.
//
// The stream stays bounded: each handler wraps its own context in a timeout, and the request
// context still ends when the client disconnects. Returns false when the ResponseWriter does
// not support deadlines, which is the case for some test recorders and for HTTP/2 pushes;
// the caller carries on either way, so a stream is never refused over it.
func releaseWriteDeadline(w http.ResponseWriter) bool {
	return http.NewResponseController(w).SetWriteDeadline(time.Time{}) == nil
}
