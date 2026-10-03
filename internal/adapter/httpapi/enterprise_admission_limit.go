package httpapi

import (
	"golang.org/x/time/rate"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type admissionClient struct {
	limiter *rate.Limiter
	expires time.Time
}
type enterpriseAdmissionLimit struct {
	mu      sync.Mutex
	global  *rate.Limiter
	clients map[string]admissionClient
}

func newEnterpriseAdmissionLimit() *enterpriseAdmissionLimit {
	return &enterpriseAdmissionLimit{global: rate.NewLimiter(1, 32), clients: make(map[string]admissionClient)}
}
func (l *enterpriseAdmissionLimit) allow(address string, at time.Time) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if net.ParseIP(host) == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.global.AllowN(at, 1) {
		return false
	}
	client, ok := l.clients[host]
	if !ok || !at.Before(client.expires) {
		for ip, entry := range l.clients {
			if !at.Before(entry.expires) {
				delete(l.clients, ip)
			}
		}
		if len(l.clients) >= 512 {
			return false
		}
		client = admissionClient{limiter: rate.NewLimiter(rate.Every(10*time.Second), 8), expires: at.Add(10 * time.Minute)}
	}
	l.clients[host] = client
	return client.limiter.AllowN(at, 1)
}
func (rt *Router) enterpriseAdmissionAllowed(w http.ResponseWriter, r *http.Request) bool {
	enterprisePrivate(w)
	if !rt.enterprise.limit.allow(r.RemoteAddr, rt.enterprise.clock.Now()) {
		w.Header().Set("Retry-After", "10")
		writeJSON(w, http.StatusTooManyRequests, errorBody{Error: "authentication rate limit reached; retry shortly"})
		return false
	}
	if r.Method == http.MethodPost {
		base, err := url.Parse(rt.enterprise.frontend)
		origin := r.Header.Get("Origin")
		if err != nil || r.Header.Get("Sec-Fetch-Site") == "cross-site" || origin != "" && origin != base.Scheme+"://"+base.Host {
			writeJSON(w, http.StatusForbidden, errorBody{Error: "authentication request origin is not allowed"})
			return false
		}
	}
	return true
}
