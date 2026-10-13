package notificationsender

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

const (
	// #nosec G101 -- fixed OAuth token endpoint, not credential material.
	googleSMTPTokenURL = "https://oauth2.googleapis.com/token"
	microsoftSMTPHost  = "https://login.microsoftonline.com/"
)

type smtpOAuthToken struct {
	value   string
	expires time.Time
}

type smtpOAuthFlight struct {
	done  chan struct{}
	token string
	err   error
}

const (
	smtpOAuthCacheLimit  = 128
	smtpOAuthCacheMargin = 30 * time.Second
	smtpOAuthMaxTTL      = 24 * time.Hour
)

// smtpOAuthToken obtains only the two pinned provider grants. Its cache key is
// supplied by the notification usecase as tenant plus email-settings revision,
// so a relay update never reuses an older tenant's token.
func (s *Sender) smtpOAuthToken(ctx context.Context, relay SMTPConfig) (string, error) {
	key := relay.OAuthCacheKey + ":" + relay.OAuthProvider
	if relay.OAuthCacheKey == "" || relay.OAuthClientID == "" || relay.OAuthClientSecret == "" {
		return "", errors.New("invalid OAuth relay")
	}
	endpoint, values, err := oauthSMTPRequest(relay)
	if err != nil {
		return "", err
	}
	s.oauthMu.Lock()
	if cached, ok := s.oauthTokens[key]; ok && smtpOAuthTokenUsable(cached, s.now()) {
		s.oauthMu.Unlock()
		return cached.value, nil
	}
	if flight, ok := s.oauthFlights[key]; ok {
		s.oauthMu.Unlock()
		select {
		case <-flight.done:
			return flight.token, flight.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if len(s.oauthFlights) >= smtpOAuthCacheLimit {
		s.oauthMu.Unlock()
		return "", errors.New("OAuth token refresh capacity reached")
	}
	flight := &smtpOAuthFlight{done: make(chan struct{})}
	s.oauthFlights[key] = flight
	s.oauthMu.Unlock()

	token, expires, err := s.refreshSMTPToken(ctx, endpoint, values)
	s.oauthMu.Lock()
	delete(s.oauthFlights, key)
	flight.token, flight.err = token, err
	if err == nil && smtpOAuthTokenUsable(smtpOAuthToken{value: token, expires: expires}, s.now()) {
		if len(s.oauthTokens) >= smtpOAuthCacheLimit {
			for old := range s.oauthTokens {
				delete(s.oauthTokens, old)
				break
			}
		}
		s.oauthTokens[key] = smtpOAuthToken{value: token, expires: expires}
	}
	close(flight.done)
	s.oauthMu.Unlock()
	return token, err
}

func smtpOAuthTokenUsable(token smtpOAuthToken, now time.Time) bool {
	return now.Add(smtpOAuthCacheMargin).Before(token.expires)
}

func (s *Sender) refreshSMTPToken(ctx context.Context, endpoint string, values url.Values) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", time.Time{}, errors.New("OAuth token endpoint rejected grant")
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&body) != nil || body.AccessToken == "" {
		return "", time.Time{}, errors.New("invalid OAuth token response")
	}
	if body.ExpiresIn <= 0 {
		return "", time.Time{}, errors.New("invalid OAuth token expiry")
	}
	ttl := smtpOAuthMaxTTL
	if body.ExpiresIn <= int64(smtpOAuthMaxTTL/time.Second) {
		ttl = time.Duration(body.ExpiresIn) * time.Second
	}
	return body.AccessToken, s.now().Add(ttl), nil
}

func oauthSMTPRequest(relay SMTPConfig) (string, url.Values, error) {
	values := url.Values{"client_id": {relay.OAuthClientID}, "client_secret": {relay.OAuthClientSecret}}
	switch relay.OAuthProvider {
	case "google":
		if relay.Host != "smtp.gmail.com" || relay.OAuthRefreshToken == "" {
			return "", nil, errors.New("invalid Google OAuth relay")
		}
		values.Set("grant_type", "refresh_token")
		values.Set("refresh_token", relay.OAuthRefreshToken)
		return googleSMTPTokenURL, values, nil
	case "microsoft":
		if relay.Host != "smtp.office365.com" || !validDirectoryID(relay.OAuthDirectoryID) {
			return "", nil, errors.New("invalid Microsoft OAuth relay")
		}
		values.Set("grant_type", "client_credentials")
		values.Set("scope", "https://outlook.office365.com/.default")
		return microsoftSMTPHost + strings.ToLower(relay.OAuthDirectoryID) + "/oauth2/v2.0/token", values, nil
	default:
		return "", nil, errors.New("unsupported SMTP OAuth provider")
	}
}

func validDirectoryID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

type xoauth2Auth struct{ username, token string }

func (a xoauth2Auth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "XOAUTH2", []byte("user=" + a.username + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}
func (a xoauth2Auth) Next(challenge []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("XOAUTH2 rejected")
	}
	return nil, nil
}
