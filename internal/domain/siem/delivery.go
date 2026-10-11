package siem

import "time"

// Delivery is one bounded provider call. The secret is in memory only for
// the call and must not be copied into an error or a log.
type Delivery struct {
	Origin  string
	Secret  string
	Target  string
	Channel string
	AckMode AckMode
	Records []DeliveryRecord
}

// DeliveryRecord is one already-redacted body.
type DeliveryRecord struct {
	ID   string
	Body []byte
}

// DeliveryItem is the provider's result for the record in the same position.
type DeliveryItem struct {
	Disposition ItemDisposition
	Retryable   bool
	Blocked     bool
	RetryAfter  time.Duration
	Diagnostic  string
}

// DeliveryResult must contain one item per submitted record, in order.
// A short or long result is a malformed response and must not advance.
type DeliveryResult struct {
	Items []DeliveryItem
	// IndexerAckID means HEC accepted the POST but indexing is not yet
	// confirmed. The caller must persist it before polling; zero is valid.
	IndexerAckID *int64
}
