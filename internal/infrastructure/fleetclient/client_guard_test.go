package fleetclient

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetca"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/outboundguard"
)

// TestClientIsGuarded pins #1698: the control plane is the agent operator's configuration and is
// often on an internal network or, in development, loopback, but the client goes through safehttp
// and so never follows a redirect or reaches a metadata endpoint.
func TestClientIsGuarded(t *testing.T) {
	outboundguard.Require(t, New("https://control.example.internal", 0).http, outboundguard.Operator)
	outboundguard.Require(t, NewWithEnrollmentURL("https://control.example.internal", "https://enrol.example.internal", 0).http, outboundguard.Operator)
}

// TestActivatedClientStaysGuarded pins that installing the enrolled certificate keeps the guard:
// ActivateCredential replaces the transport with a clone, and the clone must keep safehttp's dialer
// and the client its redirect policy.
func TestActivatedClientStaysGuarded(t *testing.T) {
	now := time.Now().UTC()
	caCertPEM, caKeyPEM, err := fleetca.GenerateCA("fleet-test-ca", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := fleetca.New(caCertPEM, caKeyPEM, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, keyPEM, err := GenerateKeyAndCSR("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.Issue(csrPEM, "agent-1", "tenant-1", now)
	if err != nil {
		t.Fatal(err)
	}
	client := New("https://control.example.internal", 0)
	if err := client.ActivateCredential(Credential{CertificatePEM: string(certPEM)}, keyPEM); err != nil {
		t.Fatalf("activate mTLS credential: %v", err)
	}
	if !client.clientCertificate {
		t.Fatal("client certificate was not installed")
	}
	outboundguard.Require(t, client.http, outboundguard.Operator)
}
