// Package selfhosted holds the operator's rules for reaching self-hosted provider endpoints, such
// as a Jenkins controller or a Jira Data Center instance, that a tenant administrator configures.
//
// A tenant chooses the endpoint URL, so without these rules anyone who can save an integration
// could point the control plane at an arbitrary host. The operator narrows that with:
//
//   - a host allowlist (SYNAPSE_INTEGRATION_HOST_ALLOWLIST): when set, only listed hosts can be
//     saved or dialed;
//   - the private-network switch (SYNAPSE_INTEGRATION_ALLOW_PRIVATE_NETWORK), and optionally the
//     private-use CIDRs it is limited to (SYNAPSE_INTEGRATION_PRIVATE_CIDRS).
//
// The rules are checked twice: when an integration is saved, so a tenant gets an immediate error,
// and when its adapter is built, so an integration saved under looser rules cannot keep dialing
// after the operator tightens them. The dial-time address check itself lives in
// internal/infrastructure/safehttp; this package only decides what that check admits.
package selfhosted
