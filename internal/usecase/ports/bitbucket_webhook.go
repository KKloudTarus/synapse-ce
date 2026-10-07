package ports

import "context"

// BitbucketWebhookDeduper commits delivery/body replay receipts and durable
// scan writes in one tenant transaction. The callback must use its bound context.
type BitbucketWebhookDeduper interface {
	AcceptBitbucketWebhook(context.Context, InboundWebhookIdentity, string, string, func(context.Context) error) (bool, error)
}

// BitbucketScanTarget contains authenticated metadata only. Acquisition always
// resolves its repository and credentials from the persisted Project.
type BitbucketScanTarget struct {
	Ref, SHA, BaseRef string
	PullRequest, Fork bool
	// ResolvedRepository is a server-owned source snapshot for commit expansion.
	ResolvedRepository string
}

type BitbucketCommitResolver interface {
	ResolveBitbucketCommit(context.Context, string, string, bool) (string, error)
}
