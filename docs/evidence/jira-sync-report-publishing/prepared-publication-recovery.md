# Prepared publication recovery

A provider can refuse a write after a neutral page has been created. An operator
can repair its destination permissions without creating another page or changing
the frozen report. The original reviewer may then resume the existing command.

The recovery endpoint accepts only a failed Create command with a definite
`provider_refused` result at the restrictions or pre-upload attachments checkpoint.
It requires zero uploads and receipts, no outstanding operation, and the observed
intent version. It freshly verifies the exact neutral page identity, container,
version and marker, restricted sharing, current source policy, human authority and
frozen destination revisions. A second guard runs after provider reads.

Recovery performs no remote content write. It audits this admission using the
intent and expected version, then uses the existing intent CAS to queue one more
attempt. Attempts, checkpoint, artifact and target identity remain unchanged. Each
execution still verifies sharing immediately before uploading content.

The audit payload uses the failed command's persisted update timestamp, identifying
that checkpoint rather than the wall-clock resume request. This makes retry after
an audit commit and failed intent CAS reproduce the same append-only audit entry.

An ambiguous upload retains its outstanding operation and remains Uncertain;
recovery cannot resend it. A command with any receipt, content-bearing checkpoint,
remote drift or changed authority is ineligible. A neutral page alone cannot prove
that a previous attachment write did not occur; definite refusal and the durable
operation ledger are required together.

Validation covers pre-upload refusal, ambiguous acknowledgement, receipt and
checkpoint rejection, actor/configuration/source drift, sharing failure, version
conflicts, separate recovery episodes, and polling the same intent after resume.
