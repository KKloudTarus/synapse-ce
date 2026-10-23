# report.generated evidence (#1410)

`payloads/` holds exactly what each destination receives for one `report.generated` event, in
English and Vietnamese, produced by the shipped template for the channel's family and the channel's
own formatter. `go test ./test/notifylive` regenerates them with `-update-captures` and fails when
they drift, so they stay the bytes the code actually sends.

| File | What it is |
| --- | --- |
| `webhook-<locale>.json` | The receiver's parsed body: the versioned envelope with the class-filtered context. This is one of the artifacts the issue asks for, and the only one that needs no third-party workspace. |
| `slack`, `teams`, `discord`, `google-chat`, `telegram`, `pagerduty` | The wire payload each client renders. |
| `email-<locale>.json` | The subject, the plain-text body and the HTML alternative. |

The timestamps are pinned to `2026-10-23T09:00:00Z` so a capture changes only when the content
does; a live run stamps the real time.

## What these are not

They are payloads, not screenshots. They prove what Synapse sends, not how a client draws it. The
rendered-message captures the issue requires still come from the clients themselves:
`go test ./test/notifylive -run TestNotificationLiveClients` posts the same message into configured
workspaces and logs the file name for each capture.

## Open observation

`email-vi.json` opens with `🟠 Severity: high` before the Vietnamese body. The email formatter
composes that line in English at `internal/infrastructure/messageformat/email.go:159` and receives
no locale, so every non-English email carries it. It predates this event and affects all of them;
fixing it means threading the locale into the formatters.
