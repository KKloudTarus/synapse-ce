package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// digestMembershipTarget is selected while the source event is published. Channel
// changes remain visible to closed-window materialization; rule identity is retained
// as history so a published digest stays readable after a rule is deleted.
type digestMembershipTarget struct {
	rule      notification.Rule
	channelID shared.ID
}

// maxDigestMembers bounds source snapshots and engagement locks per aggregate.
// Overflow continues in a separately durable chunk of the same UTC window, so
// every eligible member remains counted and eventually delivered.
const maxDigestMembers = notification.MaxDigestMembers

// recordDigestMemberships uses the same tenant scheduler lock as materialization. The
// publication-time window is computed after acquiring the lock, so an event that races a
// close is placed in the next open window rather than appended to an already-finalized one.
func (r *NotificationRepository) recordDigestMemberships(ctx context.Context, tx pgx.Tx, event notification.Event, targets []digestMembershipTarget) error {
	if len(targets) == 0 {
		return nil
	}
	// The scheduler lock serializes window finalization and membership admission.
	// It is acquired before channel locks everywhere on this path, and the window
	// is sampled only after waiting for it so a closed chunk is never reopened.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 78145))`, event.TenantID.String()); err != nil {
		return err
	}
	channelIDs := make([]string, 0, len(targets))
	for _, target := range targets {
		channelID := target.channelID.String()
		if !slices.Contains(channelIDs, channelID) {
			channelIDs = append(channelIDs, channelID)
		}
	}
	slices.Sort(channelIDs)
	rows, err := tx.Query(ctx, `SELECT id FROM notification_channels
		WHERE tenant_id=$1 AND id=ANY($2) AND enabled AND deleted_at IS NULL AND paused_at IS NULL
		ORDER BY id FOR SHARE`, event.TenantID, channelIDs)
	if err != nil {
		return fmt.Errorf("lock active notification digest channels: %w", err)
	}
	active := make(map[shared.ID]struct{}, len(channelIDs))
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		active[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	type batchTarget struct {
		RuleID      shared.ID                    `json:"rule_id"`
		ChannelID   shared.ID                    `json:"channel_id"`
		Cadence     notification.DeliveryCadence `json:"cadence"`
		WindowStart time.Time                    `json:"window_start"`
		WindowEnd   time.Time                    `json:"window_end"`
	}
	now := time.Now().UTC()
	batch := make([]batchTarget, 0, len(targets))
	for _, target := range targets {
		if _, ok := active[target.channelID]; !ok {
			continue
		}
		start, end := target.rule.Cadence.Window(now)
		batch = append(batch, batchTarget{RuleID: target.rule.ID, ChannelID: target.channelID, Cadence: target.rule.Cadence, WindowStart: start, WindowEnd: end})
	}
	if len(batch) == 0 {
		return nil
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("encode notification digest targets: %w", err)
	}
	// The lateral probes are bounded: each target reads one latest window and at
	// most maxDigestMembers rows of that chunk. Keeping window outcome in the
	// choice prevents an event accepted after a cancelled/suppressed chunk from
	// vanishing into finalized history.
	_, err = tx.Exec(ctx, `WITH targets AS (
		SELECT rule_id,channel_id,cadence,window_start,window_end
		FROM jsonb_to_recordset($2::jsonb)
		AS input(rule_id text,channel_id text,cadence text,window_start timestamptz,window_end timestamptz)
	), latest AS (
		SELECT t.*,COALESCE(last_window.chunk,0) AS latest_chunk,COALESCE(last_window.outcome,'pending') AS latest_outcome
		FROM targets t
		LEFT JOIN LATERAL (
			SELECT chunk,outcome FROM notification_digest_windows w
			WHERE w.tenant_id=$1 AND w.rule_id=t.rule_id AND w.channel_id=t.channel_id AND w.cadence=t.cadence AND w.window_start=t.window_start
			ORDER BY w.chunk DESC LIMIT 1
		) last_window ON true
	), assigned AS (
		SELECT l.*,CASE WHEN l.latest_outcome<>'pending' OR COALESCE(member_count.members,0)>=$4 THEN l.latest_chunk+1 ELSE l.latest_chunk END AS chunk
		FROM latest l
		LEFT JOIN LATERAL (
			SELECT count(*) AS members FROM notification_digest_members m
			WHERE m.tenant_id=$1 AND m.rule_id=l.rule_id AND m.channel_id=l.channel_id AND m.cadence=l.cadence
				AND m.window_start=l.window_start AND m.chunk=l.latest_chunk
		) member_count ON true
	), queued AS (
		INSERT INTO notification_digest_windows(tenant_id,rule_id,channel_id,cadence,window_start,window_end,chunk,outcome)
		SELECT $1,rule_id,channel_id,cadence,window_start,window_end,chunk,'pending' FROM assigned
		ON CONFLICT DO NOTHING
	)
	INSERT INTO notification_digest_members(tenant_id,rule_id,channel_id,cadence,window_start,window_end,chunk,event_id)
	SELECT $1,rule_id,channel_id,cadence,window_start,window_end,chunk,$3 FROM assigned
	ON CONFLICT DO NOTHING`, event.TenantID, raw, event.ID, maxDigestMembers)
	if err != nil {
		return fmt.Errorf("record notification digest memberships: %w", err)
	}
	return nil
}

type digestWindow struct {
	ruleID, channelID shared.ID
	cadence           notification.DeliveryCadence
	start, end        time.Time
	chunk             int
}

// materializeDigestsTx closes up to limit tenant-scoped digest windows. The caller
// already owns the tenant scheduler advisory lock, which also serializes membership
// admission. The durable window outcome makes a closed disabled/suppressed window final.
func (r *NotificationRepository) materializeDigestsTx(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `SELECT rule_id,channel_id,cadence,window_start,window_end,chunk
		FROM notification_digest_windows
		WHERE tenant_id=$1 AND outcome='pending' AND window_end<=$2
		ORDER BY window_end,window_start,rule_id,channel_id,chunk
		LIMIT $3`, tenant, now.UTC(), limit)
	if err != nil {
		return 0, err
	}
	var windows []digestWindow
	for rows.Next() {
		var cadence string
		var window digestWindow
		if err := rows.Scan(&window.ruleID, &window.channelID, &cadence, &window.start, &window.end, &window.chunk); err != nil {
			rows.Close()
			return 0, err
		}
		window.cadence = notification.DeliveryCadence(cadence)
		windows = append(windows, window)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	completed := 0
	for _, window := range windows {
		if err := r.materializeDigestWindowTx(ctx, tx, tenant, now.UTC(), window); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func (r *NotificationRepository) materializeDigestWindowTx(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time, window digestWindow) error {
	var channel notification.Channel
	channelErr := scanChannel(tx.QueryRow(ctx, channelSelect+` WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, window.channelID), &channel)
	if errors.Is(channelErr, pgx.ErrNoRows) {
		return nil // a physical channel removal cascades its queued windows.
	}
	if channelErr != nil {
		return channelErr
	}
	pending, err := lockPendingDigestWindow(ctx, tx, tenant, window)
	if err != nil {
		return err
	}
	if !pending {
		return nil
	}

	var ruleEnabled bool
	var cadence string
	err = tx.QueryRow(ctx, `SELECT enabled,cadence FROM notification_rules WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, window.ruleID).Scan(&ruleEnabled, &cadence)
	if errors.Is(err, pgx.ErrNoRows) {
		return r.finishDigestWindow(ctx, tx, tenant, window, "suppressed", "", now)
	}
	if err != nil {
		return err
	}
	if !ruleEnabled || notification.DeliveryCadence(cadence) != window.cadence || !channel.Enabled || channel.DeletedAt != nil || channel.Health.Paused() {
		return r.finishDigestWindow(ctx, tx, tenant, window, "suppressed", "", now)
	}

	items, err := loadDigestItems(ctx, tx, tenant, window)
	if err != nil {
		return err
	}
	context, safeCount, err := notification.BuildDigestContext(items, window.cadence, window.start, window.end, channel.Class())
	if err != nil {
		return fmt.Errorf("build notification digest context: %w", err)
	}
	if safeCount == 0 {
		return r.finishDigestWindow(ctx, tx, tenant, window, "empty", "", now)
	}
	encodedContext, err := context.Encode()
	if err != nil {
		return err
	}
	data, err := json.Marshal(notification.DigestData{Cadence: window.cadence, WindowStart: window.start, WindowEnd: window.end, EventIDs: digestEventIDs(items, channel.Class()), TotalCount: safeCount})
	if err != nil {
		return err
	}
	sourceID := digestSourceID(tenant, window)
	event := notification.Event{
		TenantID: tenant, ID: stableID("digest", tenant.String(), window.ruleID.String(), window.channelID.String(), string(window.cadence), window.start.UTC().Format(time.RFC3339Nano), strconv.Itoa(window.chunk)),
		Type: notification.EventDigest, SourceKind: "digest", SourceID: sourceID, Severity: notification.DigestSeverity(items), SchemaVersion: 1, OccurredAt: window.end,
		Data: data, Context: encodedContext,
	}
	if _, err := r.PublishToChannel(bindTenantTransaction(ctx, tenant, tx), event, window.channelID); err != nil {
		return err
	}
	return r.finishDigestWindow(ctx, tx, tenant, window, "published", event.ID, now)
}

// lockPendingDigestWindow follows the channel row lock held by materialization.
// A channel transition holds that row exclusively before suppressing pending
// windows, so this stops an already selected queue entry from being published
// after a disable, pause, or destination replacement.
func lockPendingDigestWindow(ctx context.Context, tx pgx.Tx, tenant shared.ID, window digestWindow) (bool, error) {
	var outcome string
	err := tx.QueryRow(ctx, `SELECT outcome FROM notification_digest_windows
		WHERE tenant_id=$1 AND rule_id=$2 AND channel_id=$3 AND cadence=$4 AND window_start=$5 AND chunk=$6 FOR UPDATE`,
		tenant, window.ruleID, window.channelID, window.cadence, window.start, window.chunk).Scan(&outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return outcome == "pending", nil
}

func loadDigestItems(ctx context.Context, tx pgx.Tx, tenant shared.ID, window digestWindow) ([]notification.DigestItem, error) {
	rows, err := tx.Query(ctx, `SELECT e.id,e.event_type,e.source_kind,e.source_id,e.engagement_id,e.severity,e.schema_version,e.occurred_at,e.data,e.subject_kind,e.subject_id,e.context,
		COALESCE(s.external_notifications,'inherit')
		FROM notification_digest_members m
		JOIN notification_events e ON e.tenant_id=m.tenant_id AND e.id=m.event_id
		LEFT JOIN notification_engagement_settings s ON s.tenant_id=e.tenant_id AND s.engagement_id=e.engagement_id
		WHERE m.tenant_id=$1 AND m.rule_id=$2 AND m.channel_id=$3 AND m.cadence=$4 AND m.window_start=$5 AND m.chunk=$6
		ORDER BY e.occurred_at,e.id`, tenant, window.ruleID, window.channelID, window.cadence, window.start, window.chunk)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []notification.DigestItem
	for rows.Next() {
		var event notification.Event
		var eventType, override string
		var data, eventContext []byte
		if err := rows.Scan(&event.ID, &eventType, &event.SourceKind, &event.SourceID, &event.EngagementID, &event.Severity, &event.SchemaVersion, &event.OccurredAt, &data, &event.SubjectKind, &event.SubjectID, &eventContext, &override); err != nil {
			return nil, err
		}
		event.TenantID, event.Type, event.Data, event.Context = tenant, notification.EventType(eventType), data, eventContext
		items = append(items, notification.DigestItem{Event: event, Override: notification.EngagementNotifications(override)})
	}
	return items, rows.Err()
}

func digestEventIDs(items []notification.DigestItem, class notification.DataClass) []shared.ID {
	ordered := slices.Clone(items)
	slices.SortFunc(ordered, func(left, right notification.DigestItem) int {
		if !left.Event.OccurredAt.Equal(right.Event.OccurredAt) {
			return left.Event.OccurredAt.Compare(right.Event.OccurredAt)
		}
		if left.Event.ID < right.Event.ID {
			return -1
		}
		if left.Event.ID > right.Event.ID {
			return 1
		}
		return 0
	})
	ids := make([]shared.ID, 0, min(len(ordered), notification.MaxDigestItems))
	for _, item := range ordered {
		_, deliver := notification.EffectiveDataClass(class, item.Override)
		if !deliver {
			continue
		}
		if len(ids) == notification.MaxDigestItems {
			break
		}
		ids = append(ids, item.Event.ID)
	}
	return ids
}

func currentDigestData(items []notification.DigestItem, cadence notification.DeliveryCadence, start, end time.Time, class notification.DataClass) ([]byte, int, error) {
	_, count, err := notification.BuildDigestContext(items, cadence, start, end, class)
	if err != nil {
		return nil, 0, err
	}
	encoded, err := json.Marshal(notification.DigestData{Cadence: cadence, WindowStart: start, WindowEnd: end, EventIDs: digestEventIDs(items, class), TotalCount: count})
	return encoded, count, err
}

func digestSourceID(tenant shared.ID, window digestWindow) string {
	return "digest:" + tenant.String() + ":" + window.ruleID.String() + ":" + window.channelID.String() + ":" + string(window.cadence) + ":" + window.start.UTC().Format(time.RFC3339Nano) + ":" + strconv.Itoa(window.chunk)
}

func (r *NotificationRepository) finishDigestWindow(ctx context.Context, tx pgx.Tx, tenant shared.ID, window digestWindow, outcome string, eventID shared.ID, at time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE notification_digest_windows SET outcome=$7,event_id=NULLIF($8,''),finalized_at=$9
		WHERE tenant_id=$1 AND rule_id=$2 AND channel_id=$3 AND cadence=$4 AND window_start=$5 AND chunk=$6 AND outcome='pending'`, tenant, window.ruleID, window.channelID, window.cadence, window.start, window.chunk, outcome, eventID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("notification digest window is not pending: %w", shared.ErrConflict)
	}
	return nil
}

// admitDigestPolicy rehydrates current member overrides while holding their shared
// engagement locks. BeginAttempt calls it after taking the channel row lock, so the
// lock order is channel then sorted engagements, matching setting writes.
func admitDigestPolicy(ctx context.Context, tx pgx.Tx, tenant, delivery shared.ID, class notification.DataClass, expected string) error {
	var data []byte
	var ruleID shared.ID
	var chunk int
	err := tx.QueryRow(ctx, `SELECT e.data,w.rule_id,w.chunk FROM notification_deliveries d
		JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id
		JOIN notification_digest_windows w ON w.tenant_id=e.tenant_id AND w.event_id=e.id
		WHERE d.tenant_id=$1 AND d.id=$2 AND e.event_type=$3 AND e.source_kind='digest'`, tenant, delivery, notification.EventDigest).Scan(&data, &ruleID, &chunk)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected == "" {
		return fmt.Errorf("%w: digest policy is required", shared.ErrValidation)
	}
	var digest notification.DigestData
	if err := json.Unmarshal(data, &digest); err != nil {
		return fmt.Errorf("decode notification digest: %w", err)
	}
	engagements, err := digestEngagementIDs(ctx, tx, tenant, ruleID, delivery, chunk, digest)
	if err != nil {
		return err
	}
	for _, engagement := range engagements {
		if err := lockEngagementSetting(ctx, tx, tenant, engagement, false); err != nil {
			return err
		}
	}
	window := digestWindow{ruleID: ruleID, channelID: "", cadence: digest.Cadence, start: digest.WindowStart, end: digest.WindowEnd, chunk: chunk}
	if err := tx.QueryRow(ctx, `SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2`, tenant, delivery).Scan(&window.channelID); err != nil {
		return err
	}
	items, err := loadDigestItems(ctx, tx, tenant, window)
	if err != nil {
		return err
	}
	if notification.DigestPolicy(items, class) != expected {
		return fmt.Errorf("%w: digest policy changed", ports.ErrRetryable)
	}
	_, count, err := notification.BuildDigestContext(items, digest.Cadence, digest.WindowStart, digest.WindowEnd, class)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("%w: digest suppressed", ports.ErrRetryable)
	}
	return nil
}

func digestEngagementIDs(ctx context.Context, tx pgx.Tx, tenant, ruleID, delivery shared.ID, chunk int, digest notification.DigestData) ([]shared.ID, error) {
	var channelID shared.ID
	if err := tx.QueryRow(ctx, `SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2`, tenant, delivery).Scan(&channelID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT e.engagement_id FROM notification_digest_members m
		JOIN notification_events e ON e.tenant_id=m.tenant_id AND e.id=m.event_id
		WHERE m.tenant_id=$1 AND m.rule_id=$2 AND m.channel_id=$3 AND m.cadence=$4 AND m.window_start=$5
		AND m.chunk=$6 AND e.engagement_id<>'' ORDER BY e.engagement_id`, tenant, ruleID, channelID, digest.Cadence, digest.WindowStart, chunk)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
