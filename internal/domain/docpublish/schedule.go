package docpublish

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ScheduleFrequency deliberately supports the two report cadences needed by
// governed releases. It is not a general purpose cron expression.
type ScheduleFrequency string

const (
	ScheduleWeekly  ScheduleFrequency = "weekly"
	ScheduleMonthly ScheduleFrequency = "monthly"
)

func (f ScheduleFrequency) Valid() bool { return f == ScheduleWeekly || f == ScheduleMonthly }

type ScheduleDestination string

const (
	ScheduleConfluence ScheduleDestination = "confluence"
	ScheduleEmail      ScheduleDestination = "email"
)

func (d ScheduleDestination) Valid() bool { return d == ScheduleConfluence || d == ScheduleEmail }

type Schedule struct {
	ID                shared.ID
	TenantID          shared.ID
	Source            Source
	Destination       ScheduleDestination
	IntegrationID     shared.ID
	EmailChannelID    shared.ID
	OwnerUserID       shared.ID
	OwnerMembershipID shared.ID
	OwnerPersonID     shared.ID
	Timezone          string
	Frequency         ScheduleFrequency
	// Weekday is used for weekly schedules (Sunday is 0), Day is used for
	// monthly schedules and clamps to the month's final day.
	Weekday      int
	Day          int
	Hour         int
	Minute       int
	Enabled      bool
	Version      int
	NextDueAt    time.Time
	CheckedAt    *time.Time
	CheckVersion int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (s Schedule) Validate() error {
	if s.ID.IsZero() || s.TenantID.IsZero() || s.Source.Validate() != nil ||
		!s.Destination.Valid() || s.OwnerUserID.IsZero() || (s.OwnerMembershipID.IsZero() != s.OwnerPersonID.IsZero()) ||
		!s.Frequency.Valid() || s.Hour < 0 || s.Hour > 23 || s.Minute < 0 || s.Minute > 59 ||
		s.Version < 1 || s.CheckVersion < 0 || s.NextDueAt.IsZero() || s.CreatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return fmt.Errorf("%w: invalid document schedule", shared.ErrValidation)
	}
	if _, err := time.LoadLocation(s.Timezone); err != nil || strings.TrimSpace(s.Timezone) == "" || len(s.Timezone) > 128 {
		return fmt.Errorf("%w: invalid schedule timezone", shared.ErrValidation)
	}
	if s.Destination == ScheduleConfluence {
		if s.IntegrationID.IsZero() || !s.EmailChannelID.IsZero() {
			return fmt.Errorf("%w: invalid confluence schedule destination", shared.ErrValidation)
		}
	} else if s.EmailChannelID.IsZero() || !s.IntegrationID.IsZero() {
		return fmt.Errorf("%w: invalid email schedule destination", shared.ErrValidation)
	}
	if s.Frequency == ScheduleWeekly && (s.Weekday < int(time.Sunday) || s.Weekday > int(time.Saturday) || s.Day != 0) {
		return fmt.Errorf("%w: invalid weekly schedule", shared.ErrValidation)
	}
	if s.Frequency == ScheduleMonthly && (s.Day < 1 || s.Day > 31 || s.Weekday != 0) {
		return fmt.Errorf("%w: invalid monthly schedule", shared.ErrValidation)
	}
	return nil
}

// NextDueAfter derives a strictly future instant in the configured IANA zone.
// resolveLocal selects the earliest real instant at or after the requested wall
// minute: gaps move forward to their first valid minute and folds use the first
// occurrence. Persisting the UTC result makes the choice durable across restarts.
func (s Schedule) NextDueAfter(after time.Time) (time.Time, error) {
	if err := s.Validate(); err != nil {
		return time.Time{}, err
	}
	loc, _ := time.LoadLocation(s.Timezone)
	local := after.In(loc)
	if s.Frequency == ScheduleWeekly {
		delta := (s.Weekday - int(local.Weekday()) + 7) % 7
		for i := 0; i < 2; i++ {
			// Civil date arithmetic must not normalize through a missing local midnight.
			base := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, delta+7*i)
			y, m, d := base.Date()
			candidate, err := resolveScheduleLocal(loc, y, m, d, s.Hour, s.Minute)
			if err != nil {
				return time.Time{}, err
			}
			if candidate.After(after) {
				return candidate.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("%w: cannot calculate schedule due time", shared.ErrValidation)
	}
	for i := 0; i < 14; i++ {
		y, m := local.Year(), local.Month()+time.Month(i)
		for m > time.December {
			y++
			m -= 12
		}
		last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
		day := s.Day
		if day > last {
			day = last
		}
		candidate, err := resolveScheduleLocal(loc, y, m, day, s.Hour, s.Minute)
		if err != nil {
			return time.Time{}, err
		}
		if candidate.After(after) {
			return candidate.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: cannot calculate schedule due time", shared.ErrValidation)
}

func resolveScheduleLocal(loc *time.Location, year int, month time.Month, day, hour, minute int) (time.Time, error) {
	start := time.Date(year, month, day, 0, 0, 0, 0, loc).UTC()
	for instant := start; instant.Before(start.Add(30 * time.Hour)); instant = instant.Add(time.Minute) {
		local := instant.In(loc)
		if local.Year() == year && local.Month() == month && local.Day() == day && (local.Hour() > hour || (local.Hour() == hour && local.Minute() >= minute)) {
			return instant, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: invalid local schedule time", shared.ErrValidation)
}

type ScheduleOccurrenceState string

const (
	OccurrencePending   ScheduleOccurrenceState = "pending"
	OccurrenceInFlight  ScheduleOccurrenceState = "in_flight"
	OccurrenceDone      ScheduleOccurrenceState = "done"
	OccurrenceUncertain ScheduleOccurrenceState = "uncertain"
	OccurrenceFailed    ScheduleOccurrenceState = "failed"
)

func (s ScheduleOccurrenceState) Valid() bool {
	switch s {
	case OccurrencePending, OccurrenceInFlight, OccurrenceDone, OccurrenceUncertain, OccurrenceFailed:
		return true
	}
	return false
}

type ScheduleOccurrence struct {
	ID               shared.ID
	TenantID         shared.ID
	ScheduleID       shared.ID
	DueAt            time.Time
	ScheduleVersion  int
	State            ScheduleOccurrenceState
	Version          int
	LeaseUntil       *time.Time
	ArtifactDigest   string
	DocumentIntentID shared.ID
	RemotePageID     string
	RemoteVersion    int
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (o ScheduleOccurrence) Validate() error {
	if o.ID.IsZero() || o.TenantID.IsZero() || o.ScheduleID.IsZero() || o.DueAt.IsZero() || o.ScheduleVersion < 1 || !o.State.Valid() || o.Version < 1 || o.CreatedAt.IsZero() || o.UpdatedAt.Before(o.CreatedAt) || (o.State == OccurrenceInFlight) != (o.LeaseUntil != nil) {
		return fmt.Errorf("%w: invalid schedule occurrence", shared.ErrValidation)
	}
	return nil
}
