package docpublish

import (
	"testing"
	"time"
)

func validSchedule() Schedule {
	return Schedule{ID: "schedule", TenantID: "tenant", Source: Source{SourceKind: EngagementReport, SourceRef: "engagement:eng", Scope: Engagement, ScopeID: "eng"}, Destination: ScheduleEmail, EmailChannelID: "channel", OwnerUserID: "user", OwnerMembershipID: "membership", OwnerPersonID: "person", Timezone: "Asia/Ho_Chi_Minh", Frequency: ScheduleWeekly, Weekday: int(time.Monday), Hour: 9, Version: 1, NextDueAt: time.Date(2026, 1, 5, 2, 0, 0, 0, time.UTC), CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func TestScheduleNextDueWeeklyAndMonthEnd(t *testing.T) {
	s := validSchedule()
	next, err := s.NextDueAfter(time.Date(2026, 1, 5, 2, 0, 0, 0, time.UTC))
	if err != nil || !next.Equal(time.Date(2026, 1, 12, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("next=%v err=%v", next, err)
	}
	s.Frequency, s.Weekday, s.Day, s.Timezone = ScheduleMonthly, 0, 31, "America/New_York"
	next, err = s.NextDueAfter(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || next.In(time.FixedZone("", 0)).IsZero() || next.In(mustLoc(t, "America/New_York")).Day() != 28 {
		t.Fatalf("month end next=%v err=%v", next, err)
	}
}
func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, e := time.LoadLocation(name)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func TestScheduleRejectsTwoDestinations(t *testing.T) {
	s := validSchedule()
	s.IntegrationID = "i"
	if s.Validate() == nil {
		t.Fatal("expected validation error")
	}
}

func TestScheduleDSTGapAndFoldAreDeterministic(t *testing.T) {
	s := validSchedule()
	s.Timezone, s.Hour, s.Minute, s.Weekday = "America/New_York", 2, 30, int(time.Sunday)
	gap, err := s.NextDueAfter(time.Date(2026, 3, 8, 0, 0, 0, 0, mustLoc(t, s.Timezone)))
	if err != nil {
		t.Fatal(err)
	}
	local := gap.In(mustLoc(t, s.Timezone))
	if local.Hour() != 3 || local.Minute() != 0 {
		t.Fatalf("gap resolved %v, want first valid 03:00", local)
	}
	next, err := s.NextDueAfter(gap)
	if err != nil || next.In(mustLoc(t, s.Timezone)).Hour() != 2 || next.In(mustLoc(t, s.Timezone)).Day() != 15 {
		t.Fatalf("next weekly wall time=%v err=%v", next, err)
	}
	s.Hour, s.Minute = 1, 30
	fold, err := s.NextDueAfter(time.Date(2026, 11, 1, 0, 0, 0, 0, mustLoc(t, s.Timezone)))
	if err != nil {
		t.Fatal(err)
	}
	_, off := fold.In(mustLoc(t, s.Timezone)).Zone()
	if off != -4*3600 {
		t.Fatalf("fold chose later occurrence: %v offset=%d", fold, off)
	}
}

func TestScheduleCivilDateSurvivesMidnightDSTGap(t *testing.T) {
	loc := mustLoc(t, "America/Santiago")
	for _, tc := range []struct {
		name      string
		frequency ScheduleFrequency
		hour      int
		minute    int
		wantHour  int
	}{
		{"weekly morning", ScheduleWeekly, 9, 0, 9},
		{"weekly missing minute", ScheduleWeekly, 0, 30, 1},
		{"monthly morning", ScheduleMonthly, 9, 0, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSchedule()
			s.Timezone, s.Frequency, s.Weekday, s.Hour, s.Minute = "America/Santiago", tc.frequency, int(time.Sunday), tc.hour, tc.minute
			if tc.frequency == ScheduleMonthly {
				s.Day = 6
			}
			next, err := s.NextDueAfter(time.Date(2026, 9, 5, 12, 0, 0, 0, loc))
			want := time.Date(2026, 9, 6, tc.wantHour, 0, 0, 0, loc)
			if err != nil || !next.Equal(want) {
				t.Fatalf("next=%v, want=%v, err=%v", next.In(loc), want, err)
			}
		})
	}
}

func TestScheduleOccurrenceLeaseMatchesState(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	o := ScheduleOccurrence{ID: "occurrence", TenantID: "tenant", ScheduleID: "schedule", DueAt: now, ScheduleVersion: 1, State: OccurrenceDone, Version: 1, LeaseUntil: &lease, CreatedAt: now, UpdatedAt: now}
	if err := o.Validate(); err == nil {
		t.Fatal("terminal occurrence retained lease")
	}
	o.State = OccurrenceInFlight
	o.LeaseUntil = nil
	if err := o.Validate(); err == nil {
		t.Fatal("in-flight occurrence lacks lease")
	}
	o.LeaseUntil = &lease
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
}
