package repository

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"orbguard-lab/internal/domain/models"
)

// Platform conversion helpers

func platformsToStrings(platforms []models.Platform) []string {
	result := make([]string, len(platforms))
	for i, p := range platforms {
		result[i] = p.String()
	}
	return result
}

func stringsToPlatforms(strs []string) []models.Platform {
	result := make([]models.Platform, len(strs))
	for i, s := range strs {
		result[i] = models.ParsePlatform(s)
	}
	return result
}

// Numeric conversion helpers

func floatToNumeric(f float64) pgtype.Numeric {
	var n pgtype.Numeric
	n.Scan(fmt.Sprintf("%.2f", f))
	return n
}

func numericToFloat(n pgtype.Numeric) float64 {
	if !n.Valid {
		return 0
	}
	f, _ := n.Float64Value()
	return f.Float64
}

// Float8 conversion helpers (for DOUBLE PRECISION columns)

func floatToFloat8(f float64) pgtype.Float8 {
	return pgtype.Float8{Float64: f, Valid: true}
}

func float8ToFloat(f pgtype.Float8) float64 {
	if !f.Valid {
		return 0
	}
	return f.Float64
}

// Text conversion helpers

func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func nullTextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// Timestamp conversion helpers

func timeToTimestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func timeToTimestamptzPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil || t.IsZero() {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func timestamptzToTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

func timestamptzToTimePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// UUID conversion helpers

func uuidToNullUUID(id *uuid.UUID) pgtype.UUID {
	if id == nil || *id == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

func nullUUIDToPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// Interval conversion helpers

func intervalToDuration(i pgtype.Interval) time.Duration {
	if !i.Valid {
		return 0
	}
	// PostgreSQL interval stores microseconds
	return time.Duration(i.Microseconds) * time.Microsecond
}

func durationToInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{
		Microseconds: d.Microseconds(),
		Valid:        true,
	}
}
