package sweep

import (
	"testing"
	"time"
)

func TestFinishRecordRealAge(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	r := Record{
		ARN:       "arn:aws:secretsmanager:us-east-1:1:secret:x",
		CreatedAt: now.AddDate(0, 0, -90),
		Tags:      map[string]string{},
	}
	FinishRecord(&r, "scan1", now)
	if r.AgeDays != 90 {
		t.Fatalf("expected age 90, got %d", r.AgeDays)
	}
	if r.AgeSimulated {
		t.Fatal("age should not be simulated")
	}
	if r.PK != r.ARN || r.SK != "INVENTORY#scan1" {
		t.Fatalf("bad keys: %s %s", r.PK, r.SK)
	}
}

func TestFinishRecordSimulatedAgeOverride(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	r := Record{
		ARN:       "arn:aws:secretsmanager:us-east-1:1:secret:y",
		CreatedAt: now.AddDate(0, 0, -1),
		Tags:      map[string]string{simulatedAgeTag: "400"},
	}
	FinishRecord(&r, "scan1", now)
	if r.AgeDays != 400 {
		t.Fatalf("expected simulated age 400, got %d", r.AgeDays)
	}
	if !r.AgeSimulated {
		t.Fatal("expected age_simulated true")
	}
	if got := int(now.Sub(r.CreatedAt).Hours() / 24); got != 400 {
		t.Fatalf("created_at not backdated: %d", got)
	}
}

func TestFinishRecordBadSimulatedTagIgnored(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	r := Record{
		CreatedAt: now.AddDate(0, 0, -10),
		Tags:      map[string]string{simulatedAgeTag: "not-a-number"},
	}
	FinishRecord(&r, "scan1", now)
	if r.AgeDays != 10 || r.AgeSimulated {
		t.Fatalf("bad tag should fall back to real age: %d %v", r.AgeDays, r.AgeSimulated)
	}
}
