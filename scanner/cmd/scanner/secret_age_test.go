package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/sweep"
)

func TestSecretAgeMetric(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	recent := now.AddDate(0, 0, -1)
	boundary := now.AddDate(0, 0, -90)
	stale := boundary.Add(-time.Second)
	future := now.Add(time.Hour)
	records := []sweep.Record{
		{Kind: "secretsmanager", CurrentVersionCreatedAt: &recent, CreatedAt: now.AddDate(-2, 0, 0)},
		{Kind: "secretsmanager", CurrentVersionCreatedAt: &boundary},
		{Kind: "secretsmanager", CurrentVersionCreatedAt: &stale, RotationEnabled: true},
		{Kind: "secretsmanager", CurrentVersionCreatedAt: &future},
		{Kind: "secretsmanager"},
		{Kind: "iam_access_key", AgeDays: 1000},
	}
	data, err := secretAgeMetric(records, now, 90, "secops-scanner")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["SecretsNeedingAttention"] != float64(3) || out["ScanCompleted"] != float64(1) {
		t.Fatalf("unexpected metric counts: %s", data)
	}
	if out["Scanner"] != "secops-scanner" {
		t.Fatal("incorrect metric dimension")
	}
	metadata := out["_aws"].(map[string]any)
	if metadata["Timestamp"] != float64(now.UnixMilli()) {
		t.Fatal("incorrect EMF timestamp")
	}
}

func TestEmptyScanEmitsHealthyCompletion(t *testing.T) {
	data, err := secretAgeMetric(nil, time.Now(), 90, "secops-scanner")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["SecretsNeedingAttention"] != float64(0) || out["ScanCompleted"] != float64(1) {
		t.Fatalf("unexpected empty scan: %s", data)
	}
}
