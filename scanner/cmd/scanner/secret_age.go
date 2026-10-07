package main

import (
	"encoding/json"
	"time"

	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/sweep"
)

func secretAgeMetric(records []sweep.Record, now time.Time, maxAgeDays int, name string) ([]byte, error) {
	attention := 0
	for _, record := range records {
		if record.Kind != "secretsmanager" {
			continue
		}
		date := record.CurrentVersionCreatedAt
		// An empty secret, missing version metadata, or a future timestamp must
		// not be counted as healthy. Demo age tags cannot affect this metric.
		if date == nil || date.IsZero() || date.After(now) || now.Sub(*date) > time.Duration(maxAgeDays)*24*time.Hour {
			attention++
		}
	}
	return json.Marshal(map[string]any{
		"_aws": map[string]any{
			"Timestamp": now.UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "SecOps/Secrets",
				"Dimensions": [][]string{{"Scanner"}},
				"Metrics": []any{
					map[string]string{"Name": "SecretsNeedingAttention", "Unit": "Count"},
					map[string]string{"Name": "ScanCompleted", "Unit": "Count"},
				},
			}},
		},
		"Scanner":                 name,
		"SecretsNeedingAttention": attention,
		"ScanCompleted":           1,
	})
}
