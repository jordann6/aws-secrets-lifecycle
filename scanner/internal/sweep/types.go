package sweep

import "time"

// Record is the normalized shape written to DynamoDB for every
// secret-bearing resource, regardless of source service.
type Record struct {
	PK               string            `dynamodbav:"pk" json:"pk"`
	SK               string            `dynamodbav:"sk" json:"sk"`
	ScanID           string            `dynamodbav:"scan_id" json:"scan_id"`
	ARN              string            `dynamodbav:"arn" json:"arn"`
	Name             string            `dynamodbav:"name" json:"name"`
	Kind             string            `dynamodbav:"kind" json:"kind"` // secretsmanager | ssm_securestring | iam_access_key
	AccountID        string            `dynamodbav:"account_id" json:"account_id"`
	Region           string            `dynamodbav:"region" json:"region"`
	CreatedAt        time.Time         `dynamodbav:"created_at" json:"created_at"`
	LastRotatedAt    *time.Time        `dynamodbav:"last_rotated_at,omitempty" json:"last_rotated_at,omitempty"`
	LastAccessedAt   *time.Time        `dynamodbav:"last_accessed_at,omitempty" json:"last_accessed_at,omitempty"`
	RotationEnabled  bool              `dynamodbav:"rotation_enabled" json:"rotation_enabled"`
	RotationDays     int64             `dynamodbav:"rotation_days" json:"rotation_days"`
	ResourcePolicy   string            `dynamodbav:"resource_policy,omitempty" json:"resource_policy,omitempty"`
	Tags             map[string]string `dynamodbav:"tags,omitempty" json:"tags,omitempty"`
	AgeDays          int64             `dynamodbav:"age_days" json:"age_days"`
	AgeSimulated     bool              `dynamodbav:"age_simulated" json:"age_simulated"`
	ScannedAt        time.Time         `dynamodbav:"scanned_at" json:"scanned_at"`
}

const simulatedAgeTag = "secops:simulated-age-days"
