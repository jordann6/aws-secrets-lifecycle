package sweep

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetResourcePolicy(ctx context.Context, in *secretsmanager.GetResourcePolicyInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
	ListSecretVersionIds(ctx context.Context, in *secretsmanager.ListSecretVersionIdsInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretVersionIdsOutput, error)
}

func currentVersionDate(ctx context.Context, api SecretsAPI, arn *string) (*time.Time, error) {
	var next *string
	for {
		out, err := api.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId: arn, NextToken: next, MaxResults: aws.Int32(100),
		})
		if err != nil {
			return nil, fmt.Errorf("list current secret version metadata: %w", err)
		}
		for _, version := range out.Versions {
			if slices.Contains(version.VersionStages, "AWSCURRENT") {
				return version.CreatedDate, nil
			}
		}
		if out.NextToken == nil {
			return nil, nil
		}
		next = out.NextToken
	}
}

// SweepSecrets lists Secrets Manager secrets and normalizes their
// metadata. Secret values are never requested; the scanner role also
// carries an explicit deny on GetSecretValue.
func SweepSecrets(ctx context.Context, api SecretsAPI, accountID, region, scanID string, now time.Time) ([]Record, error) {
	var records []Record
	var next *string
	for {
		out, err := api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(100),
			NextToken:  next,
		})
		if err != nil {
			return nil, err
		}
		for _, s := range out.SecretList {
			currentDate, err := currentVersionDate(ctx, api, s.ARN)
			if err != nil {
				return nil, err
			}
			r := Record{
				ARN:                     aws.ToString(s.ARN),
				Name:                    aws.ToString(s.Name),
				Kind:                    "secretsmanager",
				AccountID:               accountID,
				Region:                  region,
				Tags:                    map[string]string{},
				CurrentVersionCreatedAt: currentDate,
			}
			if s.CreatedDate != nil {
				r.CreatedAt = *s.CreatedDate
			}
			r.LastRotatedAt = s.LastRotatedDate
			r.LastAccessedAt = s.LastAccessedDate
			r.RotationEnabled = aws.ToBool(s.RotationEnabled)
			if s.RotationRules != nil && s.RotationRules.AutomaticallyAfterDays != nil {
				r.RotationDays = *s.RotationRules.AutomaticallyAfterDays
			}
			for _, t := range s.Tags {
				r.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			if pol, err := api.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: s.ARN}); err == nil {
				r.ResourcePolicy = aws.ToString(pol.ResourcePolicy)
			}
			FinishRecord(&r, scanID, now)
			records = append(records, r)
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	return records, nil
}
