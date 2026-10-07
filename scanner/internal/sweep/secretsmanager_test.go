package sweep

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type versionMetadata struct {
	calls int
	fail  bool
	date  time.Time
}

func (v *versionMetadata) ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{}, nil
}
func (v *versionMetadata) GetResourcePolicy(context.Context, *secretsmanager.GetResourcePolicyInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	return &secretsmanager.GetResourcePolicyOutput{}, nil
}
func (v *versionMetadata) ListSecretVersionIds(_ context.Context, in *secretsmanager.ListSecretVersionIdsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretVersionIdsOutput, error) {
	v.calls++
	if v.fail {
		return nil, errors.New("AccessDenied")
	}
	if in.NextToken == nil {
		return &secretsmanager.ListSecretVersionIdsOutput{
			Versions:  []types.SecretVersionsListEntry{{VersionStages: []string{"AWSPREVIOUS"}}},
			NextToken: aws.String("second"),
		}, nil
	}
	return &secretsmanager.ListSecretVersionIdsOutput{
		Versions: []types.SecretVersionsListEntry{{VersionStages: []string{"AWSCURRENT"}, CreatedDate: &v.date}},
	}, nil
}

func TestCurrentVersionDatePaginates(t *testing.T) {
	v := &versionMetadata{date: time.Now()}
	date, err := currentVersionDate(context.Background(), v, aws.String("test-secret"))
	if err != nil || date == nil || !date.Equal(v.date) || v.calls != 2 {
		t.Fatalf("current version metadata was not read correctly: %v %v", date, err)
	}
}

func TestCurrentVersionDateDoesNotHideFailure(t *testing.T) {
	_, err := currentVersionDate(context.Background(), &versionMetadata{fail: true}, aws.String("test-secret"))
	if err == nil {
		t.Fatal("metadata denial must fail the scan")
	}
}

func TestRenewedSecretHasCredentialAge(t *testing.T) {
	now := time.Now()
	current := now.AddDate(0, 0, -1)
	r := Record{CreatedAt: now.AddDate(0, 0, -400), CurrentVersionCreatedAt: &current}
	FinishRecord(&r, "test", now)
	if r.AgeDays != 1 {
		t.Fatalf("renewed secret age is %d", r.AgeDays)
	}
}
