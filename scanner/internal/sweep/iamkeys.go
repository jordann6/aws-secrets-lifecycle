package sweep

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type IAMAPI interface {
	ListUsers(ctx context.Context, in *iam.ListUsersInput, opts ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, opts ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
}

// SweepAccessKeys treats long-lived IAM access keys as unmanaged
// secrets: creation date is the key age, and access keys have no
// rotation configuration by definition.
func SweepAccessKeys(ctx context.Context, api IAMAPI, accountID, scanID string, now time.Time) ([]Record, error) {
	var records []Record
	var marker *string
	for {
		users, err := api.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, u := range users.Users {
			keys, err := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
			if err != nil {
				return nil, err
			}
			for _, k := range keys.AccessKeyMetadata {
				keyID := aws.ToString(k.AccessKeyId)
				r := Record{
					ARN:       "arn:aws:iam::" + accountID + ":user/" + aws.ToString(u.UserName) + "/access-key/" + keyID,
					Name:      aws.ToString(u.UserName) + "/" + keyID,
					Kind:      "iam_access_key",
					AccountID: accountID,
					Region:    "global",
					Tags:      map[string]string{"status": string(k.Status)},
				}
				if k.CreateDate != nil {
					r.CreatedAt = *k.CreateDate
				}
				if lu, err := api.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId}); err == nil &&
					lu.AccessKeyLastUsed != nil && lu.AccessKeyLastUsed.LastUsedDate != nil {
					r.LastAccessedAt = lu.AccessKeyLastUsed.LastUsedDate
				}
				FinishRecord(&r, scanID, now)
				records = append(records, r)
			}
		}
		if !users.IsTruncated {
			break
		}
		marker = users.Marker
	}
	return records, nil
}
