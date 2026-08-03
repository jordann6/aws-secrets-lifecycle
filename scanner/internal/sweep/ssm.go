package sweep

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type SSMAPI interface {
	DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, opts ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
	ListTagsForResource(ctx context.Context, in *ssm.ListTagsForResourceInput, opts ...func(*ssm.Options)) (*ssm.ListTagsForResourceOutput, error)
}

// SweepParameters lists SecureString SSM parameters. Values are never
// read; the role carries an explicit deny on ssm:GetParameter*.
func SweepParameters(ctx context.Context, api SSMAPI, accountID, region, scanID string, now time.Time) ([]Record, error) {
	var records []Record
	var next *string
	for {
		out, err := api.DescribeParameters(ctx, &ssm.DescribeParametersInput{
			MaxResults: aws.Int32(50),
			NextToken:  next,
			ParameterFilters: []ssmtypes.ParameterStringFilter{{
				Key:    aws.String("Type"),
				Values: []string{"SecureString"},
			}},
		})
		if err != nil {
			return nil, err
		}
		for _, p := range out.Parameters {
			name := aws.ToString(p.Name)
			r := Record{
				ARN:       "arn:aws:ssm:" + region + ":" + accountID + ":parameter" + name,
				Name:      name,
				Kind:      "ssm_securestring",
				AccountID: accountID,
				Region:    region,
				Tags:      map[string]string{},
			}
			if p.LastModifiedDate != nil {
				r.CreatedAt = *p.LastModifiedDate
			}
			if tags, err := api.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
				ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
				ResourceId:   aws.String(name),
			}); err == nil {
				for _, t := range tags.TagList {
					r.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
				}
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
