package store

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/sweep"
)

type DynamoAPI interface {
	BatchWriteItem(ctx context.Context, in *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
}

// WriteRecords batch-writes records 25 at a time, retrying unprocessed
// items until DynamoDB accepts them all.
func WriteRecords(ctx context.Context, api DynamoAPI, table string, records []sweep.Record) error {
	for start := 0; start < len(records); start += 25 {
		end := start + 25
		if end > len(records) {
			end = len(records)
		}
		var reqs []types.WriteRequest
		for _, r := range records[start:end] {
			item, err := attributevalue.MarshalMap(r)
			if err != nil {
				return err
			}
			reqs = append(reqs, types.WriteRequest{
				PutRequest: &types.PutRequest{Item: item},
			})
		}
		pending := map[string][]types.WriteRequest{table: reqs}
		for len(pending[table]) > 0 {
			out, err := api.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
				RequestItems: pending,
			})
			if err != nil {
				return err
			}
			pending = out.UnprocessedItems
			if pending == nil {
				break
			}
		}
	}
	return nil
}
