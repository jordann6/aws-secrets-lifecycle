package store

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/sweep"
)

type fakeDynamo struct {
	calls           int
	itemsSeen       int
	failFirstNItems bool
}

func (f *fakeDynamo) BatchWriteItem(ctx context.Context, in *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	f.calls++
	for _, reqs := range in.RequestItems {
		f.itemsSeen += len(reqs)
	}
	out := &dynamodb.BatchWriteItemOutput{}
	if f.failFirstNItems && f.calls == 1 {
		// Return one unprocessed item to exercise the retry path.
		for table, reqs := range in.RequestItems {
			out.UnprocessedItems = map[string][]types.WriteRequest{table: reqs[:1]}
			f.itemsSeen -= 1
		}
	}
	return out, nil
}

func makeRecords(n int) []sweep.Record {
	recs := make([]sweep.Record, n)
	for i := range recs {
		recs[i] = sweep.Record{PK: "arn", SK: "INVENTORY#s"}
	}
	return recs
}

func TestWriteRecordsChunksAt25(t *testing.T) {
	f := &fakeDynamo{}
	if err := WriteRecords(context.Background(), f, "tbl", makeRecords(60)); err != nil {
		t.Fatal(err)
	}
	if f.calls != 3 {
		t.Fatalf("expected 3 batch calls for 60 records, got %d", f.calls)
	}
	if f.itemsSeen != 60 {
		t.Fatalf("expected 60 items written, got %d", f.itemsSeen)
	}
}

func TestWriteRecordsRetriesUnprocessed(t *testing.T) {
	f := &fakeDynamo{failFirstNItems: true}
	if err := WriteRecords(context.Background(), f, "tbl", makeRecords(10)); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Fatalf("expected retry call, got %d calls", f.calls)
	}
	if f.itemsSeen != 10 {
		t.Fatalf("expected all 10 items eventually written, got %d", f.itemsSeen)
	}
}
