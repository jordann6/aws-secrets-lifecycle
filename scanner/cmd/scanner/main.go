package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/store"
	"github.com/jordann6/aws-secrets-lifecycle/scanner/internal/sweep"
)

type Result struct {
	ScanID           string  `json:"scan_id"`
	SecretsScanned   int     `json:"secrets_scanned"`
	WallClockSeconds float64 `json:"wall_clock_seconds"`
	SecretsPerSecond float64 `json:"secrets_per_second"`
}

// target is one account+region sweep surface.
type target struct {
	cfg       aws.Config
	accountID string
	region    string
}

func buildTargets(ctx context.Context) ([]target, error) {
	base, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(base)
	ident, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	regions := []string{base.Region}
	if v := os.Getenv("SCAN_REGIONS"); v != "" {
		regions = strings.Split(v, ",")
	}

	var targets []target
	for _, region := range regions {
		cfg := base.Copy()
		cfg.Region = region
		targets = append(targets, target{cfg: cfg, accountID: *ident.Account, region: region})
	}

	// Cross-account targets via assumed roles, comma-separated ARNs.
	if v := os.Getenv("SCAN_TARGET_ROLE_ARNS"); v != "" {
		for _, roleARN := range strings.Split(v, ",") {
			roleARN = strings.TrimSpace(roleARN)
			if roleARN == "" {
				continue
			}
			provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN)
			accountID := strings.Split(roleARN, ":")[4]
			for _, region := range regions {
				cfg := base.Copy()
				cfg.Region = region
				cfg.Credentials = aws.NewCredentialsCache(provider)
				targets = append(targets, target{cfg: cfg, accountID: accountID, region: region})
			}
		}
	}
	return targets, nil
}

func runScan(ctx context.Context) (Result, error) {
	started := time.Now()
	scanID := started.UTC().Format("20060102T150405Z")
	table := os.Getenv("INVENTORY_TABLE")
	if table == "" {
		return Result{}, fmt.Errorf("INVENTORY_TABLE is required")
	}

	targets, err := buildTargets(ctx)
	if err != nil {
		return Result{}, err
	}

	var tasks []sweep.Task
	seenAccounts := map[string]bool{}
	for _, t := range targets {
		t := t
		smClient := secretsmanager.NewFromConfig(t.cfg)
		ssmClient := ssm.NewFromConfig(t.cfg)
		tasks = append(tasks, func(ctx context.Context) ([]sweep.Record, error) {
			return sweep.SweepSecrets(ctx, smClient, t.accountID, t.region, scanID, started)
		})
		tasks = append(tasks, func(ctx context.Context) ([]sweep.Record, error) {
			return sweep.SweepParameters(ctx, ssmClient, t.accountID, t.region, scanID, started)
		})
		// IAM is global: one sweep per account, not per region.
		if !seenAccounts[t.accountID] {
			seenAccounts[t.accountID] = true
			iamClient := iam.NewFromConfig(t.cfg)
			tasks = append(tasks, func(ctx context.Context) ([]sweep.Record, error) {
				return sweep.SweepAccessKeys(ctx, iamClient, t.accountID, scanID, started)
			})
		}
	}

	records, err := sweep.RunPool(ctx, 8, tasks)
	if err != nil {
		return Result{}, err
	}

	base, _ := config.LoadDefaultConfig(ctx)
	if err := store.WriteRecords(ctx, dynamodb.NewFromConfig(base), table, records); err != nil {
		return Result{}, err
	}

	elapsed := time.Since(started).Seconds()
	res := Result{
		ScanID:           scanID,
		SecretsScanned:   len(records),
		WallClockSeconds: elapsed,
		SecretsPerSecond: float64(len(records)) / elapsed,
	}
	out, _ := json.Marshal(res)
	log.Printf("scan complete %s", out)
	return res, nil
}

func handler(ctx context.Context) (Result, error) {
	return runScan(ctx)
}

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(handler)
		return
	}
	res, err := runScan(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}
