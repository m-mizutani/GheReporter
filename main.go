package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	ar "github.com/m-mizutani/AlertResponder/lib"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type secretValues struct {
	GithubEndpoint   string `json:"github_endpoint"`
	GithubRepository string `json:"github_repo"`
	GithubToken      string `json:"github_token"`
}

func EmitReport(report ar.Report, region string, secrets secretValues) (string, error) {
	ar.Dump("report", report)
	return "ok", nil
}

func main() {
	lambda.Start(func(ctx context.Context, event events.SNSEvent) (string, error) {
		arn, err := ar.NewArnFromContext(ctx)
		if err != nil {
			ar.Dump("context", ctx)
			log.Fatal("Invalid context:", err)
		}
		region := arn.Region()

		var secrets secretValues
		err = ar.GetSecretValues(os.Getenv("SECRET_ID"), &secrets)
		if err != nil {
			log.Fatal("Can not get values from SecretsManager: ", err)
		}

		for _, record := range event.Records {
			var report ar.Report
			err := json.Unmarshal([]byte(record.SNS.Message), &report)
			if err != nil {
				log.Fatal("Fail to parse json into Report: ", record.SNS.Message)
			}

			EmitReport(report, region, secrets)
		}
		return "ok", nil
	})
}
