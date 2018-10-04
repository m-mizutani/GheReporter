package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/guregu/dynamo"
	ar "github.com/m-mizutani/AlertResponder/lib"
	"github.com/pkg/errors"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

type secretValues struct {
	GithubEndpoint   string `json:"github_endpoint"`
	GithubRepository string `json:"github_repo"`
	GithubToken      string `json:"github_token"`
}

type Result struct {
	ApiURL         string `json:"api_url"`
	HtmlURL        string `json:"html_url"`
	CommentApiURL  string `json:"comment_api_url"`
	CommentHtmlURL string `json:"comment_html_url"`
}

type reportCache struct {
	ReportID ar.ReportID `dynamo:"report_id"`
	IssueURL string      `dynamo:"issue_url"`
	HtmlURL  string      `dynamo:"html_url"`
}

func EmitReport(report ar.Report, region, secretArn, tableName string) (*Result, error) {
	result := Result{}

	// Get secrets from SecretsManager
	var secrets secretValues
	err := ar.GetSecretValues(secretArn, &secrets)
	if err != nil {
		return nil, errors.Wrap(err, "Can not get values from SecretsManager")
	}

	ghe, err := NewGitHub(secrets.GithubEndpoint, secrets.GithubRepository, secrets.GithubToken)
	if err != nil {
		return nil, errors.Wrap(err, "Fail to create github accessor")
	}

	db := dynamo.New(session.New(), &aws.Config{Region: aws.String(region)})
	table := db.Table(tableName)

	// Lookup existing issue item.
	var cache reportCache
	err = table.Get("report_id", report.ID).One(&cache)
	var issue *GitHubIssue

	switch err {
	case dynamo.ErrNotFound:
		// If not existing issue, create a new one.
		body := BuildIssueBody(report)
		title := report.Alert.Title()
		issue, err = ghe.NewIssue(title, body)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to create GHE issue")
		}
		cache.ReportID = report.ID
		cache.IssueURL = issue.ApiURL
		cache.HtmlURL = issue.HtmlURL

		if err := table.Put(cache).Run(); err != nil {
			return nil, errors.Wrap(err, "Fail to set cache to DynamoDB")
		}

	case nil:
		issue, err = ghe.GetIssue(cache.IssueURL)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to get GHE issue")
		}

	default:
		return nil, errors.Wrap(err, "Fail to get cache DB")
	}

	result.ApiURL = issue.ApiURL
	result.HtmlURL = issue.HtmlURL

	if len(report.Pages) > 0 {
		body := BuildCommentBody(report)
		comment, err := issue.AddComment(body)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to add a comment to GHE issue")
		}

		result.CommentApiURL = comment.ApiURL
		result.CommentHtmlURL = comment.HtmlURL
	}

	return &result, nil
}

func main() {
	lambda.Start(func(ctx context.Context, event events.SNSEvent) (string, error) {
		// Get region
		arn, err := ar.NewArnFromContext(ctx)
		if err != nil {
			ar.Dump("context", ctx)
			log.Fatal("Invalid context:", err)
		}
		region := arn.Region()

		for _, record := range event.Records {
			var report ar.Report
			err := json.Unmarshal([]byte(record.SNS.Message), &report)
			if err != nil {
				log.Fatal("Fail to parse json into Report: ", record.SNS.Message)
			}

			EmitReport(report, region, os.Getenv("SECRET_ARN"), os.Getenv("TABLE_NAME"))
		}
		return "ok", nil
	})
}
