package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/guregu/dynamo"
	ar "github.com/m-mizutani/AlertResponder/lib"
	"github.com/pkg/errors"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	log "github.com/sirupsen/logrus"
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
		log.Println("The issue is not found")
		// If not existing issue, create a new one.
		body := BuildIssueBody(report)
		title := report.Alert.Title()
		body = fmt.Sprintf("ReportID: %s\n\n", report.ID) + body

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
		ar.Dump("New issue", cache)

	case nil:
		log.Println("The issue exists")
		ar.Dump("Existing issue", cache)
		issue, err = ghe.GetIssue(cache.IssueURL)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to get GHE issue")
		}

		if report.Status == "new" {
			body := BuildIssueBody(report)
			issue.AppendContent(body)
		}

	default:
		return nil, errors.Wrap(err, "Fail to get cache DB")
	}

	result.ApiURL = issue.ApiURL
	result.HtmlURL = issue.HtmlURL

	if report.IsPublished() {
		body := BuildPublishedReportHeader(report) + BuildCommentBody(report)
		log.Printf("body = %d\n", len(body))
		ar.Dump("comment", body)

		if len(body) > 0 {
			comment, err := issue.AddComment(body)
			if err != nil {
				return nil, errors.Wrap(err, "Fail to add a comment to GHE issue")
			}

			result.CommentApiURL = comment.ApiURL
			result.CommentHtmlURL = comment.HtmlURL
		}
	}

	ar.Dump("Result", result)

	return &result, nil
}

func main() {
	lambda.Start(func(ctx context.Context, event events.SNSEvent) (string, error) {
		ar.Dump("SNSevent", event)

		// Get region
		region := os.Getenv("AWS_REGION")
		if region == "" {
			log.Fatal("No AWS_REGION variable")
		}

		for _, record := range event.Records {
			var report ar.Report
			err := json.Unmarshal([]byte(record.SNS.Message), &report)
			if err != nil {
				log.Fatal("Fail to parse json into Report: ", record.SNS.Message)
			}

			ar.Dump("report", report)
			EmitReport(report, region, os.Getenv("SECRET_ARN"), os.Getenv("TABLE_NAME"))
		}
		return "ok", nil
	})
}
