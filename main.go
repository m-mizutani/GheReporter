package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	PagerDutyToken   string `json:"pagerduty_token"`
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

func CreatePagerDutyIncident(token, title, url string) error {
	type incidentContext struct {
		Type string `json:"type"`
		Href string `json:"href"`
		Text string `json:"text"`
	}
	type incidentBody struct {
		ServiceKey  string            `json:"service_key"`
		EventType   string            `json:"event_type"`
		Description string            `json:"description"`
		Detail      string            `json:"detail"`
		Client      string            `json:"client"`
		ClientURL   string            `json:"client_url"`
		Contexts    []incidentContext `json:"contexts"`
	}

	const pdURL = "https://events.pagerduty.com/generic/2010-04-15/create_event.json"

	if token == "" {
		return nil
	}

	body := incidentBody{
		ServiceKey:  token,
		EventType:   "trigger",
		Description: fmt.Sprintf("%s %s", url, title),
		Client:      "issue",
		ClientURL:   url,
		Contexts: []incidentContext{
			{
				Type: "link",
				Href: url,
			},
		},
	}

	log.WithField("body", body)

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", pdURL, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	log.WithField("resp", resp).Info("sent a PD request")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var respData []byte
	_, err = resp.Body.Read(respData)
	if err != nil {
		return err
	}
	log.Printf("response: %s", string(respData))

	return nil
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
		log.WithField("report", report).Info("The issue is not found")
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
		log.WithField("issue", cache).Info("new issue")

	case nil:
		log.WithField("issue", cache).Info("The issue exists")

		issue, err = ghe.GetIssue(cache.IssueURL)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to get GHE issue")
		}

		if report.IsNew() {
			body := BuildIssueBody(report)
			issue.AppendContent(body)
		}

	default:
		return nil, errors.Wrap(err, "Fail to get cache DB")
	}

	result.ApiURL = issue.ApiURL
	result.HtmlURL = issue.HtmlURL

	commentHdr := BuildPublishedReportHeader(report)
	commentBody := BuildCommentBody(report)
	log.Println("Comment: ", commentBody)

	if report.IsPublished() {
		if report.Result.Severity == ar.SevSafe {
			err := issue.Close()
			if err != nil {
				return nil, err
			}
		}

		body := commentHdr + commentBody
		comment, err := issue.AddComment(body)
		if err != nil {
			return nil, errors.Wrap(err, "Fail to add a comment to GHE issue")
		}

		result.CommentApiURL = comment.ApiURL
		result.CommentHtmlURL = comment.HtmlURL

		if report.Result.Severity != ar.SevSafe {
			err := CreatePagerDutyIncident(secrets.PagerDutyToken, report.Alert.Title(), result.CommentHtmlURL)

			if err != nil {
				return nil, err
			}
		}
	}

	log.WithField("result", result).Info("")

	return &result, nil
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	lambda.Start(func(ctx context.Context, event events.SNSEvent) (string, error) {
		log.WithField("SNSevent", event).Info("Start")

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

			log.WithField("report", report).Info("Extrated report")
			result, err := EmitReport(report, region, os.Getenv("SECRET_ARN"), os.Getenv("TABLE_NAME"))
			if err != nil {
				log.WithError(err).Error("Fail to emit report")
				return "ng", err
			} else {
				log.WithField("result", result).Info("Emitted")
			}
		}

		return "ok", nil
	})
}
