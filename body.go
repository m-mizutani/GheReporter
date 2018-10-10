package main

import (
	"fmt"
	"strings"
	"time"

	ar "github.com/m-mizutani/AlertResponder/lib"
)

// BuildIssueBody creates message body of issue by Alert. It should show
// only basic information of the alert.
func BuildIssueBody(report ar.Report) string {
	timeFormat := "2006.01.02 15:04:05"
	fromTime := time.Unix(int64(report.Alert.Timestamp.Init), 0).Format(timeFormat)
	toTime := time.Unix(int64(report.Alert.Timestamp.Last), 0).Format(timeFormat)

	lines := []string{
		"## Overview",
		"",
		fmt.Sprintf("- Detected by %s", report.Alert.Rule),
		fmt.Sprintf("- %s - %s", fromTime, toTime),
		"- Attributes:",
	}

	for _, attr := range report.Alert.Attrs {
		base := fmt.Sprintf("  - %s: `%s`", attr.Key, attr.Value)
		if len(attr.Context) > 0 {
			base = fmt.Sprintf("%s (%s)", base, strings.Join(attr.Context, ", "))
		}
		lines = append(lines, base)
	}

	return strings.Join(lines, "\n")
}

func BuildCommentBody(report ar.Report) string {
	// lines := []string{"# Inspection report"}
	return "ugooooooo"
}
