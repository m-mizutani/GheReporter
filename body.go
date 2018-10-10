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
	var timeRange string
	if fromTime == toTime {
		timeRange = fromTime
	} else {
		timeRange = fmt.Sprintf("%s - %s", fromTime, toTime)
	}

	lines := []string{
		"## Overview",
		"",
		fmt.Sprintf("- Detected by %s", report.Alert.Rule),
		fmt.Sprintf("- Time: %s", timeRange),
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

func sliceIndex(strArray []string, word string) int {
	for idx, s := range strArray {
		if s == word {
			return idx
		}
	}

	return -1
}

type aggrValue struct {
	valueMap map[string]struct{}
}

func newAggrMap() aggrValue {
	av := aggrValue{
		valueMap: map[string]struct{}{},
	}
	return av
}

func (x *aggrValue) add(value string) {
	x.valueMap[value] = struct{}{}
}

func (x *aggrValue) aggr() []string {
	valueList := []string{}
	for k := range x.valueMap {
		valueList = append(valueList, k)
	}

	return valueList
}

func buildRemoteHostDocs(pages []*ar.ReportPage) []string {
	pageMap := map[string]*[]ar.ReportRemoteHost{}
	for _, page := range pages {
		for _, remote := range page.RemoteHost {
			arr, ok := pageMap[remote.ID]
			if !ok {
				newSlice := []ar.ReportRemoteHost{}
				pageMap[remote.ID] = &newSlice
				arr = &newSlice
			}

			*arr = append(*arr, remote)
		}
	}

	body := []string{}

	for k, arr := range pageMap {
		ipaddr, country, asOwner := newAggrMap(), newAggrMap(), newAggrMap()
		for _, remote := range *arr {
			for _, v := range remote.IPAddr {
				ipaddr.add(v)
			}
			for _, v := range remote.Country {
				country.add(v)
			}
			for _, v := range remote.ASOwner {
				asOwner.add(v)
			}
		}

		lines := []string{
			fmt.Sprintf("## Remote Host: %s", k),
			"",
			fmt.Sprintf("- IP address: %s", strings.Join(ipaddr.aggr(), ", ")),
			fmt.Sprintf("- Country: %s", strings.Join(country.aggr(), ", ")),
			fmt.Sprintf("- AS Owner: %s", strings.Join(asOwner.aggr(), ", ")),
			"",
		}

		body = append(body, lines...)
	}

	return body
}

func BuildCommentBody(report ar.Report) string {
	// lines := []string{"# Inspection report"}
	body := []string{}

	body = append(body, buildRemoteHostDocs(report.Pages)...)

	return strings.Join(body, "\n")
}
