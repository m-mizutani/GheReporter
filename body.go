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

func buildMalwareSection(pages []ar.ReportMalware) []string {
	if len(pages) == 0 {
		return []string{}
	}

	vendors := map[string]int{}
	vendorList := []string{}

	for _, page := range pages {
		for _, scan := range page.Scans {
			_, ok := vendors[scan.Vendor]
			if !ok {
				vendors[scan.Vendor] = len(vendorList)
				vendorList = append(vendorList, scan.Vendor)
			}
		}
	}

	hdr := []string{
		"",
		"Datetime",
		"Type",
	}
	for _, vendor := range vendorList {
		hdr = append(hdr, vendor)
	}
	hdr = append(hdr, "")

	sep := make([]string, len(hdr))
	for i := 1; i < len(hdr)-1; i++ {
		sep[i] = ":----"
	}

	thead := []string{
		"",
		"### Related Malware",
		"",
		strings.Join(hdr, "|"),
		strings.Join(sep, "|"),
	}

	tbody := []string{}

	for _, page := range pages {
		datetime := page.Timestamp.Format("2006-01-02 15:04:05")
		url := fmt.Sprintf("https://www.virustotal.com/ja/file/%s/analysis/", page.SHA256)
		row := make([]string, len(hdr))
		row[1] = fmt.Sprintf("[%s](%s)", datetime, url)
		row[2] = page.Relation
		for _, scan := range page.Scans {
			idx := vendors[scan.Vendor]
			row[3+idx] = scan.Name
		}
		tbody = append(tbody, strings.Join(row, "|"))
	}

	tbody = append(tbody, "")

	return append(thead, tbody...)
}

func buildDomainSection(pages []ar.ReportDomain) []string {
	if len(pages) == 0 {
		return []string{}
	}

	body := []string{
		"",
		"### Related Domain",
		"",
	}

	for _, page := range pages {
		datetime := page.Timestamp.Format("2006-01-02 15:04:05")
		body = append(body, fmt.Sprintf("- %s `%s` (%s)", datetime, page.Name, page.Source))
	}

	return append(body, "")
}

func buildURLSection(pages []ar.ReportURL) []string {
	if len(pages) == 0 {
		return []string{}
	}

	body := []string{
		"",
		"### Related URLs",
		"",
	}

	for _, page := range pages {
		datetime := page.Timestamp.Format("2006-01-02 15:04:05")
		body = append(body, fmt.Sprintf("- %s `%s` (%s)", datetime, page.URL, page.Source))
	}

	return append(body, "")
}

func aggrStrings(values []string) string {
	vmap := map[string]struct{}{}
	for _, v := range values {
		vmap[v] = struct{}{}
	}

	vlist := []string{}
	for k := range vmap {
		vlist = append(vlist, fmt.Sprintf("`%s`", k))
	}

	if len(vlist) == 0 {
		return "N/A"
	}

	return strings.Join(vlist, ", ")
}

func buildOpponentHostSection(pages map[string]ar.ReportOpponentHost) []string {
	body := []string{}

	for k, page := range pages {
		lines := []string{
			fmt.Sprintf("## Opponent Host: %s", k),
			"",
			fmt.Sprintf("- IP address: %s", aggrStrings(page.IPAddr)),
			fmt.Sprintf("- Country: %s", aggrStrings(page.Country)),
			fmt.Sprintf("- AS Owner: %s", aggrStrings(page.ASOwner)),
			"",
		}

		body = append(body, lines...)
		body = append(body, buildMalwareSection(page.RelatedMalware)...)
		body = append(body, buildDomainSection(page.RelatedDomains)...)
		body = append(body, buildURLSection(page.RelatedURLs)...)
	}

	return body
}

func buildServiceUsageSection(usages []ar.ReportServiceUsage) []string {
	if len(usages) == 0 {
		return []string{}
	}

	body := []string{
		"",
		"### Service Usage History",
		"",
		"Time | Service | Principal | Action ",
		":---:|:--------|:----------|:-------",
	}

	for _, usage := range usages {
		line := fmt.Sprintf(" %s | %s | %s | %s",
			usage.LastSeen.Format("2006-01-02 15:04:05"),
			usage.ServiceName, usage.Principal, usage.Action)
		body = append(body, line)
	}

	body = append(body, "")
	return body
}

func buildAlliedHostSection(pages map[string]ar.ReportAlliedHost) []string {
	body := []string{}

	for k, page := range pages {
		lines := []string{
			fmt.Sprintf("## Allied Host: %s", k),
			"",
			fmt.Sprintf("- UserName: %s", aggrStrings(page.UserName)),
			fmt.Sprintf("- Owner: %s", aggrStrings(page.Owner)),
			fmt.Sprintf("- OS: %s", aggrStrings(page.OS)),
			fmt.Sprintf("- IPAddr: %s", aggrStrings(page.IPAddr)),
			fmt.Sprintf("- MACAddr: %s", aggrStrings(page.MACAddr)),
			fmt.Sprintf("- HostName: %s", aggrStrings(page.HostName)),
			fmt.Sprintf("- Country: %s", aggrStrings(page.Country)),
			fmt.Sprintf("- Software: %s", aggrStrings(page.Software)),
			"",
		}

		body = append(body, lines...)
		body = append(body, buildServiceUsageSection(page.ServiceUsage)...)
	}

	return body
}

func BuildCommentBody(report ar.Report) string {
	// lines := []string{"# Inspection report"}
	body := []string{}

	body = append(body, buildAlliedHostSection(report.Content.AlliedHosts)...)
	body = append(body, buildOpponentHostSection(report.Content.OpponentHosts)...)

	return strings.Join(body, "\n")
}

func BuildPublishedReportHeader(report ar.Report) string {
	reason := report.Result.Reason
	if reason == "" {
		reason = "N/A"
	}

	body := []string{
		fmt.Sprintf("# Report: %s", report.Alert.Title()),
		"",
		fmt.Sprintf("- **Severity: %s**", report.Result.Severity),
		fmt.Sprintf("- Reason: %s", reason),
		"",
	}

	return strings.Join(body, "\n")
}
