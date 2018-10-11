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

func (x *aggrValue) aggr() string {
	valueList := []string{}
	for k := range x.valueMap {
		valueList = append(valueList, k)
	}

	if len(valueList) > 0 {
		return strings.Join(valueList, ", ")
	} else {
		return "N/A"
	}
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

func buildRemoteHostSection(pages map[string]ar.ReportRemoteHost) []string {
	body := []string{}

	for k, page := range pages {
		ipaddr, country, asOwner := newAggrMap(), newAggrMap(), newAggrMap()
		for _, v := range page.IPAddr {
			ipaddr.add(v)
		}
		for _, v := range page.Country {
			country.add(v)
		}
		for _, v := range page.ASOwner {
			asOwner.add(v)
		}

		lines := []string{
			fmt.Sprintf("## Remote Host: %s", k),
			"",
			fmt.Sprintf("- IP address: %s", ipaddr.aggr()),
			fmt.Sprintf("- Country: %s", country.aggr()),
			fmt.Sprintf("- AS Owner: %s", asOwner.aggr()),
			"",
		}

		body = append(body, lines...)
		body = append(body, buildMalwareSection(page.RelatedMalware)...)
		body = append(body, buildDomainSection(page.RelatedDomains)...)
		body = append(body, buildURLSection(page.RelatedURLs)...)
	}

	return body
}

func BuildCommentBody(report ar.Report) string {
	// lines := []string{"# Inspection report"}
	body := []string{}

	body = append(body, buildRemoteHostSection(report.Content.RemoteHosts)...)

	return strings.Join(body, "\n")
}
