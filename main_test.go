package main_test

import (
	"testing"
	"time"

	"github.com/k0kubun/pp"

	"github.com/stretchr/testify/assert"

	ar "github.com/m-mizutani/AlertResponder/lib"
	main "github.com/m-mizutani/GheReporter"
	uuid "github.com/satori/go.uuid"
)

type testParams struct {
	SecretArn string `json:"secret_arn"`
	Region    string `json:"region"`
	TableName string `json:"table_name"`
}

func genDummyReport() ar.Report {
	alertKey := uuid.NewV4().String()

	alert := ar.Alert{
		Name:        "Kimochi",
		Rule:        "I am a rule",
		Description: "yossha",
		Key:         alertKey,
		Attrs: []ar.Attribute{
			ar.Attribute{
				Type:    "ipaddr",
				Value:   "10.0.0.1",
				Key:     "source address",
				Context: "remote",
			},
		},
	}
	reportID := ar.NewReportID()
	report := ar.NewReport(reportID, &alert)

	// ----------------------------
	// Page1
	page1 := ar.ReportPage{
		Title:  "test1",
		Author: "blue",
	}

	mw1 := ar.ReportMalware{
		SHA256:    "4490da766c35af92c8d8768136a5e775ed6a0929226ea9ab8995e50d5c516bf9",
		Timestamp: time.Now(),
		Scans: []ar.ReportMalwareScan{
			ar.ReportMalwareScan{
				Vendor:   "SomeVendor",
				Name:     "Win32.blood",
				Positive: true,
				Source:   "Testing",
			},
			ar.ReportMalwareScan{
				Vendor:   "OtherVendor",
				Name:     "Win32.cell",
				Positive: true,
				Source:   "Testing",
			},
		},
		Relation: "communicated",
	}

	page1.RemoteHost = []ar.ReportRemoteHost{
		ar.ReportRemoteHost{
			IPAddr:         []string{"10.0.0.1"},
			RelatedMalware: []ar.ReportMalware{mw1},
		},
	}

	report.Pages = append(report.Pages, &page1)

	// ----------------------------
	// Page2
	page2 := ar.ReportPage{
		Title:  "test2",
		Author: "orange",
	}

	mw2 := ar.ReportMalware{
		SHA256:    "b8e9671fe6fa897efb47aa66bd36f3d33117f77ec03e8d232f32e71559cef4a8",
		Timestamp: time.Now(),
		Scans: []ar.ReportMalwareScan{
			ar.ReportMalwareScan{
				Vendor:   "T company",
				Name:     "Win32.blood",
				Positive: true,
				Source:   "Testing",
			},
			ar.ReportMalwareScan{
				Vendor:   "S compamny",
				Name:     "Win32.cell",
				Positive: true,
				Source:   "Testing",
			},
		},
		Relation: "embeded",
	}

	page2.RemoteHost = []ar.ReportRemoteHost{
		ar.ReportRemoteHost{
			IPAddr:         []string{"10.0.0.1"},
			RelatedMalware: []ar.ReportMalware{mw2},
		},
	}
	report.Pages = append(report.Pages, &page2)

	return *report
}

func TestAlertPost(t *testing.T) {
	var params testParams
	ar.LoadTestConfig(&params)

	report := genDummyReport()
	resp, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.ApiURL, "https://")
	assert.Contains(t, resp.CommentApiURL, "https://")
	pp.Println(resp)

	report.Pages = []*ar.ReportPage{}
	respNoPage, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)
	assert.NoError(t, err)
	assert.Equal(t, resp.ApiURL, respNoPage.ApiURL)
	assert.Contains(t, respNoPage.ApiURL, "https://")
	assert.NotContains(t, respNoPage.CommentApiURL, "https://")

	report.ID = ar.NewReportID()
	respNewID, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)

	assert.NoError(t, err)
	assert.NotEqual(t, resp.ApiURL, respNewID.ApiURL)
	assert.Contains(t, respNewID.ApiURL, "https://")
	assert.NotContains(t, respNewID.CommentApiURL, "https://")
}
