package main_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	ar "github.com/m-mizutani/AlertResponder/lib"
	main "github.com/m-mizutani/GithubEmitter"
	uuid "github.com/satori/go.uuid"
)

func TestAlertBody(t *testing.T) {
	alertKey := uuid.NewV4().String()
	startTime := 1538642326
	endTime := 1538642336

	alert := ar.Alert{
		Name:        "Unusual network activity",
		Rule:        "NGFW threat",
		Description: "10.0.0.1",
		Key:         alertKey,
		Attrs: []ar.Attribute{
			ar.Attribute{
				Type:    "ipaddr",
				Value:   "10.0.0.1",
				Key:     "src address",
				Context: []string{"remote"},
			},
			ar.Attribute{
				Type:    "ipaddr",
				Value:   "192.168.3.1",
				Key:     "dst address",
				Context: []string{"remote"},
			},
			ar.Attribute{
				Value: "3306",
				Key:   "src port",
			},
		},
		Timestamp: ar.TimeRange{
			Init: float64(startTime),
			Last: float64(endTime),
		},
	}

	reportID := ar.NewReportID()
	report := ar.NewReport(reportID, alert)

	text := main.BuildIssueBody(report)
	assert.Contains(t, text, "  - src address: `10.0.0.1`")
	assert.Contains(t, text, "  - dst address: `192.168.3.1` (remote)")
	assert.Contains(t, text, "2018.10.04 17:38:46")
	assert.Contains(t, text, "2018.10.04 17:38:56")
}

func TestCommentBody(t *testing.T) {
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
				Context: []string{"remote"},
			},
		},
	}
	reportID := ar.NewReportID()
	report := ar.NewReport(reportID, alert)

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

}
