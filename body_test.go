package main_test

import (
	"log"
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

	mw1 := ar.ReportMalware{
		SHA256:    "4490da766c35af92c8d8768136a5e775ed6a0929226ea9ab8995e50d5c516bf9",
		Timestamp: time.Now(),
		Scans: []ar.ReportMalwareScan{
			ar.ReportMalwareScan{
				Vendor:   "SomeVendor",
				Name:     "Win32.blood",
				Positive: true,
				Source:   "Blue",
			},
			ar.ReportMalwareScan{
				Vendor:   "OtherVendor",
				Name:     "Win32.cell",
				Positive: true,
				Source:   "Blue",
			},
		},
		Relation: "communicated",
	}

	mw2 := ar.ReportMalware{
		SHA256:    "b8e9671fe6fa897efb47aa66bd36f3d33117f77ec03e8d232f32e71559cef4a8",
		Timestamp: time.Now(),
		Scans: []ar.ReportMalwareScan{
			ar.ReportMalwareScan{
				Vendor:   "T company",
				Name:     "Win32.blood",
				Positive: true,
				Source:   "Orange",
			},
			ar.ReportMalwareScan{
				Vendor:   "S compamny",
				Name:     "Win32.cell",
				Positive: true,
				Source:   "Orange",
			},
		},
		Relation: "embeded",
	}

	domain1 := ar.ReportDomain{
		Name:      "example.com",
		Source:    "Pen",
		Timestamp: time.Now(),
	}

	report.Content.RemoteHosts["10.0.0.1"] = ar.ReportRemoteHost{
		IPAddr:         []string{"10.0.0.1", "10.0.0.3"},
		RelatedMalware: []ar.ReportMalware{mw1, mw2},
		RelatedDomains: []ar.ReportDomain{domain1},
	}

	// ----------------------------
	// Page2

	mw3 := ar.ReportMalware{
		SHA256:    "2e0390eb024a52963db7b95e84a9c2b12c004054a7bad9a97ec0c7c89d4681d2",
		Timestamp: time.Now(),
		Scans: []ar.ReportMalwareScan{
			ar.ReportMalwareScan{
				Vendor:   "T company",
				Name:     "Win32.blood",
				Positive: true,
				Source:   "Orange",
			},
			ar.ReportMalwareScan{
				Vendor:   "S compamny",
				Name:     "Win32.cell",
				Positive: true,
				Source:   "Orange",
			},
		},
		Relation: "embeded",
	}

	report.Content.RemoteHosts["10.0.0.2"] = ar.ReportRemoteHost{
		IPAddr:         []string{"10.0.0.2"},
		RelatedMalware: []ar.ReportMalware{mw3},
	}

	body := main.BuildCommentBody(report)
	log.Println(body)
}
