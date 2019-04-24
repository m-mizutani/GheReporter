package main_test

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	ar "github.com/m-mizutani/AlertResponder/lib"
	main "github.com/m-mizutani/GithubEmitter"
	uuid "github.com/satori/go.uuid"
)

type testParams struct {
	SecretArn string `json:"secret_arn"`
	Region    string `json:"region"`
	TableName string `json:"table_name"`
}

func loadTestConfig(params interface{}) {
	fpath := "test.json"
	fd, err := os.Open(fpath)
	if err != nil {
		log.Fatal("Fail to open TestConfig:", fpath, err)
	}
	defer fd.Close()

	fdata, err := ioutil.ReadAll(fd)
	if err != nil {
		log.Fatal("Fail to read TestConfig:", fpath, err)
	}

	err = json.Unmarshal(fdata, params)
	if err != nil {
		log.Fatal("Fail to unmarshal TestConfig", fpath, err)
	}

	return
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

	report.Content.OpponentHosts["10.0.0.1"] = ar.ReportOpponentHost{
		IPAddr:         []string{"10.0.0.1"},
		RelatedMalware: []ar.ReportMalware{mw1, mw2},
	}

	return report
}

func TestAlertPost(t *testing.T) {
	var params testParams
	loadTestConfig(&params)

	report := genDummyReport()

	resp, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)
	report.Status = ar.StatusPublished

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.ApiURL, "https://")

	/*
		assert.Contains(t, resp.CommentApiURL, "https://")

		// Overwrite
		report.Content.OpponentHosts = map[string]ar.ReportOpponentHost{}
		respNoPage, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)
		assert.NoError(t, err)
		assert.Equal(t, resp.ApiURL, respNoPage.ApiURL)
		assert.Contains(t, respNoPage.ApiURL, "https://")

		report.ID = ar.NewReportID()
		respNewID, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)

		assert.NoError(t, err)
		assert.NotEqual(t, resp.ApiURL, respNewID.ApiURL)
		assert.Contains(t, respNewID.ApiURL, "https://")
		assert.NotContains(t, respNewID.CommentApiURL, "https://")
	*/
}

func TestPagerDuty(t *testing.T) {
	var params testParams
	loadTestConfig(&params)

	report := genDummyReport()
	report.Status = ar.StatusPublished
	report.Result.Severity = ar.SevUrgent
	resp, err := main.EmitReport(report, params.Region, params.SecretArn, params.TableName)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
}
