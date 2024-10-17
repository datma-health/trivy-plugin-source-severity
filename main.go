package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"slices"
	"strings"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	pkgReport "github.com/aquasecurity/trivy/pkg/report/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func getSeverity(cvss dbTypes.CVSS) dbTypes.Severity {
	if cvss.V3Score == 0 {
		return dbTypes.SeverityUnknown
	} else if cvss.V3Score < 4 {
		return dbTypes.SeverityLow
	} else if cvss.V3Score < 7 {
		return dbTypes.SeverityMedium
	} else if cvss.V3Score < 9 {
		return dbTypes.SeverityHigh
	} else {
		return dbTypes.SeverityCritical
	}
}

func run() error {
	// First we read Stdin to avoid Trivy freezing if we get an error
	var report types.Report
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return err
	}

	severityFlag := flag.String("severity", "HIGH,CRITICAL", "comma-separated severity levels to include in final report")
	severitySourcesFlag := flag.String("severity-sources", "ubuntu", "comma-separated vuln. sources where we attempt to update severity based on CVSS")
	flag.Parse()

	var severities []dbTypes.Severity
	for _, s := range strings.Split(*severityFlag, ",") {
		if sev, err := dbTypes.NewSeverity(s); err == nil {
			severities = append(severities, sev)
		}
	}
	severitySources := strings.Split(*severitySourcesFlag, ",")

	for i, result := range report.Results {
		for j, vuln := range result.Vulnerabilities {
			if !slices.Contains(severitySources, string(vuln.SeveritySource)) {
				continue
			}
			log.Printf("Checking CVE: %s for pkgId: %s to see if severity needs to be updated", vuln.VulnerabilityID, vuln.PkgID)

			var severity dbTypes.Severity = dbTypes.SeverityUnknown
			if cvss, ok := vuln.CVSS["nvd"]; ok {
				severity = getSeverity(cvss)
			} else if cvss, ok := vuln.CVSS["ghsa"]; ok {
				severity = getSeverity(cvss)
			} else {
				for k := range vuln.CVSS {
					severity = getSeverity(vuln.CVSS[k])
					break
				}
			}

			if vulnSeverity, err := dbTypes.NewSeverity(vuln.Severity); err == nil {
				if vulnSeverity < severity {
					log.Printf("Updating severity for %s from %s to %s", vuln.VulnerabilityID, vulnSeverity.String(), severity.String())
					report.Results[i].Vulnerabilities[j].Severity = severity.String()
				}
			}
		}
	}

	writer := pkgReport.Writer{Output: os.Stdout, Severities: severities}
	err := writer.Write(context.TODO(), report)
	if err != nil {
		return err
	}
	return nil
}
