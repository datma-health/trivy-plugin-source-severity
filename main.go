package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
		log.Fatal(fmt.Errorf("main.run() failure %w", err))
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
		return fmt.Errorf("json.NewDecoder failure %w", err)
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

	var detected bool
	for i, result := range report.Results {
		var filteredVulnerability []types.DetectedVulnerability
		for j, vuln := range result.Vulnerabilities {
			if slices.Contains(severitySources, string(vuln.SeveritySource)) {
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
						fmt.Printf("Updating severity for %s from %s to %s\n", vuln.VulnerabilityID, vulnSeverity.String(), severity.String())
						report.Results[i].Vulnerabilities[j].Severity = severity.String()
					}
				}
			}

			if vulnSeverity, err := dbTypes.NewSeverity(report.Results[i].Vulnerabilities[j].Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredVulnerability = append(filteredVulnerability, report.Results[i].Vulnerabilities[j])
					detected = true
				}
			}
		}
		report.Results[i].Vulnerabilities = filteredVulnerability

		var filteredSecrets []types.DetectedSecret
		for _, secret := range result.Secrets {
			if vulnSeverity, err := dbTypes.NewSeverity(secret.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredSecrets = append(filteredSecrets, secret)
					detected = true
				}
			}
		}
		report.Results[i].Secrets = filteredSecrets

		var filteredLicenses []types.DetectedLicense
		for _, license := range result.Licenses {
			if vulnSeverity, err := dbTypes.NewSeverity(license.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredLicenses = append(filteredLicenses, license)
					detected = true
				}
			}
		}
		report.Results[i].Licenses = filteredLicenses

		var filteredMisconfs []types.DetectedMisconfiguration
		for _, misconf := range result.Misconfigurations {
			if vulnSeverity, err := dbTypes.NewSeverity(misconf.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredMisconfs = append(filteredMisconfs, misconf)
					detected = true
				}
			}
		}
		report.Results[i].Misconfigurations = filteredMisconfs
	}

	writer := pkgReport.Writer{Output: os.Stdout, Severities: severities}
	if err := writer.Write(context.TODO(), report); err != nil {
		return fmt.Errorf("writer.Write failure %w", err)
	}

	if detected {
		return fmt.Errorf("plugin detected vulnerabilities")
	}
	return nil
}
