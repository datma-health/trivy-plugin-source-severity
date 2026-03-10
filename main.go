package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
		if err == io.EOF {
			// Trivy produced no output (e.g. the scan itself failed) - proceed with an empty report
		} else {
			return fmt.Errorf("json.NewDecoder failure %w", err)
		}
	}

	// Use a local FlagSet so run() can be called more than once (e.g. in tests)
	// without triggering a "flag redefined" panic on flag.CommandLine.
	flags := flag.NewFlagSet("source-severity", flag.ContinueOnError)
	severityFlag := flags.String("severity", "HIGH,CRITICAL", "comma-separated severity levels to include in final report")
	severitySourcesFlag := flags.String("severity-sources", "ubuntu", "comma-separated vuln. sources where we attempt to update severity based on CVSS")
	// Ignore parse errors: unknown flags (e.g. -test.run from the Go test runner)
	// are harmless; the defaults above remain in effect.
	_ = flags.Parse(os.Args[1:])

	var severities []dbTypes.Severity
	for _, s := range strings.Split(*severityFlag, ",") {
		if sev, err := dbTypes.NewSeverity(s); err == nil {
			severities = append(severities, sev)
		}
	}
	severitySources := strings.Split(*severitySourcesFlag, ",")

	var detected int
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
					detected += 1
				}
			}
		}
		report.Results[i].Vulnerabilities = filteredVulnerability

		var filteredSecrets []types.DetectedSecret
		for _, secret := range result.Secrets {
			if vulnSeverity, err := dbTypes.NewSeverity(secret.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredSecrets = append(filteredSecrets, secret)
					detected += 1
				}
			}
		}
		report.Results[i].Secrets = filteredSecrets

		var filteredLicenses []types.DetectedLicense
		for _, license := range result.Licenses {
			if vulnSeverity, err := dbTypes.NewSeverity(license.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredLicenses = append(filteredLicenses, license)
					detected += 1
				}
			}
		}
		report.Results[i].Licenses = filteredLicenses

		var filteredMisconfs []types.DetectedMisconfiguration
		for _, misconf := range result.Misconfigurations {
			if vulnSeverity, err := dbTypes.NewSeverity(misconf.Severity); err == nil {
				if slices.Contains(severities, vulnSeverity) {
					filteredMisconfs = append(filteredMisconfs, misconf)
					detected += 1
				}
			}
		}
		report.Results[i].Misconfigurations = filteredMisconfs
	}

	writer := pkgReport.Writer{Output: os.Stdout, Severities: severities}
	if err := writer.Write(context.TODO(), report); err != nil {
		return fmt.Errorf("writer.Write failure %w", err)
	}

	if detected > 0 {
		return fmt.Errorf("plugin detected %v vulnerabilities", detected)
	}
	return nil
}
