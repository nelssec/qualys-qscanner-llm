package qscanner

import (
	"fmt"
	"time"

	"github.com/nelssec/qualys-qscanner-llm/pkg/models"
	"github.com/google/uuid"
)

func ParseToScanResult(output *ScanOutput) *models.ScanResult {
	vulns := make([]models.Vulnerability, 0, len(output.Vulnerabilities))
	counts := models.SeverityCounts{}

	for _, v := range output.Vulnerabilities {
		severity := severityFromInt(v.Severity)

		switch severity {
		case models.SeverityCritical:
			counts.Critical++
		case models.SeverityHigh:
			counts.High++
		case models.SeverityMedium:
			counts.Medium++
		case models.SeverityLow:
			counts.Low++
		}

		cveID := ""
		if len(v.CVE) > 0 {
			cveID = v.CVE[0]
		}

		vulns = append(vulns, models.Vulnerability{
			CVEID:          cveID,
			QID:            v.QID,
			Title:          v.Title,
			Severity:       severity,
			CVSSv3Score:    v.CVSSv3Score,
			CVSSv3Vector:   v.CVSSv3Vector,
			Package:        v.Package,
			PackageVersion: v.PackageVersion,
			FixedVersion:   v.FixedVersion,
			IsPatchable:    v.IsPatchable,
			IsExploitable:  v.Threat.IsExploitable || v.Threat.EasyExploit || v.Threat.ActiveAttacks,
			Source:         "qscanner",
		})
	}

	target := output.Repository
	if output.Tag != "" {
		target = fmt.Sprintf("%s:%s", output.Repository, output.Tag)
	}
	if output.Registry != "" {
		target = fmt.Sprintf("%s/%s", output.Registry, target)
	}

	return &models.ScanResult{
		ID:              uuid.New().String(),
		Type:            "image",
		Target:          target,
		StartTime:       output.ScanDate,
		EndTime:         time.Now(),
		Status:          "completed",
		SeverityCounts:  counts,
		Vulnerabilities: vulns,
		Source:          "qscanner",
	}
}

func ParseToImage(output *ScanOutput) *models.Image {
	result := ParseToScanResult(output)

	return &models.Image{
		SHA:            output.ImageDigest,
		Name:           output.Repository,
		Tag:            output.Tag,
		Registry:       output.Registry,
		Created:        output.Created,
		Updated:        output.ScanDate,
		SeverityCounts: result.SeverityCounts,
		Vulnerabilities: result.Vulnerabilities,
	}
}

func severityFromInt(s int) models.Severity {
	switch s {
	case 1:
		return models.SeverityLow
	case 2:
		return models.SeverityMedium
	case 3:
		return models.SeverityHigh
	case 4, 5:
		return models.SeverityCritical
	default:
		return models.SeverityUnknown
	}
}
