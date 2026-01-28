package models

import "time"

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func ParseSeverity(s string) Severity {
	switch s {
	case "low", "1":
		return SeverityLow
	case "medium", "2":
		return SeverityMedium
	case "high", "3":
		return SeverityHigh
	case "critical", "4", "5":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

type Vulnerability struct {
	CVEID          string    `json:"cve_id"`
	QID            int       `json:"qid,omitempty"`
	Title          string    `json:"title"`
	Description    string    `json:"description,omitempty"`
	Severity       Severity  `json:"severity"`
	CVSSv3Score    float64   `json:"cvss_v3_score,omitempty"`
	CVSSv3Vector   string    `json:"cvss_v3_vector,omitempty"`
	Package        string    `json:"package,omitempty"`
	PackageVersion string    `json:"package_version,omitempty"`
	FixedVersion   string    `json:"fixed_version,omitempty"`
	IsPatchable    bool      `json:"is_patchable"`
	IsExploitable  bool      `json:"is_exploitable"`
	PublishedDate  time.Time `json:"published_date,omitempty"`
	Source         string    `json:"source"`
}

type Image struct {
	SHA            string    `json:"sha"`
	Name           string    `json:"name"`
	Tag            string    `json:"tag"`
	Registry       string    `json:"registry,omitempty"`
	Created        time.Time `json:"created,omitempty"`
	Updated        time.Time `json:"updated,omitempty"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Container struct {
	SHA            string    `json:"sha"`
	Name           string    `json:"name"`
	ImageSHA       string    `json:"image_sha"`
	State          string    `json:"state"`
	Created        time.Time `json:"created,omitempty"`
	Updated        time.Time `json:"updated,omitempty"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type ScanResult struct {
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Target          string          `json:"target"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Status          string          `json:"status"`
	SeverityCounts  SeverityCounts  `json:"severity_counts"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Source          string          `json:"source"`
}

type RiskSummary struct {
	TotalImages        int            `json:"total_images"`
	TotalContainers    int            `json:"total_containers"`
	TotalVulnerabilities int          `json:"total_vulnerabilities"`
	SeverityCounts     SeverityCounts `json:"severity_counts"`
	TopCVEs            []Vulnerability `json:"top_cves"`
	Source             string         `json:"source"`
}
