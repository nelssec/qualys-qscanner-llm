package qscanner

import "time"

type ScanOutput struct {
	ImageID        string          `json:"imageId"`
	ImageDigest    string          `json:"imageDigest"`
	Registry       string          `json:"registry"`
	Repository     string          `json:"repository"`
	Tag            string          `json:"tag"`
	Created        time.Time       `json:"created"`
	ScanDate       time.Time       `json:"scanDate"`
	ScanType       []string        `json:"scanType"`
	ScanMode       string          `json:"scanMode"`
	OS             OSInfo          `json:"os"`
	Packages       []Package       `json:"packages"`
	Vulnerabilities []VulnOutput   `json:"vulnerabilities"`
	Secrets        []Secret        `json:"secrets,omitempty"`
	Malware        []MalwareOutput `json:"malware,omitempty"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	Path    string `json:"path,omitempty"`
}

type VulnOutput struct {
	QID            int      `json:"qid"`
	CVE            []string `json:"cve"`
	Title          string   `json:"title"`
	Severity       int      `json:"severity"`
	CVSSv3Score    float64  `json:"cvssV3Score"`
	CVSSv3Vector   string   `json:"cvssV3Vector"`
	Package        string   `json:"package"`
	PackageVersion string   `json:"packageVersion"`
	FixedVersion   string   `json:"fixedVersion,omitempty"`
	IsPatchable    bool     `json:"isPatchable"`
	Threat         Threat   `json:"threat,omitempty"`
}

type Threat struct {
	IsExploitable   bool `json:"isExploitable"`
	EasyExploit     bool `json:"easyExploit"`
	ActiveAttacks   bool `json:"activeAttacks"`
	HighDataLoss    bool `json:"highDataLoss"`
	DenialOfService bool `json:"denialOfService"`
	NoPatch         bool `json:"noPatch"`
}

type Secret struct {
	Type     string `json:"type"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity int    `json:"severity"`
}

type MalwareOutput struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Hash     string `json:"hash"`
	Severity int    `json:"severity"`
}

type ScanOptions struct {
	Image    string
	Mode     string
	ScanType []string
	Platform string
	Path     string
	ContainerID string
}
