package qualys

import (
	"encoding/json"
	"fmt"
	"time"
)

type UnixMilliTime struct {
	time.Time
}

func (t *UnixMilliTime) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		var millis int64
		if err := json.Unmarshal(data, &millis); err != nil {
			var floatMillis float64
			if err := json.Unmarshal(data, &floatMillis); err != nil {
				return nil
			}
			t.Time = time.UnixMilli(int64(floatMillis))
			return nil
		}
		t.Time = time.UnixMilli(millis)
		return nil
	}

	if str == "" || str == "null" {
		return nil
	}

	var millis int64
	if _, err := fmt.Sscanf(str, "%d", &millis); err == nil {
		t.Time = time.UnixMilli(millis)
		return nil
	}

	parsed, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil
	}
	t.Time = parsed
	return nil
}

type FlexInt struct {
	Value int
}

func (f *FlexInt) UnmarshalJSON(data []byte) error {
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		f.Value = intVal
		return nil
	}

	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		if strVal == "" || strVal == "null" {
			f.Value = 0
			return nil
		}
		fmt.Sscanf(strVal, "%d", &f.Value)
		return nil
	}

	var floatVal float64
	if err := json.Unmarshal(data, &floatVal); err == nil {
		f.Value = int(floatVal)
		return nil
	}

	return nil
}

type FlexFloat struct {
	Value float64
}

func (f *FlexFloat) UnmarshalJSON(data []byte) error {
	var floatVal float64
	if err := json.Unmarshal(data, &floatVal); err == nil {
		f.Value = floatVal
		return nil
	}

	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		if strVal == "" || strVal == "null" {
			f.Value = 0
			return nil
		}
		fmt.Sscanf(strVal, "%f", &f.Value)
		return nil
	}

	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		f.Value = float64(intVal)
		return nil
	}

	return nil
}

type FlexString struct {
	Value string
}

func (f *FlexString) UnmarshalJSON(data []byte) error {
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		f.Value = strVal
		return nil
	}

	var intVal int64
	if err := json.Unmarshal(data, &intVal); err == nil {
		f.Value = fmt.Sprintf("%d", intVal)
		return nil
	}

	var floatVal float64
	if err := json.Unmarshal(data, &floatVal); err == nil {
		f.Value = fmt.Sprintf("%v", floatVal)
		return nil
	}

	return nil
}

type FlexBool struct {
	Value bool
}

func (f *FlexBool) UnmarshalJSON(data []byte) error {
	var boolVal bool
	if err := json.Unmarshal(data, &boolVal); err == nil {
		f.Value = boolVal
		return nil
	}

	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		f.Value = strVal == "true" || strVal == "1" || strVal == "yes"
		return nil
	}

	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		f.Value = intVal != 0
		return nil
	}

	return nil
}

type AuthResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

type PaginatedResponse struct {
	Count int `json:"count"`
	Data  any `json:"data"`
}

type ImageListResponse struct {
	Count int         `json:"count"`
	Data  []ImageData `json:"data"`
}

type ImageRepoInfo struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

type ImageDigestInfo struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

type ImageVulnCounts struct {
	Severity1Count *int `json:"severity1Count"`
	Severity2Count *int `json:"severity2Count"`
	Severity3Count *int `json:"severity3Count"`
	Severity4Count *int `json:"severity4Count"`
	Severity5Count *int `json:"severity5Count"`
	Total          *int `json:"total"`
}

type HostInfo struct {
	UUID      string        `json:"uuid"`
	Hostname  string        `json:"hostname"`
	IPAddress string        `json:"ipAddress"`
	LastFound UnixMilliTime `json:"lastFound"`
}

type ClusterInfo struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type ImageData struct {
	ImageID                string            `json:"imageId"`
	SHA                    string            `json:"sha"`
	UUID                   string            `json:"uuid"`
	CustomerUUID           string            `json:"customerUuid"`
	Repo                   []ImageRepoInfo   `json:"repo"`
	RepoDigests            []ImageDigestInfo `json:"repoDigests"`
	Label                  json.RawMessage   `json:"label"`
	Author                 string            `json:"author"`
	Created                UnixMilliTime     `json:"created"`
	Updated                UnixMilliTime     `json:"updated"`
	LastUsedDate           UnixMilliTime     `json:"lastUsedDate"`
	LastScannedDate        UnixMilliTime     `json:"lastScannedDate"`
	LastAssessed           UnixMilliTime     `json:"lastAssessed"`
	Size                   int64             `json:"size"`
	OperatingSystem        string            `json:"operatingSystem"`
	DockerVersion          string            `json:"dockerVersion"`
	Architecture           string            `json:"architecture"`
	Vulnerabilities        ImageVulnCounts   `json:"vulnerabilities"`
	ScanStatus             string            `json:"scanStatus"`
	ScanType               []string          `json:"scanType"`
	ScanErrorCode          string            `json:"scanErrorCode"`
	ScanErrorMessage       string            `json:"scanErrorMessage"`
	Source                 []string          `json:"source"`
	IsContinuouslyAssessed *bool             `json:"isContinuouslyAssessed"`
	RiskScore              *float64          `json:"riskScore"`
	MaxQdsScore            *int              `json:"maxQdsScore"`
	QdsSeverity            string            `json:"qdsSeverity"`
	Criticality            FlexString        `json:"criticality"`
	LastFoundOnHost        *HostInfo         `json:"lastFoundOnHost"`
	MalwareCount           *int              `json:"malwareCount"`
	SecretsCount           *int              `json:"secretsCount"`
	SensitiveDataCount     *int              `json:"sensitiveDataCount"`
}

type LayerData struct {
	SHA       string          `json:"sha"`
	ID        string          `json:"id"`
	Size      int64           `json:"size"`
	CreatedBy string          `json:"createdBy"`
	Created   UnixMilliTime   `json:"created"`
	Comment   string          `json:"comment"`
	Tags      json.RawMessage `json:"tags"`
}

type SoftwareData struct {
	Name           string        `json:"name"`
	Version        string        `json:"version"`
	Type           string        `json:"type"`
	Path           string        `json:"path"`
	FixedVersion   string        `json:"fixedVersion"`
	VulnCount      *int          `json:"vulnCount"`
	Severity5Count *int          `json:"severity5Count"`
	Severity4Count *int          `json:"severity4Count"`
	Severity3Count *int          `json:"severity3Count"`
	Severity2Count *int          `json:"severity2Count"`
	Severity1Count *int          `json:"severity1Count"`
	Created        UnixMilliTime `json:"created"`
	Updated        UnixMilliTime `json:"updated"`
}

type ImageDetailResponse struct {
	ImageID                string              `json:"imageId"`
	SHA                    string              `json:"sha"`
	UUID                   string              `json:"uuid"`
	CustomerUUID           string              `json:"customerUuid"`
	Registry               string              `json:"registry"`
	Repo                   []ImageRepoInfo     `json:"repo"`
	Tag                    string              `json:"tag"`
	Author                 string              `json:"author"`
	Label                  json.RawMessage     `json:"label"`
	Created                UnixMilliTime       `json:"created"`
	Updated                UnixMilliTime       `json:"updated"`
	LastUsedDate           UnixMilliTime       `json:"lastUsedDate"`
	LastScannedDate        UnixMilliTime       `json:"lastScannedDate"`
	LastAssessed           UnixMilliTime       `json:"lastAssessed"`
	OS                     string              `json:"os"`
	OperatingSystem        string              `json:"operatingSystem"`
	DockerVersion          string              `json:"dockerVersion"`
	Architecture           string              `json:"architecture"`
	Size                   int64               `json:"size"`
	Layers                 []LayerData         `json:"layers"`
	Software               []SoftwareData      `json:"softwares"`
	Vulnerabilities        []VulnerabilityData `json:"vulnerabilities"`
	Malware                []MalwareData       `json:"malware"`
	Secrets                []SecretData        `json:"secrets"`
	SensitiveData          []SensitiveData     `json:"sensitiveData"`
	ScanStatus             string              `json:"scanStatus"`
	ScanType               []string            `json:"scanType"`
	ScanErrorCode          string              `json:"scanErrorCode"`
	ScanErrorMessage       string              `json:"scanErrorMessage"`
	Source                 []string            `json:"source"`
	IsContinuouslyAssessed *bool               `json:"isContinuouslyAssessed"`
	RiskScore              *float64            `json:"riskScore"`
	MaxQdsScore            *int                `json:"maxQdsScore"`
	QdsSeverity            string              `json:"qdsSeverity"`
	Criticality            FlexString          `json:"criticality"`
	LastFoundOnHost        *HostInfo           `json:"lastFoundOnHost"`
	AssociatedContainers   []AssociationInfo   `json:"associatedContainers"`
	AssociatedHosts        []AssociationInfo   `json:"associatedHosts"`
}

type AssociationInfo struct {
	UUID     string        `json:"uuid"`
	Name     string        `json:"name"`
	Hostname string        `json:"hostname"`
	Count    int           `json:"count"`
	LastSeen UnixMilliTime `json:"lastSeen"`
}

type MalwareData struct {
	Name     string          `json:"name"`
	Hash     string          `json:"hash"`
	Path     string          `json:"path"`
	Type     string          `json:"type"`
	Severity int             `json:"severity"`
	Details  json.RawMessage `json:"details"`
}

type SecretData struct {
	Type     string          `json:"type"`
	Path     string          `json:"path"`
	Line     int             `json:"line"`
	Severity int             `json:"severity"`
	Details  json.RawMessage `json:"details"`
}

type SensitiveData struct {
	Type     string          `json:"type"`
	Path     string          `json:"path"`
	Severity int             `json:"severity"`
	Details  json.RawMessage `json:"details"`
}

type ThreatIntelData struct {
	ActiveAttacks        FlexBool `json:"activeAttacks"`
	ZeroDay              FlexBool `json:"zeroDay"`
	PublicExploit        FlexBool `json:"publicExploit"`
	EasyExploit          FlexBool `json:"easyExploit"`
	HighLateralMovement  FlexBool `json:"highLateralMovement"`
	HighDataLoss         FlexBool `json:"highDataLoss"`
	NoPatch              FlexBool `json:"noPatch"`
	DenialOfService      FlexBool `json:"denialOfService"`
	Malware              FlexBool `json:"malware"`
	ExploitKit           FlexBool `json:"exploitKit"`
	PublicExploitNames   []string `json:"publicExploitNames"`
	MalwareNames         []string `json:"malwareNames"`
	ExploitKitNames      []string `json:"exploitKitNames"`
	MalwareHashes        []string `json:"malwareHashes"`
	WormableExploit      FlexBool `json:"wormableExploit"`
	PredictedHighRisk    FlexBool `json:"predictedHighRisk"`
	RansomwareExploit    FlexBool `json:"ransomwareExploit"`
	CisaKev              FlexBool `json:"cisaKev"`
	EpssScore            *float64 `json:"epssScore"`
	EpssPercentile       *float64 `json:"epssPercentile"`
	TrendingInTheNews    FlexBool `json:"trendingInTheNews"`
	ThreatActors         []string `json:"threatActors"`
	TrendingSources      []string `json:"trendingSources"`
}

type RTIData struct {
	EasyExploit         bool `json:"easyExploit"`
	NoPatch             bool `json:"noPatch"`
	ActiveAttacks       bool `json:"activeAttacks"`
	HighLateralMovement bool `json:"highLateralMovement"`
	HighDataLoss        bool `json:"highDataLoss"`
	DenialOfService     bool `json:"denialOfService"`
	PublicExploit       bool `json:"publicExploit"`
	Malware             bool `json:"malware"`
	ExploitKit          bool `json:"exploitKit"`
}

type RHSAData struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	CVEs     []string `json:"cves"`
}

type VulnerabilityData struct {
	QID              int              `json:"qid"`
	CVE              string           `json:"cve"`
	CVEIDs           []string         `json:"cveids"`
	Title            string           `json:"title"`
	Description      string           `json:"description"`
	Severity         int              `json:"severity"`
	CustomerSeverity *int             `json:"customerSeverity"`
	CVSSv2Score      FlexFloat        `json:"cvssScore"`
	CVSSv2Vector     string           `json:"cvssVector"`
	CVSSv3Score      float64          `json:"cvssV3Score"`
	CVSSv3Vector     string           `json:"cvssV3Vector"`
	CVSSv3Base       *float64         `json:"cvss3Base"`
	Package          string           `json:"packageName"`
	PackageVersion   string           `json:"currentVersion"`
	FixedVersion     string           `json:"fixedVersion"`
	PackagePath      string           `json:"packagePath"`
	PackageType      string           `json:"packageType"`
	IsPatchable      bool             `json:"isPatchable"`
	IsExempted       bool             `json:"isExempted"`
	FirstFound       UnixMilliTime    `json:"firstFound"`
	LastFound        UnixMilliTime    `json:"lastFound"`
	PublishedDate    UnixMilliTime    `json:"publishedDate"`
	RTI              RTIData          `json:"rti"`
	ThreatIntel      *ThreatIntelData `json:"threatIntel"`
	Port             *int             `json:"port"`
	Protocol         string           `json:"protocol"`
	TypeDetected     string           `json:"typeDetected"`
	Status           string           `json:"status"`
	Risk             FlexString       `json:"risk"`
	Category         string           `json:"category"`
	DiscoveryType    string           `json:"discoveryType"`
	AuthType         string           `json:"authType"`
	SupportedBy      string           `json:"supportedBy"`
	Product          string           `json:"product"`
	Vendor           string           `json:"vendor"`
	RHSA             *RHSAData        `json:"rhsa"`
	QDS              *int             `json:"qds"`
	QDSSeverity      string           `json:"qdsSeverity"`
	LayerSHA         string           `json:"layerSha"`
	SoftwareID       string           `json:"softwareId"`
	ExceptionApplied *bool            `json:"exceptionApplied"`
	ExceptionReason  string           `json:"exceptionReason"`
}

type ContainerListResponse struct {
	Count int             `json:"count"`
	Data  []ContainerData `json:"data"`
}

type ContainerData struct {
	ContainerID            string          `json:"containerId"`
	SHA                    string          `json:"sha"`
	UUID                   string          `json:"uuid"`
	CustomerUUID           string          `json:"customerUuid"`
	Name                   string          `json:"name"`
	ImageID                string          `json:"imageId"`
	ImageSHA               string          `json:"imageSha"`
	ImageUUID              string          `json:"imageUuid"`
	State                  string          `json:"state"`
	Created                UnixMilliTime   `json:"created"`
	Updated                UnixMilliTime   `json:"updated"`
	StateChanged           UnixMilliTime   `json:"stateChanged"`
	LastVmScanDate         UnixMilliTime   `json:"lastVmScanDate"`
	VulnPropagationDate    UnixMilliTime   `json:"vulnPropagationDate"`
	IsRoot                 *bool           `json:"isRoot"`
	IsVulnPropagated       *bool           `json:"isVulnPropagated"`
	Privileged             *bool           `json:"privileged"`
	Host                   *HostInfo       `json:"host"`
	Cluster                *ClusterInfo    `json:"cluster"`
	Severity1Count         int             `json:"severity1Count"`
	Severity2Count         int             `json:"severity2Count"`
	Severity3Count         int             `json:"severity3Count"`
	Severity4Count         int             `json:"severity4Count"`
	Severity5Count         int             `json:"severity5Count"`
	VulnCount              int             `json:"vulnCount"`
	RiskScore              *float64        `json:"riskScore"`
	RiskScoreCalculatedAt  UnixMilliTime   `json:"riskScoreCalculatedDate"`
	FormulaUsed            string          `json:"formulaUsed"`
	MaxQdsScore            *int            `json:"maxQdsScore"`
	QdsSeverity            string          `json:"qdsSeverity"`
	ScanTypes              []string        `json:"scanTypes"`
	Criticality            FlexString      `json:"criticality"`
	Labels                 json.RawMessage `json:"labels"`
	Environment            json.RawMessage `json:"environment"`
	Arguments              json.RawMessage `json:"arguments"`
	Command                string          `json:"command"`
	Entrypoint             string          `json:"entrypoint"`
	Ports                  json.RawMessage `json:"ports"`
	Services               json.RawMessage `json:"services"`
	Vulnerabilities        ImageVulnCounts `json:"vulnerabilities"`
	MalwareCount           *int            `json:"malwareCount"`
	SecretsCount           *int            `json:"secretsCount"`
	SensitiveDataCount     *int            `json:"sensitiveDataCount"`
	CompliancePassedCount  *int            `json:"compliancePassedCount"`
	ComplianceFailedCount  *int            `json:"complianceFailedCount"`
	K8sExposure            json.RawMessage `json:"k8sExposure"`
}

type ContainerDetailResponse struct {
	ContainerID            string              `json:"containerId"`
	SHA                    string              `json:"sha"`
	UUID                   string              `json:"uuid"`
	CustomerUUID           string              `json:"customerUuid"`
	Name                   string              `json:"name"`
	ImageID                string              `json:"imageId"`
	ImageSHA               string              `json:"imageSha"`
	ImageUUID              string              `json:"imageUuid"`
	State                  string              `json:"state"`
	Created                UnixMilliTime       `json:"created"`
	Updated                UnixMilliTime       `json:"updated"`
	StateChanged           UnixMilliTime       `json:"stateChanged"`
	LastVmScanDate         UnixMilliTime       `json:"lastVmScanDate"`
	VulnPropagationDate    UnixMilliTime       `json:"vulnPropagationDate"`
	IsRoot                 *bool               `json:"isRoot"`
	IsVulnPropagated       *bool               `json:"isVulnPropagated"`
	Privileged             *bool               `json:"privileged"`
	Host                   *HostInfo           `json:"host"`
	Cluster                *ClusterInfo        `json:"cluster"`
	RiskScore              *float64            `json:"riskScore"`
	RiskScoreCalculatedAt  UnixMilliTime       `json:"riskScoreCalculatedDate"`
	FormulaUsed            string              `json:"formulaUsed"`
	MaxQdsScore            *int                `json:"maxQdsScore"`
	QdsSeverity            string              `json:"qdsSeverity"`
	ScanTypes              []string            `json:"scanTypes"`
	Criticality            FlexString          `json:"criticality"`
	Labels                 json.RawMessage     `json:"labels"`
	Environment            json.RawMessage     `json:"environment"`
	Arguments              json.RawMessage     `json:"arguments"`
	Command                string              `json:"command"`
	Entrypoint             string              `json:"entrypoint"`
	Ports                  json.RawMessage     `json:"ports"`
	Services               json.RawMessage     `json:"services"`
	Layers                 []LayerData         `json:"layers"`
	Software               []SoftwareData      `json:"softwares"`
	Vulnerabilities        []VulnerabilityData `json:"vulnerabilities"`
	Malware                []MalwareData       `json:"malware"`
	Secrets                []SecretData        `json:"secrets"`
	SensitiveData          []SensitiveData     `json:"sensitiveData"`
	Compliance             json.RawMessage     `json:"compliance"`
	K8sExposure            json.RawMessage     `json:"k8sExposure"`
	AssociatedImage        *AssociationInfo    `json:"associatedImage"`
}

type ListOptions struct {
	PageSize int
	PageNo   int
	Filter   string
	Sort     string
}

type ErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	Details      string `json:"details"`
}

type BulkResponse struct {
	Count   int             `json:"count"`
	Data    json.RawMessage `json:"data"`
	Errors  []ErrorResponse `json:"errors"`
	Status  string          `json:"status"`
	BatchID string          `json:"batchId"`
}
