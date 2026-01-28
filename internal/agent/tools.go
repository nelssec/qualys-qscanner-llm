package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/qualys-qscanner-llm/internal/qualys"
	"github.com/nelssec/qualys-qscanner-llm/internal/qscanner"
	"github.com/nelssec/qualys-qscanner-llm/pkg/models"
)

func isValidSHA(sha string) bool {
	sha = strings.TrimPrefix(sha, "sha256:")
	if len(sha) != 64 {
		return false
	}
	_, err := hex.DecodeString(sha)
	return err == nil
}

type ToolHandler struct {
	qscannerExec *qscanner.Executor
	qualysClient *qualys.Client
	scanCache    map[string]*models.ScanResult
}

func NewToolHandler(qscannerExec *qscanner.Executor, qualysClient *qualys.Client) *ToolHandler {
	return &ToolHandler{
		qscannerExec: qscannerExec,
		qualysClient: qualysClient,
		scanCache:    make(map[string]*models.ScanResult),
	}
}

func (h *ToolHandler) ExecuteTool(ctx context.Context, name string, input json.RawMessage) (string, error) {
	switch name {
	case "qscanner_scan_image":
		return h.scanImage(ctx, input)
	case "qscanner_scan_directory":
		return h.scanDirectory(ctx, input)
	case "qscanner_scan_container":
		return h.scanContainer(ctx, input)
	case "cs_list_images":
		return h.listImages(ctx, input)
	case "cs_get_image_vulnerabilities":
		return h.getImageVulnerabilities(ctx, input)
	case "cs_list_containers":
		return h.listContainers(ctx, input)
	case "cs_get_container_vulnerabilities":
		return h.getContainerVulnerabilities(ctx, input)
	case "analyze_vulnerabilities":
		return h.analyzeVulnerabilities(ctx, input)
	case "get_cve_details":
		return h.getCVEDetails(ctx, input)
	case "get_risk_summary":
		return h.getRiskSummary(ctx, input)
	case "cs_get_runtime_risk":
		return h.getRuntimeRisk(ctx, input)
	case "cs_search_images":
		return h.searchImages(ctx, input)
	case "cs_search_containers":
		return h.searchContainers(ctx, input)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

type scanImageInput struct {
	Image    string   `json:"image"`
	Mode     string   `json:"mode"`
	ScanType []string `json:"scan_type"`
	Platform string   `json:"platform"`
}

func (h *ToolHandler) scanImage(ctx context.Context, input json.RawMessage) (string, error) {
	if h.qscannerExec == nil {
		return "", fmt.Errorf("QScanner binary not configured. Set QSCANNER_PATH to point to the Qualys qscanner binary. For existing image data, use cs_list_images and cs_get_image_vulnerabilities instead")
	}

	var params scanImageInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	opts := qscanner.ScanOptions{
		Image:    params.Image,
		Mode:     params.Mode,
		ScanType: params.ScanType,
		Platform: params.Platform,
	}

	if len(opts.ScanType) == 0 {
		opts.ScanType = []string{"os", "sca"}
	}

	output, err := h.qscannerExec.ScanImage(ctx, opts)
	if err != nil {
		if strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "not found") {
			return "", fmt.Errorf("QScanner binary not available. Use cs_list_images and cs_get_image_vulnerabilities to check existing scan data from the Qualys platform instead of performing new scans")
		}
		return "", err
	}

	result := qscanner.ParseToScanResult(output)
	h.scanCache[result.ID] = result

	return h.formatScanResult(result), nil
}

type scanDirectoryInput struct {
	Path     string   `json:"path"`
	ScanType []string `json:"scan_type"`
}

func (h *ToolHandler) scanDirectory(ctx context.Context, input json.RawMessage) (string, error) {
	if h.qscannerExec == nil {
		return "", fmt.Errorf("QScanner binary not configured. Set QSCANNER_PATH to point to the Qualys qscanner binary")
	}

	var params scanDirectoryInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	opts := qscanner.ScanOptions{
		Path:     params.Path,
		ScanType: params.ScanType,
	}

	if len(opts.ScanType) == 0 {
		opts.ScanType = []string{"sca"}
	}

	output, err := h.qscannerExec.ScanDirectory(ctx, opts)
	if err != nil {
		if strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "not found") {
			return "", fmt.Errorf("QScanner binary error: %v. Ensure QSCANNER_PATH points to the actual Qualys qscanner binary", err)
		}
		return "", err
	}

	result := qscanner.ParseToScanResult(output)
	h.scanCache[result.ID] = result

	return h.formatScanResult(result), nil
}

type scanContainerInput struct {
	ContainerID string `json:"container_id"`
}

func (h *ToolHandler) scanContainer(ctx context.Context, input json.RawMessage) (string, error) {
	if h.qscannerExec == nil {
		return "", fmt.Errorf("QScanner binary not configured. Set QSCANNER_PATH to point to the Qualys qscanner binary. For existing container data, use cs_list_containers instead")
	}

	var params scanContainerInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	opts := qscanner.ScanOptions{
		ContainerID: params.ContainerID,
		ScanType:    []string{"os", "sca"},
	}

	output, err := h.qscannerExec.ScanContainer(ctx, opts)
	if err != nil {
		if strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "not found") {
			return "", fmt.Errorf("QScanner binary error: %v. Ensure QSCANNER_PATH points to the actual Qualys qscanner binary. For existing data, use cs_list_containers instead", err)
		}
		return "", err
	}

	result := qscanner.ParseToScanResult(output)
	h.scanCache[result.ID] = result

	return h.formatScanResult(result), nil
}

type listImagesInput struct {
	PageSize int    `json:"page_size"`
	Filter   string `json:"filter"`
	Sort     string `json:"sort"`
}

func (h *ToolHandler) listImages(ctx context.Context, input json.RawMessage) (string, error) {
	var params listImagesInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	opts := qualys.ListOptions{
		PageSize: params.PageSize,
	}

	images, total, err := h.qualysClient.ListImages(ctx, opts)
	if err != nil {
		return "", err
	}

	return h.formatImageList(images, total), nil
}

type getImageVulnsInput struct {
	ImageSHA string `json:"image_sha"`
}

func (h *ToolHandler) getImageVulnerabilities(ctx context.Context, input json.RawMessage) (string, error) {
	var params getImageVulnsInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	if !isValidSHA(params.ImageSHA) {
		return "", fmt.Errorf("invalid image SHA format: must be 64-character hex string (sha256). Got: %s. Use cs_list_images first to get valid image SHAs", params.ImageSHA)
	}

	image, err := h.qualysClient.GetImage(ctx, params.ImageSHA)
	if err != nil {
		return "", err
	}

	return h.formatImageDetails(image), nil
}

type listContainersInput struct {
	PageSize int    `json:"page_size"`
	Filter   string `json:"filter"`
	Sort     string `json:"sort"`
}

func (h *ToolHandler) listContainers(ctx context.Context, input json.RawMessage) (string, error) {
	var params listContainersInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	opts := qualys.ListOptions{
		PageSize: params.PageSize,
	}

	containers, total, err := h.qualysClient.ListContainers(ctx, opts)
	if err != nil {
		return "", err
	}

	return h.formatContainerList(containers, total), nil
}

type getContainerVulnsInput struct {
	ContainerSHA string `json:"container_sha"`
}

func (h *ToolHandler) getContainerVulnerabilities(ctx context.Context, input json.RawMessage) (string, error) {
	var params getContainerVulnsInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	if !isValidSHA(params.ContainerSHA) {
		return "", fmt.Errorf("invalid container SHA format: must be 64-character hex string (sha256). Got: %s. Use cs_list_containers first to get valid container SHAs", params.ContainerSHA)
	}

	container, err := h.qualysClient.GetContainer(ctx, params.ContainerSHA)
	if err != nil {
		return "", err
	}

	return h.formatContainerDetails(container), nil
}

type analyzeVulnsInput struct {
	Source          string `json:"source"`
	SeverityFilter  string `json:"severity_filter"`
	ExploitableOnly bool   `json:"exploitable_only"`
	Limit           int    `json:"limit"`
}

func (h *ToolHandler) analyzeVulnerabilities(ctx context.Context, input json.RawMessage) (string, error) {
	var params analyzeVulnsInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	var allVulns []models.Vulnerability

	if params.Source == "qscanner" || params.Source == "both" || params.Source == "" {
		for _, result := range h.scanCache {
			allVulns = append(allVulns, result.Vulnerabilities...)
		}
	}

	if params.Source == "qualys_cs" || params.Source == "both" || params.Source == "" {
		images, _, err := h.qualysClient.ListImages(ctx, qualys.ListOptions{PageSize: 100})
		if err == nil {
			for _, img := range images {
				if img.SeverityCounts.Critical > 0 || img.SeverityCounts.High > 0 {
					fullImg, err := h.qualysClient.GetImage(ctx, img.SHA)
					if err == nil {
						allVulns = append(allVulns, fullImg.Vulnerabilities...)
					}
				}
			}
		}
	}

	filteredVulns := h.filterAndPrioritize(allVulns, params.SeverityFilter, params.ExploitableOnly)

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}
	if len(filteredVulns) > limit {
		filteredVulns = filteredVulns[:limit]
	}

	return h.formatVulnerabilityAnalysis(filteredVulns), nil
}

type getCVEInput struct {
	CVEID string `json:"cve_id"`
}

func (h *ToolHandler) getCVEDetails(ctx context.Context, input json.RawMessage) (string, error) {
	var params getCVEInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	cveID := strings.ToUpper(params.CVEID)

	for _, result := range h.scanCache {
		for _, v := range result.Vulnerabilities {
			if strings.EqualFold(v.CVEID, cveID) {
				return h.formatCVEDetails(&v), nil
			}
		}
	}

	images, _, err := h.qualysClient.ListImages(ctx, qualys.ListOptions{PageSize: 50})
	if err == nil {
		for _, img := range images {
			fullImg, err := h.qualysClient.GetImage(ctx, img.SHA)
			if err == nil {
				for _, v := range fullImg.Vulnerabilities {
					if strings.EqualFold(v.CVEID, cveID) {
						return h.formatCVEDetails(&v), nil
					}
				}
			}
		}
	}

	return fmt.Sprintf("CVE %s not found in scanned data. This CVE may not affect your scanned images/containers.", cveID), nil
}

type getRiskSummaryInput struct {
	Source string `json:"source"`
}

func (h *ToolHandler) getRiskSummary(ctx context.Context, input json.RawMessage) (string, error) {
	var params getRiskSummaryInput
	json.Unmarshal(input, &params)

	summary := models.RiskSummary{}
	var allVulns []models.Vulnerability

	if params.Source == "qualys_cs" || params.Source == "both" || params.Source == "" {
		images, total, err := h.qualysClient.ListImages(ctx, qualys.ListOptions{PageSize: 100})
		if err == nil {
			summary.TotalImages = total
			for _, img := range images {
				summary.SeverityCounts.Critical += img.SeverityCounts.Critical
				summary.SeverityCounts.High += img.SeverityCounts.High
				summary.SeverityCounts.Medium += img.SeverityCounts.Medium
				summary.SeverityCounts.Low += img.SeverityCounts.Low
			}
		}

		containers, total, err := h.qualysClient.ListContainers(ctx, qualys.ListOptions{PageSize: 100})
		if err == nil {
			summary.TotalContainers = total
			for _, ctr := range containers {
				sha := ctr.SHA
				if len(sha) > 12 {
					sha = sha[:12]
				}
				allVulns = append(allVulns, models.Vulnerability{
					CVEID:    fmt.Sprintf("container:%s", sha),
					Severity: models.SeverityCritical,
				})
				_ = ctr
			}
		}
	}

	if params.Source == "qscanner" || params.Source == "both" {
		for _, result := range h.scanCache {
			allVulns = append(allVulns, result.Vulnerabilities...)
		}
	}

	summary.TotalVulnerabilities = summary.SeverityCounts.Critical + summary.SeverityCounts.High + summary.SeverityCounts.Medium + summary.SeverityCounts.Low

	prioritized := h.filterAndPrioritize(allVulns, "critical", true)
	if len(prioritized) > 5 {
		prioritized = prioritized[:5]
	}
	summary.TopCVEs = prioritized

	return h.formatRiskSummary(&summary), nil
}

func (h *ToolHandler) filterAndPrioritize(vulns []models.Vulnerability, severityFilter string, exploitableOnly bool) []models.Vulnerability {
	var filtered []models.Vulnerability

	minSeverity := models.SeverityUnknown
	switch severityFilter {
	case "critical":
		minSeverity = models.SeverityCritical
	case "high":
		minSeverity = models.SeverityHigh
	case "medium":
		minSeverity = models.SeverityMedium
	case "low":
		minSeverity = models.SeverityLow
	}

	for _, v := range vulns {
		if v.Severity < minSeverity {
			continue
		}
		if exploitableOnly && !v.IsExploitable {
			continue
		}
		filtered = append(filtered, v)
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Severity != filtered[j].Severity {
			return filtered[i].Severity > filtered[j].Severity
		}
		if filtered[i].IsExploitable != filtered[j].IsExploitable {
			return filtered[i].IsExploitable
		}
		return filtered[i].CVSSv3Score > filtered[j].CVSSv3Score
	})

	return filtered
}

func (h *ToolHandler) formatScanResult(result *models.ScanResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Scan Result: %s\n\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Scan ID:** %s\n", result.ID))
	sb.WriteString(fmt.Sprintf("**Status:** %s\n\n", result.Status))
	sb.WriteString("### Vulnerability Summary\n")
	sb.WriteString(fmt.Sprintf("- Critical: %d\n", result.SeverityCounts.Critical))
	sb.WriteString(fmt.Sprintf("- High: %d\n", result.SeverityCounts.High))
	sb.WriteString(fmt.Sprintf("- Medium: %d\n", result.SeverityCounts.Medium))
	sb.WriteString(fmt.Sprintf("- Low: %d\n\n", result.SeverityCounts.Low))

	if len(result.Vulnerabilities) > 0 {
		sb.WriteString("### Top Vulnerabilities\n")
		count := 10
		if len(result.Vulnerabilities) < count {
			count = len(result.Vulnerabilities)
		}
		for i := 0; i < count; i++ {
			v := result.Vulnerabilities[i]
			sb.WriteString(fmt.Sprintf("- **%s** (%s, CVSS %.1f) - %s", v.CVEID, v.Severity.String(), v.CVSSv3Score, v.Package))
			if v.IsPatchable {
				sb.WriteString(" [FIX AVAILABLE]")
			}
			if v.IsExploitable {
				sb.WriteString(" [EXPLOITABLE]")
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (h *ToolHandler) formatImageList(images []models.Image, total int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Container Images (%d total)\n\n", total))

	for _, img := range images {
		name := img.Name
		if img.Tag != "" {
			name = fmt.Sprintf("%s:%s", img.Name, img.Tag)
		}
		sb.WriteString(fmt.Sprintf("### %s\n", name))
		sb.WriteString(fmt.Sprintf("- **SHA (full):** %s\n", img.SHA))
		sb.WriteString(fmt.Sprintf("- **Registry:** %s\n", img.Registry))
		sb.WriteString(fmt.Sprintf("- **Vulns:** Critical=%d, High=%d, Medium=%d, Low=%d\n\n",
			img.SeverityCounts.Critical, img.SeverityCounts.High, img.SeverityCounts.Medium, img.SeverityCounts.Low))
	}

	return sb.String()
}

func (h *ToolHandler) formatImageDetails(image *models.Image) string {
	var sb strings.Builder
	name := image.Name
	if image.Tag != "" {
		name = fmt.Sprintf("%s:%s", image.Name, image.Tag)
	}
	sb.WriteString(fmt.Sprintf("## Image: %s\n\n", name))
	sb.WriteString(fmt.Sprintf("**SHA:** %s\n", image.SHA))
	sb.WriteString(fmt.Sprintf("**Registry:** %s\n\n", image.Registry))
	sb.WriteString("### Vulnerability Summary\n")
	sb.WriteString(fmt.Sprintf("- Critical: %d\n", image.SeverityCounts.Critical))
	sb.WriteString(fmt.Sprintf("- High: %d\n", image.SeverityCounts.High))
	sb.WriteString(fmt.Sprintf("- Medium: %d\n", image.SeverityCounts.Medium))
	sb.WriteString(fmt.Sprintf("- Low: %d\n\n", image.SeverityCounts.Low))

	if len(image.Vulnerabilities) > 0 {
		sb.WriteString("### Vulnerabilities\n")
		for _, v := range image.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("- **%s** (%s, CVSS %.1f)\n", v.CVEID, v.Severity.String(), v.CVSSv3Score))
			sb.WriteString(fmt.Sprintf("  - Package: %s %s\n", v.Package, v.PackageVersion))
			if v.FixedVersion != "" {
				sb.WriteString(fmt.Sprintf("  - Fix: Upgrade to %s\n", v.FixedVersion))
			}
			if v.IsExploitable {
				sb.WriteString("  - [!] Known exploit exists\n")
			}
		}
	}

	return sb.String()
}

func (h *ToolHandler) formatContainerList(containers []models.Container, total int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Containers (%d total)\n\n", total))

	for _, ctr := range containers {
		sb.WriteString(fmt.Sprintf("### %s\n", ctr.Name))
		sb.WriteString(fmt.Sprintf("- **SHA (full):** %s\n", ctr.SHA))
		sb.WriteString(fmt.Sprintf("- **State:** %s\n", ctr.State))
		sb.WriteString(fmt.Sprintf("- **Image SHA:** %s\n", ctr.ImageSHA))
		sb.WriteString(fmt.Sprintf("- **Vulns:** Critical=%d, High=%d, Medium=%d, Low=%d\n\n",
			ctr.SeverityCounts.Critical, ctr.SeverityCounts.High, ctr.SeverityCounts.Medium, ctr.SeverityCounts.Low))
	}

	return sb.String()
}

func (h *ToolHandler) formatContainerDetails(container *models.Container) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Container: %s\n\n", container.Name))
	sb.WriteString(fmt.Sprintf("**SHA:** %s\n", container.SHA))
	sb.WriteString(fmt.Sprintf("**State:** %s\n", container.State))
	sb.WriteString(fmt.Sprintf("**Image SHA:** %s\n\n", container.ImageSHA))
	sb.WriteString("### Vulnerability Summary\n")
	sb.WriteString(fmt.Sprintf("- Critical: %d\n", container.SeverityCounts.Critical))
	sb.WriteString(fmt.Sprintf("- High: %d\n", container.SeverityCounts.High))
	sb.WriteString(fmt.Sprintf("- Medium: %d\n", container.SeverityCounts.Medium))
	sb.WriteString(fmt.Sprintf("- Low: %d\n\n", container.SeverityCounts.Low))

	if len(container.Vulnerabilities) > 0 {
		sb.WriteString("### Vulnerabilities\n")
		for _, v := range container.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("- **%s** (%s, CVSS %.1f) - %s\n", v.CVEID, v.Severity.String(), v.CVSSv3Score, v.Package))
		}
	}

	return sb.String()
}

func (h *ToolHandler) formatVulnerabilityAnalysis(vulns []models.Vulnerability) string {
	var sb strings.Builder
	sb.WriteString("## Vulnerability Analysis (Prioritized)\n\n")

	if len(vulns) == 0 {
		sb.WriteString("No vulnerabilities found matching the criteria.\n")
		return sb.String()
	}

	for i, v := range vulns {
		sb.WriteString(fmt.Sprintf("### %d. %s\n", i+1, v.CVEID))
		sb.WriteString(fmt.Sprintf("- **Severity:** %s (CVSS %.1f)\n", v.Severity.String(), v.CVSSv3Score))
		sb.WriteString(fmt.Sprintf("- **Package:** %s %s\n", v.Package, v.PackageVersion))
		if v.IsExploitable {
			sb.WriteString("- **[!] EXPLOITABLE:** Known exploit or active attacks\n")
		}
		if v.IsPatchable {
			sb.WriteString(fmt.Sprintf("- **Fix Available:** Upgrade to %s\n", v.FixedVersion))
		} else {
			sb.WriteString("- **No patch available** - Consider mitigation controls\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func (h *ToolHandler) formatCVEDetails(v *models.Vulnerability) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## %s\n\n", v.CVEID))
	sb.WriteString(fmt.Sprintf("**Title:** %s\n", v.Title))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", v.Severity.String()))
	sb.WriteString(fmt.Sprintf("**CVSS v3 Score:** %.1f\n", v.CVSSv3Score))
	if v.CVSSv3Vector != "" {
		sb.WriteString(fmt.Sprintf("**CVSS Vector:** %s\n", v.CVSSv3Vector))
	}
	sb.WriteString(fmt.Sprintf("**Affected Package:** %s %s\n", v.Package, v.PackageVersion))

	sb.WriteString("\n### Risk Factors\n")
	if v.IsExploitable {
		sb.WriteString("- [!] Known exploit or active attacks in the wild\n")
	}
	if v.IsPatchable {
		sb.WriteString(fmt.Sprintf("- [+] Patch available: Upgrade to %s\n", v.FixedVersion))
	} else {
		sb.WriteString("- [-] No patch currently available\n")
	}

	sb.WriteString("\n### Remediation\n")
	if v.IsPatchable {
		sb.WriteString(fmt.Sprintf("Update %s to version %s or later.\n", v.Package, v.FixedVersion))
	} else {
		sb.WriteString("No patch available. Consider:\n")
		sb.WriteString("- Network segmentation to limit exposure\n")
		sb.WriteString("- Web Application Firewall (WAF) rules\n")
		sb.WriteString("- Monitoring for exploitation attempts\n")
	}

	return sb.String()
}

func (h *ToolHandler) formatRiskSummary(summary *models.RiskSummary) string {
	var sb strings.Builder
	sb.WriteString("## Security Risk Summary\n\n")

	sb.WriteString("### Asset Inventory\n")
	sb.WriteString(fmt.Sprintf("- Total Images: %d\n", summary.TotalImages))
	sb.WriteString(fmt.Sprintf("- Total Containers: %d\n\n", summary.TotalContainers))

	sb.WriteString("### Vulnerability Breakdown\n")
	sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", summary.SeverityCounts.Critical))
	sb.WriteString(fmt.Sprintf("- **High:** %d\n", summary.SeverityCounts.High))
	sb.WriteString(fmt.Sprintf("- **Medium:** %d\n", summary.SeverityCounts.Medium))
	sb.WriteString(fmt.Sprintf("- **Low:** %d\n", summary.SeverityCounts.Low))
	sb.WriteString(fmt.Sprintf("- **Total:** %d\n\n", summary.TotalVulnerabilities))

	if len(summary.TopCVEs) > 0 {
		sb.WriteString("### Top Priority CVEs\n")
		for _, v := range summary.TopCVEs {
			sb.WriteString(fmt.Sprintf("- **%s** (%s, CVSS %.1f)", v.CVEID, v.Severity.String(), v.CVSSv3Score))
			if v.IsExploitable {
				sb.WriteString(" [EXPLOITABLE]")
			}
			sb.WriteString("\n")
		}
	}

	riskLevel := "Low"
	if summary.SeverityCounts.Critical > 0 {
		riskLevel = "Critical"
	} else if summary.SeverityCounts.High > 5 {
		riskLevel = "High"
	} else if summary.SeverityCounts.High > 0 {
		riskLevel = "Medium"
	}

	sb.WriteString(fmt.Sprintf("\n### Overall Risk Level: **%s**\n", riskLevel))

	return sb.String()
}

type runtimeRiskInput struct {
	State          string `json:"state"`
	SeverityFilter string `json:"severity_filter"`
}

func (h *ToolHandler) getRuntimeRisk(ctx context.Context, input json.RawMessage) (string, error) {
	var params runtimeRiskInput
	json.Unmarshal(input, &params)

	if params.State == "" {
		params.State = "RUNNING"
	}

	containers, totalContainers, err := h.qualysClient.ListContainersRaw(ctx, qualys.ListOptions{PageSize: 1000})
	if err != nil {
		return "", err
	}

	images, _, err := h.qualysClient.ListImagesRaw(ctx, qualys.ListOptions{PageSize: 500})
	if err != nil {
		return "", err
	}

	imageVulnsByUUID := make(map[string]models.SeverityCounts)
	imageNamesByUUID := make(map[string]string)
	for _, img := range images {
		uuid := img.UUID
		if uuid == "" {
			continue
		}
		counts := models.SeverityCounts{}
		if img.Vulnerabilities.Severity5Count != nil {
			counts.Critical = *img.Vulnerabilities.Severity5Count
		}
		if img.Vulnerabilities.Severity4Count != nil {
			counts.High = *img.Vulnerabilities.Severity4Count
		}
		if img.Vulnerabilities.Severity3Count != nil {
			counts.Medium = *img.Vulnerabilities.Severity3Count
		}
		if img.Vulnerabilities.Severity2Count != nil {
			counts.Low = *img.Vulnerabilities.Severity2Count
		}
		imageVulnsByUUID[uuid] = counts

		imageName := ""
		if len(img.Repo) > 0 {
			imageName = img.Repo[0].Repository
			if img.Repo[0].Tag != "" {
				imageName = imageName + ":" + img.Repo[0].Tag
			}
		}
		imageNamesByUUID[uuid] = imageName
	}

	type containerRisk struct {
		Name     string
		State    string
		ImageSHA string
		Image    string
		Vulns    models.SeverityCounts
	}

	var riskContainers []containerRisk
	sev5Containers := 0
	sev4Containers := 0
	sev3Containers := 0
	runningCount := 0

	for _, ctr := range containers {
		if params.State != "" && ctr.State != params.State {
			continue
		}
		runningCount++

		vulns, hasImage := imageVulnsByUUID[ctr.ImageUUID]
		if !hasImage {
			continue
		}

		if vulns.Critical > 0 || vulns.High > 0 || vulns.Medium > 0 {
			imgName := imageNamesByUUID[ctr.ImageUUID]
			if imgName == "" {
				imgName = ctr.ImageUUID
				if len(imgName) > 12 {
					imgName = imgName[:12]
				}
			}
			riskContainers = append(riskContainers, containerRisk{
				Name:     ctr.Name,
				State:    ctr.State,
				ImageSHA: ctr.ImageUUID,
				Image:    imgName,
				Vulns:    vulns,
			})

			if vulns.Critical > 0 {
				sev5Containers++
			}
			if vulns.High > 0 {
				sev4Containers++
			}
			if vulns.Medium > 0 {
				sev3Containers++
			}
		}
	}

	sort.Slice(riskContainers, func(i, j int) bool {
		if riskContainers[i].Vulns.Critical != riskContainers[j].Vulns.Critical {
			return riskContainers[i].Vulns.Critical > riskContainers[j].Vulns.Critical
		}
		return riskContainers[i].Vulns.High > riskContainers[j].Vulns.High
	})

	var sb strings.Builder
	sb.WriteString("## Runtime Environment Risk Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Total Containers:** %d\n", totalContainers))
	sb.WriteString(fmt.Sprintf("**%s Containers:** %d\n\n", params.State, runningCount))

	sb.WriteString("### Containers by Image Vulnerability Severity\n")
	sb.WriteString(fmt.Sprintf("- **Critical (Severity 5):** %d containers\n", sev5Containers))
	sb.WriteString(fmt.Sprintf("- **High (Severity 4):** %d containers\n", sev4Containers))
	sb.WriteString(fmt.Sprintf("- **Medium (Severity 3):** %d containers\n\n", sev3Containers))

	if len(riskContainers) > 0 {
		sb.WriteString("### Top Risk Containers (by image vulnerabilities)\n\n")
		limit := 20
		if len(riskContainers) < limit {
			limit = len(riskContainers)
		}
		for i := 0; i < limit; i++ {
			rc := riskContainers[i]
			sb.WriteString(fmt.Sprintf("**%d. %s**\n", i+1, rc.Name))
			sb.WriteString(fmt.Sprintf("   - Image: %s\n", rc.Image))
			sb.WriteString(fmt.Sprintf("   - Critical: %d, High: %d, Medium: %d, Low: %d\n\n",
				rc.Vulns.Critical, rc.Vulns.High, rc.Vulns.Medium, rc.Vulns.Low))
		}
	} else {
		sb.WriteString("No containers found running vulnerable images.\n")
	}

	return sb.String(), nil
}

type searchImagesInput struct {
	Product  string `json:"product"`
	CVE      string `json:"cve"`
	Severity int    `json:"severity"`
	Filter   string `json:"filter"`
	PageSize int    `json:"page_size"`
}

func (h *ToolHandler) searchImages(ctx context.Context, input json.RawMessage) (string, error) {
	var params searchImagesInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	filter := params.Filter
	if filter == "" {
		var parts []string
		if params.Product != "" {
			parts = append(parts, fmt.Sprintf("vulnerabilities.product:%s", params.Product))
		}
		if params.CVE != "" {
			parts = append(parts, fmt.Sprintf("vulnerabilities.cveids:%s", params.CVE))
		}
		if params.Severity > 0 {
			parts = append(parts, fmt.Sprintf("vulnerabilities.severity:%d", params.Severity))
		}
		if len(parts) > 0 {
			filter = strings.Join(parts, " and ")
		}
	}

	if filter == "" {
		return "", fmt.Errorf("at least one search parameter required: product, cve, severity, or filter")
	}

	pageSize := params.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	images, total, err := h.qualysClient.SearchImages(ctx, filter, pageSize)
	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Image Search Results\n\n"))
	sb.WriteString(fmt.Sprintf("**Filter:** `%s`\n", filter))
	sb.WriteString(fmt.Sprintf("**Found:** %d images\n\n", total))

	if len(images) == 0 {
		sb.WriteString("No images found matching the search criteria.\n")
		return sb.String(), nil
	}

	for i, img := range images {
		if i >= 50 {
			sb.WriteString(fmt.Sprintf("\n... and %d more images\n", total-50))
			break
		}

		name := "unknown"
		if len(img.Repo) > 0 {
			name = img.Repo[0].Repository
			if img.Repo[0].Tag != "" {
				name = name + ":" + img.Repo[0].Tag
			}
		}

		counts := ""
		if img.Vulnerabilities.Severity5Count != nil && *img.Vulnerabilities.Severity5Count > 0 {
			counts += fmt.Sprintf("Critical=%d ", *img.Vulnerabilities.Severity5Count)
		}
		if img.Vulnerabilities.Severity4Count != nil && *img.Vulnerabilities.Severity4Count > 0 {
			counts += fmt.Sprintf("High=%d ", *img.Vulnerabilities.Severity4Count)
		}
		if img.Vulnerabilities.Severity3Count != nil && *img.Vulnerabilities.Severity3Count > 0 {
			counts += fmt.Sprintf("Medium=%d ", *img.Vulnerabilities.Severity3Count)
		}

		sb.WriteString(fmt.Sprintf("**%d. %s**\n", i+1, name))
		sb.WriteString(fmt.Sprintf("   - SHA: %s\n", img.SHA))
		if counts != "" {
			sb.WriteString(fmt.Sprintf("   - Vulns: %s\n", counts))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

type searchContainersInput struct {
	Product  string `json:"product"`
	CVE      string `json:"cve"`
	Severity int    `json:"severity"`
	State    string `json:"state"`
	Filter   string `json:"filter"`
	PageSize int    `json:"page_size"`
}

func (h *ToolHandler) searchContainers(ctx context.Context, input json.RawMessage) (string, error) {
	var params searchContainersInput
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid input: %w", err)
	}

	filter := params.Filter
	if filter == "" {
		var parts []string
		if params.State != "" {
			parts = append(parts, fmt.Sprintf("state:%s", params.State))
		}
		if params.Product != "" {
			parts = append(parts, fmt.Sprintf("vulnerabilities.product:%s", params.Product))
		}
		if params.CVE != "" {
			parts = append(parts, fmt.Sprintf("vulnerabilities.cveids:%s", params.CVE))
		}
		if params.Severity > 0 {
			parts = append(parts, fmt.Sprintf("vulnerabilities.severity:%d", params.Severity))
		}
		if len(parts) > 0 {
			filter = strings.Join(parts, " and ")
		}
	}

	if filter == "" {
		return "", fmt.Errorf("at least one search parameter required: product, cve, severity, state, or filter")
	}

	pageSize := params.PageSize
	if pageSize <= 0 {
		pageSize = 100
	}

	containers, total, err := h.qualysClient.SearchContainers(ctx, filter, pageSize)
	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## Container Search Results\n\n"))
	sb.WriteString(fmt.Sprintf("**Filter:** `%s`\n", filter))
	sb.WriteString(fmt.Sprintf("**Found:** %d containers\n\n", total))

	if len(containers) == 0 {
		sb.WriteString("No containers found matching the search criteria.\n")
		return sb.String(), nil
	}

	for i, ctr := range containers {
		if i >= 50 {
			sb.WriteString(fmt.Sprintf("\n... and %d more containers\n", total-50))
			break
		}

		counts := ""
		if ctr.Vulnerabilities.Severity5Count != nil && *ctr.Vulnerabilities.Severity5Count > 0 {
			counts += fmt.Sprintf("Critical=%d ", *ctr.Vulnerabilities.Severity5Count)
		}
		if ctr.Vulnerabilities.Severity4Count != nil && *ctr.Vulnerabilities.Severity4Count > 0 {
			counts += fmt.Sprintf("High=%d ", *ctr.Vulnerabilities.Severity4Count)
		}
		if ctr.Vulnerabilities.Severity3Count != nil && *ctr.Vulnerabilities.Severity3Count > 0 {
			counts += fmt.Sprintf("Medium=%d ", *ctr.Vulnerabilities.Severity3Count)
		}

		sb.WriteString(fmt.Sprintf("**%d. %s**\n", i+1, ctr.Name))
		sb.WriteString(fmt.Sprintf("   - State: %s\n", ctr.State))
		sb.WriteString(fmt.Sprintf("   - SHA: %s\n", ctr.SHA))
		if counts != "" {
			sb.WriteString(fmt.Sprintf("   - Vulns: %s\n", counts))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}
