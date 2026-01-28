package qualys

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/nelssec/qualys-qscanner-llm/config"
	"github.com/nelssec/qualys-qscanner-llm/pkg/models"
	"github.com/rs/zerolog"
)

type Client struct {
	httpClient *AuthenticatedClient
	logger     zerolog.Logger
}

func NewClient(cfg *config.Config, logger zerolog.Logger) *Client {
	tokenManager := NewTokenManager(cfg.QualysAPIURL, cfg)
	httpClient := NewAuthenticatedClient(cfg.QualysAPIURL, tokenManager)

	return &Client{
		httpClient: httpClient,
		logger:     logger,
	}
}

func (c *Client) ListImages(ctx context.Context, opts ListOptions) ([]models.Image, int, error) {
	path := c.buildPath("/csapi/v1.3/images", opts)

	c.logger.Debug().Str("path", path).Msg("listing images from Qualys CS API")

	var resp ImageListResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, 0, fmt.Errorf("failed to list images: %w", err)
	}

	images := make([]models.Image, 0, len(resp.Data))
	for _, img := range resp.Data {
		images = append(images, convertImage(img))
	}

	return images, resp.Count, nil
}

func (c *Client) GetImage(ctx context.Context, imageSHA string) (*models.Image, error) {
	path := fmt.Sprintf("/csapi/v1.3/images/%s", url.PathEscape(imageSHA))

	c.logger.Debug().Str("sha", imageSHA).Msg("getting image details from Qualys CS API")

	var resp ImageDetailResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("failed to get image: %w", err)
	}

	image := convertImageDetail(resp)
	return &image, nil
}

func (c *Client) ListContainers(ctx context.Context, opts ListOptions) ([]models.Container, int, error) {
	path := c.buildPath("/csapi/v1.3/containers", opts)

	c.logger.Debug().Str("path", path).Msg("listing containers from Qualys CS API")

	var resp ContainerListResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, 0, fmt.Errorf("failed to list containers: %w", err)
	}

	containers := make([]models.Container, 0, len(resp.Data))
	for _, ctr := range resp.Data {
		containers = append(containers, convertContainer(ctr))
	}

	return containers, resp.Count, nil
}

func (c *Client) ListContainersRaw(ctx context.Context, opts ListOptions) ([]ContainerData, int, error) {
	path := c.buildPath("/csapi/v1.3/containers", opts)

	c.logger.Debug().Str("path", path).Msg("listing containers (raw) from Qualys CS API")

	var resp ContainerListResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, 0, fmt.Errorf("failed to list containers: %w", err)
	}

	return resp.Data, resp.Count, nil
}

func (c *Client) ListImagesRaw(ctx context.Context, opts ListOptions) ([]ImageData, int, error) {
	path := c.buildPath("/csapi/v1.3/images", opts)

	c.logger.Debug().Str("path", path).Msg("listing images (raw) from Qualys CS API")

	var resp ImageListResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, 0, fmt.Errorf("failed to list images: %w", err)
	}

	return resp.Data, resp.Count, nil
}

func (c *Client) GetContainer(ctx context.Context, containerSHA string) (*models.Container, error) {
	path := fmt.Sprintf("/csapi/v1.3/containers/%s", url.PathEscape(containerSHA))

	c.logger.Debug().Str("sha", containerSHA).Msg("getting container details from Qualys CS API")

	var resp ContainerDetailResponse
	if err := c.httpClient.GetJSON(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("failed to get container: %w", err)
	}

	container := convertContainerDetail(resp)
	return &container, nil
}

func (c *Client) buildPath(base string, opts ListOptions) string {
	params := url.Values{}

	if opts.PageSize > 0 {
		params.Set("pageSize", strconv.Itoa(opts.PageSize))
	} else {
		params.Set("pageSize", "200")
	}

	if opts.PageNo > 0 {
		params.Set("pageNo", strconv.Itoa(opts.PageNo))
	}

	if opts.Filter != "" {
		params.Set("filter", opts.Filter)
	}

	if len(params) > 0 {
		return fmt.Sprintf("%s?%s", base, params.Encode())
	}
	return base
}

func (c *Client) SearchImages(ctx context.Context, filter string, pageSize int) ([]ImageData, int, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	opts := ListOptions{
		PageSize: pageSize,
		Filter:   filter,
	}
	return c.ListImagesRaw(ctx, opts)
}

func (c *Client) SearchContainers(ctx context.Context, filter string, pageSize int) ([]ContainerData, int, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	opts := ListOptions{
		PageSize: pageSize,
		Filter:   filter,
	}
	return c.ListContainersRaw(ctx, opts)
}

func convertImage(img ImageData) models.Image {
	var name, tag, registry string
	if len(img.Repo) > 0 {
		name = img.Repo[0].Repository
		tag = img.Repo[0].Tag
		registry = img.Repo[0].Registry
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
	if img.Vulnerabilities.Severity1Count != nil {
		counts.Info = *img.Vulnerabilities.Severity1Count
	}

	return models.Image{
		SHA:            img.SHA,
		Name:           name,
		Tag:            tag,
		Registry:       registry,
		Created:        img.Created.Time,
		Updated:        img.Updated.Time,
		SeverityCounts: counts,
	}
}

func convertImageDetail(resp ImageDetailResponse) models.Image {
	vulns := make([]models.Vulnerability, 0, len(resp.Vulnerabilities))
	counts := models.SeverityCounts{}

	for _, v := range resp.Vulnerabilities {
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

		vulns = append(vulns, models.Vulnerability{
			CVEID:          v.CVE,
			QID:            v.QID,
			Title:          v.Title,
			Severity:       severity,
			CVSSv3Score:    v.CVSSv3Score,
			CVSSv3Vector:   v.CVSSv3Vector,
			Package:        v.Package,
			PackageVersion: v.PackageVersion,
			FixedVersion:   v.FixedVersion,
			IsPatchable:    v.IsPatchable,
			IsExploitable:  isExploitable(v),
			Source:         "qualys_cs",
		})
	}

	var name, tag, registry string
	if len(resp.Repo) > 0 {
		name = resp.Repo[0].Repository
		tag = resp.Repo[0].Tag
		registry = resp.Repo[0].Registry
	}
	if registry == "" {
		registry = resp.Registry
	}
	if tag == "" {
		tag = resp.Tag
	}

	return models.Image{
		SHA:             resp.SHA,
		Name:            name,
		Tag:             tag,
		Registry:        registry,
		Created:         resp.Created.Time,
		Updated:         resp.Updated.Time,
		SeverityCounts:  counts,
		Vulnerabilities: vulns,
	}
}

func convertContainer(ctr ContainerData) models.Container {
	counts := models.SeverityCounts{}
	if ctr.Vulnerabilities.Severity5Count != nil {
		counts.Critical = *ctr.Vulnerabilities.Severity5Count
	}
	if ctr.Vulnerabilities.Severity4Count != nil {
		counts.High = *ctr.Vulnerabilities.Severity4Count
	}
	if ctr.Vulnerabilities.Severity3Count != nil {
		counts.Medium = *ctr.Vulnerabilities.Severity3Count
	}
	if ctr.Vulnerabilities.Severity2Count != nil {
		counts.Low = *ctr.Vulnerabilities.Severity2Count
	}
	if ctr.Vulnerabilities.Severity1Count != nil {
		counts.Info = *ctr.Vulnerabilities.Severity1Count
	}

	return models.Container{
		SHA:            ctr.SHA,
		Name:           ctr.Name,
		ImageSHA:       ctr.ImageSHA,
		State:          ctr.State,
		Created:        ctr.Created.Time,
		Updated:        ctr.Updated.Time,
		SeverityCounts: counts,
	}
}

func convertContainerDetail(resp ContainerDetailResponse) models.Container {
	vulns := make([]models.Vulnerability, 0, len(resp.Vulnerabilities))
	counts := models.SeverityCounts{}

	for _, v := range resp.Vulnerabilities {
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

		vulns = append(vulns, models.Vulnerability{
			CVEID:          v.CVE,
			QID:            v.QID,
			Title:          v.Title,
			Severity:       severity,
			CVSSv3Score:    v.CVSSv3Score,
			CVSSv3Vector:   v.CVSSv3Vector,
			Package:        v.Package,
			PackageVersion: v.PackageVersion,
			FixedVersion:   v.FixedVersion,
			IsPatchable:    v.IsPatchable,
			IsExploitable:  isExploitable(v),
			Source:         "qualys_cs",
		})
	}

	return models.Container{
		SHA:             resp.SHA,
		Name:            resp.Name,
		ImageSHA:        resp.ImageSHA,
		State:           resp.State,
		Created:         resp.Created.Time,
		Updated:         resp.Updated.Time,
		SeverityCounts:  counts,
		Vulnerabilities: vulns,
	}
}

func severityFromInt(s int) models.Severity {
	switch s {
	case 1, 2:
		return models.SeverityLow
	case 3:
		return models.SeverityMedium
	case 4:
		return models.SeverityHigh
	case 5:
		return models.SeverityCritical
	default:
		return models.SeverityUnknown
	}
}

func isExploitable(v VulnerabilityData) bool {
	if v.RTI.EasyExploit || v.RTI.ActiveAttacks || v.RTI.PublicExploit {
		return true
	}
	if v.ThreatIntel != nil {
		if v.ThreatIntel.EasyExploit.Value || v.ThreatIntel.ActiveAttacks.Value ||
			v.ThreatIntel.PublicExploit.Value || v.ThreatIntel.CisaKev.Value {
			return true
		}
	}
	return false
}
