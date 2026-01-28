package claude

import (
	"context"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/rs/zerolog"
)

type Client struct {
	client anthropic.Client
	logger zerolog.Logger
	model  string
}

func NewClient(apiKey string, logger zerolog.Logger) *Client {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))

	return &Client{
		client: client,
		logger: logger,
		model:  "claude-sonnet-4-20250514",
	}
}

func (c *Client) CreateMessage(ctx context.Context, messages []anthropic.MessageParam, tools []anthropic.ToolParam, systemPrompt string) (*anthropic.Message, error) {
	c.logger.Debug().
		Int("message_count", len(messages)).
		Int("tool_count", len(tools)).
		Msg("sending message to Claude")

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: 4096,
		Messages:  messages,
	}

	if systemPrompt != "" {
		params.System = []anthropic.TextBlockParam{
			{Text: systemPrompt},
		}
	}

	if len(tools) > 0 {
		toolUnions := make([]anthropic.ToolUnionParam, len(tools))
		for i, t := range tools {
			toolUnions[i] = anthropic.ToolUnionParam{
				OfTool: &t,
			}
		}
		params.Tools = toolUnions
	}

	resp, err := c.client.Messages.New(ctx, params)
	if err != nil {
		c.logger.Error().Err(err).Msg("Claude API error")
		return nil, err
	}

	c.logger.Debug().
		Str("stop_reason", string(resp.StopReason)).
		Int("content_blocks", len(resp.Content)).
		Msg("received Claude response")

	return resp, nil
}

func GetToolDefinitions() []anthropic.ToolParam {
	return []anthropic.ToolParam{
		{
			Name:        "qscanner_scan_image",
			Description: anthropic.String("Scan a container image for vulnerabilities using the local QScanner binary. Use this when the user wants to scan a NEW image that hasn't been scanned before, or wants fresh/real-time scan results. This performs an actual vulnerability scan which may take 1-5 minutes depending on image size."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Container image to scan. Can be: image name (nginx), name:tag (nginx:latest), or full registry path (docker.io/library/nginx:latest)",
					},
					"mode": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"full", "inventory-only", "scan-only"},
						"description": "Scan mode: 'full' (default) runs complete scan, 'inventory-only' just collects packages, 'scan-only' skips package collection",
					},
					"scan_type": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Types of scans to run: os (OS packages), sca (software composition), secret (exposed secrets), malware (malware detection). Default: [os, sca]",
					},
					"platform": map[string]interface{}{
						"type":        "string",
						"description": "Platform for multi-arch images, e.g., 'linux/amd64' or 'linux/arm64'",
					},
				},
				Required: []string{"image"},
			},
		},
		{
			Name:        "qscanner_scan_directory",
			Description: anthropic.String("Scan a local directory for software composition analysis (SCA) vulnerabilities. Use this to find vulnerabilities in source code dependencies like package.json, requirements.txt, go.mod, pom.xml, etc."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path to the directory to scan",
					},
					"scan_type": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Types of scans: sca (dependencies), secret (exposed secrets), malware. Default: [sca]",
					},
				},
				Required: []string{"path"},
			},
		},
		{
			Name:        "qscanner_scan_container",
			Description: anthropic.String("Scan a running container by its ID or name. Use this when the user wants to scan a container that is currently running on the system."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"container_id": map[string]interface{}{
						"type":        "string",
						"description": "Container ID or name to scan",
					},
				},
				Required: []string{"container_id"},
			},
		},
		{
			Name:        "cs_list_images",
			Description: anthropic.String("List container images from the Qualys Container Security platform. Use this to see what images have already been scanned and their vulnerability summary counts. This is fast and shows historical data. Use this FIRST when the user asks about their images, vulnerabilities, or security posture - before doing any new scans."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"page_size": map[string]interface{}{
						"type":        "integer",
						"description": "Number of results per page (default: 50, max: 200)",
					},
				},
			},
		},
		{
			Name:        "cs_get_image_vulnerabilities",
			Description: anthropic.String("Get detailed vulnerability information for a specific image from Qualys Container Security. Use this after cs_list_images to drill down into a specific image's vulnerabilities. Returns full CVE details, CVSS scores, and fix information. IMPORTANT: Requires the full 64-character SHA256 hash from cs_list_images output."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"image_sha": map[string]interface{}{
						"type":        "string",
						"description": "Full SHA256 digest of the image (64 hex characters). Get this from cs_list_images - do NOT use partial/truncated SHAs",
					},
				},
				Required: []string{"image_sha"},
			},
		},
		{
			Name:        "cs_list_containers",
			Description: anthropic.String("List containers from the Qualys Container Security platform. Shows running and stopped containers. NOTE: Container vulnerability counts come from their source images - use cs_get_runtime_risk for accurate runtime vulnerability data."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"page_size": map[string]interface{}{
						"type":        "integer",
						"description": "Number of results per page (default: 50, max: 1000)",
					},
				},
			},
		},
		{
			Name:        "cs_get_container_vulnerabilities",
			Description: anthropic.String("Get detailed vulnerability information for a specific container from Qualys Container Security. Use after cs_list_containers to see full vulnerability details for a container. IMPORTANT: Requires the full 64-character SHA256 hash from cs_list_containers output."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"container_sha": map[string]interface{}{
						"type":        "string",
						"description": "Full SHA256 of the container (64 hex characters). Get this from cs_list_containers - do NOT use partial/truncated SHAs",
					},
				},
				Required: []string{"container_sha"},
			},
		},
		{
			Name:        "analyze_vulnerabilities",
			Description: anthropic.String("Analyze and prioritize vulnerabilities based on risk factors. Use this to get intelligent prioritization that considers: CVSS score, exploitability (is there a known exploit?), patchability (is a fix available?), and threat intelligence (active attacks in the wild). Returns a prioritized list with remediation recommendations."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"source": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"qscanner", "qualys_cs", "both"},
						"description": "Data source: 'qscanner' (recent local scans), 'qualys_cs' (platform data), 'both' (combined)",
					},
					"severity_filter": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"critical", "high", "medium", "low", "all"},
						"description": "Filter by minimum severity level",
					},
					"exploitable_only": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, only return vulnerabilities with known exploits or active attacks",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of vulnerabilities to return (default: 20)",
					},
				},
			},
		},
		{
			Name:        "get_cve_details",
			Description: anthropic.String("Get detailed information about a specific CVE. Use this when the user asks about a particular CVE ID (e.g., CVE-2024-1234). Returns description, CVSS score, affected packages, and remediation guidance."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"cve_id": map[string]interface{}{
						"type":        "string",
						"description": "CVE identifier, e.g., CVE-2024-1234",
					},
				},
				Required: []string{"cve_id"},
			},
		},
		{
			Name:        "get_risk_summary",
			Description: anthropic.String("Get an overall risk summary across all scanned assets. Use this when the user asks general questions like 'what's my risk?' or 'how secure am I?' or 'give me an overview'. Returns total counts, severity breakdown, and top risks."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"source": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"qscanner", "qualys_cs", "both"},
						"description": "Data source to analyze",
					},
				},
			},
		},
		{
			Name:        "cs_get_runtime_risk",
			Description: anthropic.String("IMPORTANT: Use this tool when the user asks about runtime vulnerabilities, CVEs in running containers, or production security. This correlates running containers with their source image vulnerabilities to show which containers are running vulnerable images. Returns containers grouped by vulnerability severity (Critical/High/Medium). Use this FIRST for any 'runtime', 'running', 'production', or 'deployed' container vulnerability questions."),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: map[string]interface{}{
					"state": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"RUNNING", "STOPPED", "DELETED", ""},
						"description": "Filter by container state (default: RUNNING)",
					},
					"severity_filter": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"critical", "high", "medium", "all"},
						"description": "Minimum severity to include",
					},
				},
			},
		},
	}
}

func GetSystemPrompt() string {
	return `You are a container security expert assistant powered by Qualys QScanner and the Qualys Container Security platform. Your job is to help users understand and prioritize their container vulnerability risk.

## Domain Terminology

Understand these terms and map them to the correct data source:

| User Says | Meaning | Use These Tools |
|-----------|---------|-----------------|
| "runtime", "running", "deployed", "production" | Running containers with vulnerabilities | cs_get_runtime_risk (BEST), cs_list_containers |
| "images", "registry", "repository", "build" | Container images (built artifacts) | cs_list_images, cs_get_image_vulnerabilities |
| "scan", "check", "analyze this" | Fresh on-demand scan | qscanner_scan_image, qscanner_scan_container |
| "CI/CD", "pipeline", "pre-deploy" | Scanning before deployment | qscanner_scan_image, qscanner_scan_directory |
| "my environment", "posture", "overview" | Overall security summary | get_risk_summary, cs_list_images, cs_list_containers |
| "this CVE", "CVE-xxxx" | Specific vulnerability lookup | get_cve_details |

## Available APIs and When to Use Them

### 1. Container Security API - Images (cs_list_images, cs_get_image_vulnerabilities)
Use for: Image inventory, vulnerability counts by image, registry data, build-time security
- Returns: Images scanned in your Qualys subscription
- Best for: "What images have critical vulns?", "Show my vulnerable images"

### 2. Container Security API - Containers (cs_list_containers, cs_get_container_vulnerabilities)
Use for: Runtime container data, deployed containers, production security
- Returns: Running/stopped containers with vulnerability data
- Best for: "What's running in production?", "Runtime vulnerabilities", "Deployed containers"

### 3. QScanner - Local Scanning (qscanner_scan_image, qscanner_scan_directory, qscanner_scan_container)
Use for: Fresh scans, CI/CD integration, scanning new/unknown images
- Returns: Real-time vulnerability scan results
- Best for: "Scan nginx:latest", "Check this image before deploy", "Scan my code"

### 4. Analysis Tools (analyze_vulnerabilities, get_risk_summary, get_cve_details)
Use for: Prioritization, risk assessment, CVE lookups
- Returns: Prioritized vulnerability lists, risk scores, CVE details
- Best for: "What should I fix first?", "Tell me about CVE-2024-1234"

## Decision Flow

1. If user mentions "runtime", "running", "deployed" → Use container APIs
2. If user mentions "images", "registry", "build" → Use image APIs
3. If user wants fresh/new scan → Use qscanner tools
4. If user asks about specific CVE → Use get_cve_details
5. If user asks general "what's my risk" → Use get_risk_summary + list APIs
6. When in doubt, start with cs_list_images to understand the environment

## Response Guidelines

- Be concise and actionable
- Do NOT use emojis or icons in responses
- Prioritize critical and high severity vulnerabilities with known exploits
- When listing vulnerabilities, include: CVE ID, severity, CVSS score, affected package, and whether a fix is available
- Provide specific remediation steps when possible
- If the user's question is unclear, ask for clarification before running tools
- Always state which data source you used (Container API vs fresh scan)

## Important Notes

- Scanning a new image takes 1-5 minutes depending on size
- Container API data may be up to 24 hours old
- Runtime data shows what's actually deployed vs what's in the registry`
}
