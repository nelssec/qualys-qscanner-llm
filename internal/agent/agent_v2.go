package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-qscanner-llm/internal/llm"
	"github.com/nelssec/qualys-qscanner-llm/internal/qualys"
	"github.com/nelssec/qualys-qscanner-llm/internal/qscanner"
	"github.com/rs/zerolog"
)

type AgentV2 struct {
	router       *llm.HybridRouter
	toolHandler  *ToolHandler
	logger       zerolog.Logger
	maxTurns     int
	systemPrompt string
	tools        []llm.ToolDefinition
}

func NewAgentV2(router *llm.HybridRouter, qscannerExec *qscanner.Executor, qualysClient *qualys.Client, logger zerolog.Logger) *AgentV2 {
	return &AgentV2{
		router:       router,
		toolHandler:  NewToolHandler(qscannerExec, qualysClient),
		logger:       logger,
		maxTurns:     15,
		systemPrompt: getSystemPrompt(),
		tools:        getToolDefinitions(),
	}
}

func (a *AgentV2) Chat(ctx context.Context, userMessage string, history []Message) (string, []Message, error) {
	client := a.router.Route(userMessage)
	if client == nil {
		return "", nil, fmt.Errorf("no LLM client available - set ANTHROPIC_API_KEY or ensure Ollama is running")
	}

	a.logger.Info().Str("client", client.Name()).Str("query", truncate(userMessage, 50)).Msg("routing query")

	messages := a.buildMessages(history, userMessage)
	var finalResponse string
	turn := 0

	for turn < a.maxTurns {
		turn++
		a.logger.Debug().Int("turn", turn).Str("client", client.Name()).Msg("agent turn")

		resp, err := client.Chat(ctx, messages, a.tools, a.systemPrompt)
		if err != nil {
			if a.router.GetCloud() != nil && client != a.router.GetCloud() {
				a.logger.Warn().Err(err).Msg("local model failed, falling back to cloud")
				client = a.router.GetCloud()
				continue
			}
			return "", nil, fmt.Errorf("LLM error: %w", err)
		}

		if resp.StopReason == "end_turn" && len(resp.ToolCalls) == 0 {
			finalResponse = resp.Content
			history = append(history, Message{Role: "user", Content: userMessage})
			history = append(history, Message{Role: "assistant", Content: resp.Content})
			break
		}

		if len(resp.ToolCalls) > 0 {
			assistantContent := resp.Content
			if len(resp.ToolCalls) > 0 {
				toolCallsJSON, _ := json.Marshal(resp.ToolCalls)
				assistantContent += "\n[Tool calls: " + string(toolCallsJSON) + "]"
			}
			messages = append(messages, llm.Message{Role: "assistant", Content: assistantContent})

			var toolResultsContent string
			for _, tc := range resp.ToolCalls {
				a.logger.Info().Str("tool", tc.Name).Msg("executing tool")

				result, err := a.toolHandler.ExecuteTool(ctx, tc.Name, tc.Input)
				if err != nil {
					a.logger.Error().Err(err).Str("tool", tc.Name).Msg("tool execution failed")
					result = fmt.Sprintf("Error: %v", err)
				}

				toolResultsContent += fmt.Sprintf("\n[Tool result for %s (id=%s)]: %s\n", tc.Name, tc.ID, result)
			}

			messages = append(messages, llm.Message{Role: "user", Content: toolResultsContent})
		}
	}

	if turn >= a.maxTurns {
		return "", nil, fmt.Errorf("max turns (%d) exceeded", a.maxTurns)
	}

	return finalResponse, history, nil
}

func (a *AgentV2) buildMessages(history []Message, currentMessage string) []llm.Message {
	messages := make([]llm.Message, 0, len(history)+1)

	for _, msg := range history {
		messages = append(messages, llm.Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	messages = append(messages, llm.Message{
		Role:    "user",
		Content: currentMessage,
	})

	return messages
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getSystemPrompt() string {
	return `You are a container security expert assistant powered by Qualys QScanner and the Qualys Container Security platform. Your job is to help users understand and prioritize their container vulnerability risk.

## Domain Terminology

Understand these terms and map them to the correct data source:

| User Says | Meaning | Use These Tools |
|-----------|---------|-----------------|
| "openssl vulnerabilities", "nginx vulns", "[product] vulnerabilities" | Search for specific product vulnerabilities | cs_search_images, cs_search_containers |
| "CVE-xxxx", "containers with CVE" | Search for specific CVE | cs_search_images, cs_search_containers |
| "runtime", "running", "deployed", "production" | Running containers with vulnerabilities | cs_search_containers with state:RUNNING, cs_get_runtime_risk |
| "images", "registry", "repository", "build" | Container images (built artifacts) | cs_list_images, cs_search_images |
| "scan", "check", "analyze this" | Fresh on-demand scan | qscanner_scan_image, qscanner_scan_container |
| "my environment", "posture", "overview" | Overall security summary | get_risk_summary, cs_list_images |

## Response Guidelines

- Be concise and actionable
- Do NOT use emojis or icons in responses
- Prioritize critical and high severity vulnerabilities with known exploits
- When listing vulnerabilities, include: CVE ID, severity, CVSS score, affected package, and whether a fix is available
- Provide specific remediation steps when possible
- If the user's question is unclear, ask for clarification before running tools
- Always state which data source you used (Container API vs fresh scan)`
}

func getToolDefinitions() []llm.ToolDefinition {
	return []llm.ToolDefinition{
		{
			Name:        "cs_list_images",
			Description: "List container images from the Qualys Container Security platform. Use this to see what images have been scanned and their vulnerability counts.",
			Parameters: map[string]interface{}{
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of results (default: 50, max: 200)",
				},
			},
		},
		{
			Name:        "cs_get_image_vulnerabilities",
			Description: "Get detailed vulnerability information for a specific image. Requires full 64-character SHA256 from cs_list_images.",
			Parameters: map[string]interface{}{
				"image_sha": map[string]interface{}{
					"type":        "string",
					"description": "Full SHA256 digest (64 hex chars) from cs_list_images",
				},
			},
			Required: []string{"image_sha"},
		},
		{
			Name:        "cs_list_containers",
			Description: "List containers from the Qualys Container Security platform. Shows running and stopped containers.",
			Parameters: map[string]interface{}{
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of results (default: 50, max: 1000)",
				},
			},
		},
		{
			Name:        "cs_get_container_vulnerabilities",
			Description: "Get detailed vulnerability information for a specific container. Requires full 64-character SHA256.",
			Parameters: map[string]interface{}{
				"container_sha": map[string]interface{}{
					"type":        "string",
					"description": "Full SHA256 (64 hex chars) from cs_list_containers",
				},
			},
			Required: []string{"container_sha"},
		},
		{
			Name:        "cs_get_runtime_risk",
			Description: "IMPORTANT: Use this for runtime vulnerability questions. Correlates running containers with their source image vulnerabilities.",
			Parameters: map[string]interface{}{
				"state": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"RUNNING", "STOPPED", "DELETED", ""},
					"description": "Filter by container state (default: RUNNING)",
				},
			},
		},
		{
			Name:        "analyze_vulnerabilities",
			Description: "Analyze and prioritize vulnerabilities based on risk factors (CVSS, exploitability, patchability).",
			Parameters: map[string]interface{}{
				"source": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"qscanner", "qualys_cs", "both"},
					"description": "Data source to analyze",
				},
				"severity_filter": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"critical", "high", "medium", "low", "all"},
					"description": "Minimum severity level",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Max vulnerabilities to return (default: 20)",
				},
			},
		},
		{
			Name:        "get_cve_details",
			Description: "Get detailed information about a specific CVE.",
			Parameters: map[string]interface{}{
				"cve_id": map[string]interface{}{
					"type":        "string",
					"description": "CVE identifier (e.g., CVE-2024-1234)",
				},
			},
			Required: []string{"cve_id"},
		},
		{
			Name:        "get_risk_summary",
			Description: "Get overall risk summary across all scanned assets.",
			Parameters: map[string]interface{}{
				"source": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"qscanner", "qualys_cs", "both"},
					"description": "Data source to analyze",
				},
			},
		},
		{
			Name:        "cs_search_images",
			Description: "IMPORTANT: Search for images with specific vulnerabilities using QQL filters. Use this when looking for images with specific products (openssl, nginx), CVEs, or severity levels.",
			Parameters: map[string]interface{}{
				"product": map[string]interface{}{
					"type":        "string",
					"description": "Product name to search for (e.g., openssl, nginx, curl). Maps to vulnerabilities.product filter.",
				},
				"cve": map[string]interface{}{
					"type":        "string",
					"description": "CVE ID to search for (e.g., CVE-2024-1234). Maps to vulnerabilities.cveids filter.",
				},
				"severity": map[string]interface{}{
					"type":        "integer",
					"description": "Minimum severity level 1-5 (5=critical). Maps to vulnerabilities.severity filter.",
				},
				"filter": map[string]interface{}{
					"type":        "string",
					"description": "Raw QQL filter string for advanced queries (e.g., 'vulnerabilities.product:openssl and vulnerabilities.severity:5')",
				},
			},
		},
		{
			Name:        "cs_search_containers",
			Description: "IMPORTANT: Search for containers with specific vulnerabilities using QQL filters. Use this when looking for running containers with specific products (openssl), CVEs, or severity levels.",
			Parameters: map[string]interface{}{
				"product": map[string]interface{}{
					"type":        "string",
					"description": "Product name to search for (e.g., openssl, nginx). Maps to vulnerabilities.product filter.",
				},
				"cve": map[string]interface{}{
					"type":        "string",
					"description": "CVE ID to search for. Maps to vulnerabilities.cveids filter.",
				},
				"severity": map[string]interface{}{
					"type":        "integer",
					"description": "Minimum severity level 1-5 (5=critical).",
				},
				"state": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"RUNNING", "STOPPED", "DELETED", ""},
					"description": "Container state filter (e.g., RUNNING for active containers).",
				},
				"filter": map[string]interface{}{
					"type":        "string",
					"description": "Raw QQL filter (e.g., 'state:RUNNING and vulnerabilities.product:openssl')",
				},
			},
		},
	}
}
