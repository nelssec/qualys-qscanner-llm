package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type ClaudeClient struct {
	client anthropic.Client
	model  string
}

func NewClaudeClient(apiKey, model string) *ClaudeClient {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	return &ClaudeClient{
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  model,
	}
}

func (c *ClaudeClient) Name() string {
	return fmt.Sprintf("claude/%s", c.model)
}

func (c *ClaudeClient) Chat(ctx context.Context, messages []Message, tools []ToolDefinition, systemPrompt string) (*Response, error) {
	anthropicMessages := make([]anthropic.MessageParam, 0, len(messages))

	for _, msg := range messages {
		role := anthropic.MessageParamRoleUser
		if msg.Role == "assistant" {
			role = anthropic.MessageParamRoleAssistant
		}

		anthropicMessages = append(anthropicMessages, anthropic.MessageParam{
			Role: role,
			Content: []anthropic.ContentBlockParamUnion{
				anthropic.NewTextBlock(msg.Content),
			},
		})
	}

	anthropicTools := make([]anthropic.ToolParam, 0, len(tools))
	for _, tool := range tools {
		anthropicTools = append(anthropicTools, anthropic.ToolParam{
			Name:        tool.Name,
			Description: anthropic.String(tool.Description),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: tool.Parameters,
				Required:   tool.Required,
			},
		})
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: 4096,
		Messages:  anthropicMessages,
	}

	if systemPrompt != "" {
		params.System = []anthropic.TextBlockParam{
			{Text: systemPrompt},
		}
	}

	if len(anthropicTools) > 0 {
		toolUnions := make([]anthropic.ToolUnionParam, len(anthropicTools))
		for i, t := range anthropicTools {
			toolUnions[i] = anthropic.ToolUnionParam{
				OfTool: &t,
			}
		}
		params.Tools = toolUnions
	}

	resp, err := c.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("Claude API error: %w", err)
	}

	response := &Response{
		StopReason: string(resp.StopReason),
	}

	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			response.Content += block.Text
		case "tool_use":
			inputJSON, _ := json.Marshal(block.Input)
			response.ToolCalls = append(response.ToolCalls, ToolCall{
				ID:    block.ID,
				Name:  block.Name,
				Input: inputJSON,
			})
		}
	}

	return response, nil
}
