package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nelssec/qualys-qscanner-llm/internal/claude"
	"github.com/nelssec/qualys-qscanner-llm/internal/qualys"
	"github.com/nelssec/qualys-qscanner-llm/internal/qscanner"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/rs/zerolog"
)

type Agent struct {
	claudeClient *claude.Client
	toolHandler  *ToolHandler
	logger       zerolog.Logger
	maxTurns     int
}

func NewAgent(claudeClient *claude.Client, qscannerExec *qscanner.Executor, qualysClient *qualys.Client, logger zerolog.Logger) *Agent {
	return &Agent{
		claudeClient: claudeClient,
		toolHandler:  NewToolHandler(qscannerExec, qualysClient),
		logger:       logger,
		maxTurns:     15,
	}
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (a *Agent) Chat(ctx context.Context, userMessage string, history []Message) (string, []Message, error) {
	messages := a.buildMessages(history, userMessage)
	tools := claude.GetToolDefinitions()
	systemPrompt := claude.GetSystemPrompt()

	var finalResponse string
	turn := 0

	for turn < a.maxTurns {
		turn++
		a.logger.Debug().Int("turn", turn).Msg("agent turn")

		resp, err := a.claudeClient.CreateMessage(ctx, messages, tools, systemPrompt)
		if err != nil {
			return "", nil, fmt.Errorf("Claude API error: %w", err)
		}

		type toolUseInfo struct {
			ID    string
			Name  string
			Input json.RawMessage
		}
		var toolUses []toolUseInfo
		var textContent string

		for _, block := range resp.Content {
			switch block.Type {
			case "text":
				textContent += block.Text
			case "tool_use":
				toolUses = append(toolUses, toolUseInfo{
					ID:    block.ID,
					Name:  block.Name,
					Input: block.Input,
				})
			}
		}

		if resp.StopReason == anthropic.StopReasonEndTurn && len(toolUses) == 0 {
			finalResponse = textContent
			history = append(history, Message{Role: "user", Content: userMessage})
			history = append(history, Message{Role: "assistant", Content: textContent})
			break
		}

		if len(toolUses) > 0 {
			messages = append(messages, anthropic.MessageParam{
				Role:    anthropic.MessageParamRoleAssistant,
				Content: a.contentToParam(resp.Content),
			})

			var toolResults []anthropic.ToolResultBlockParam
			for _, toolUse := range toolUses {
				a.logger.Info().
					Str("tool", toolUse.Name).
					Msg("executing tool")

				result, err := a.toolHandler.ExecuteTool(ctx, toolUse.Name, toolUse.Input)
				if err != nil {
					a.logger.Error().Err(err).Str("tool", toolUse.Name).Msg("tool execution failed")
					result = fmt.Sprintf("Error: %v", err)
				}

				toolResults = append(toolResults, anthropic.ToolResultBlockParam{
					ToolUseID: toolUse.ID,
					Content: []anthropic.ToolResultBlockParamContentUnion{
						{
							OfText: &anthropic.TextBlockParam{Text: result},
						},
					},
				})
			}

			messages = append(messages, anthropic.MessageParam{
				Role:    anthropic.MessageParamRoleUser,
				Content: a.toolResultsToParam(toolResults),
			})
		}
	}

	if turn >= a.maxTurns {
		return "", nil, fmt.Errorf("max turns (%d) exceeded", a.maxTurns)
	}

	return finalResponse, history, nil
}

func (a *Agent) buildMessages(history []Message, currentMessage string) []anthropic.MessageParam {
	messages := make([]anthropic.MessageParam, 0, len(history)+1)

	for _, msg := range history {
		role := anthropic.MessageParamRoleUser
		if msg.Role == "assistant" {
			role = anthropic.MessageParamRoleAssistant
		}

		messages = append(messages, anthropic.MessageParam{
			Role: role,
			Content: []anthropic.ContentBlockParamUnion{
				anthropic.NewTextBlock(msg.Content),
			},
		})
	}

	messages = append(messages, anthropic.MessageParam{
		Role: anthropic.MessageParamRoleUser,
		Content: []anthropic.ContentBlockParamUnion{
			anthropic.NewTextBlock(currentMessage),
		},
	})

	return messages
}

func (a *Agent) contentToParam(content []anthropic.ContentBlockUnion) []anthropic.ContentBlockParamUnion {
	params := make([]anthropic.ContentBlockParamUnion, 0, len(content))

	for _, block := range content {
		switch block.Type {
		case "text":
			params = append(params, anthropic.NewTextBlock(block.Text))
		case "tool_use":
			params = append(params, anthropic.ContentBlockParamUnion{
				OfToolUse: &anthropic.ToolUseBlockParam{
					ID:    block.ID,
					Name:  block.Name,
					Input: block.Input,
				},
			})
		}
	}

	return params
}

func (a *Agent) toolResultsToParam(results []anthropic.ToolResultBlockParam) []anthropic.ContentBlockParamUnion {
	params := make([]anthropic.ContentBlockParamUnion, 0, len(results))

	for _, result := range results {
		params = append(params, anthropic.ContentBlockParamUnion{
			OfToolResult: &result,
		})
	}

	return params
}
