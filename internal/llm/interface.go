package llm

import (
	"context"
)

type Message struct {
	Role    string
	Content string
}

type ToolCall struct {
	ID    string
	Name  string
	Input []byte
}

type Response struct {
	Content   string
	ToolCalls []ToolCall
	StopReason string
}

type ToolDefinition struct {
	Name        string
	Description string
	Parameters  map[string]interface{}
	Required    []string
}

type Client interface {
	Chat(ctx context.Context, messages []Message, tools []ToolDefinition, systemPrompt string) (*Response, error)
	Name() string
}

type Router interface {
	Route(query string) Client
}
