package agent

import "context"

type ChatAgent interface {
	Chat(ctx context.Context, userMessage string, history []Message) (string, []Message, error)
}
