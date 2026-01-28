# QScanner Agent

An AI-powered CLI tool for querying Qualys Container Security data using natural language.

## Installation

### From Release

Download the latest binary for your platform from the [Releases](https://github.com/nelssec/qualys-qscanner-llm/releases) page.

### From Source

```bash
go build -o qscanner ./cmd/qscanner-agent
```

## Configuration

Store credentials securely in your system keychain:

```bash
# Interactive setup
./qscanner config setup

# View configured credentials (masked)
./qscanner config show

# Clear all stored credentials
./qscanner config clear
```

Alternatively, use environment variables:

```bash
export ANTHROPIC_API_KEY=your-key
export QUALYS_ACCESS_TOKEN=your-token
export QUALYS_POD=CA1
```

## Usage

```bash
# Ask questions about your container security data
./qscanner ask "what containers have openssl vulnerabilities"
./qscanner ask "list images with critical vulnerabilities"
./qscanner ask "show running containers with nginx"

# Start API server mode
./qscanner serve --port 8080
```

## Hybrid LLM Support

The agent supports both cloud (Claude) and local (Ollama) LLM backends:

- Simple queries (list, show, count) route to local Ollama if available
- Complex queries (analyze, prioritize, explain) route to Claude
- Automatic fallback to Claude if local model fails

To use local LLM, install Ollama and run:

```bash
ollama pull llama3.2
ollama serve
```

## License

MIT
