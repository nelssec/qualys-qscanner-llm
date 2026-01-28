package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nelssec/qualys-qscanner-llm/config"
	"github.com/nelssec/qualys-qscanner-llm/internal/agent"
	"github.com/nelssec/qualys-qscanner-llm/internal/api"
	"github.com/nelssec/qualys-qscanner-llm/internal/credentials"
	"github.com/nelssec/qualys-qscanner-llm/internal/llm"
	"github.com/nelssec/qualys-qscanner-llm/internal/qualys"
	"github.com/nelssec/qualys-qscanner-llm/internal/qscanner"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	cfg         *config.Config
	logger      zerolog.Logger
	llmProvider string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "qscanner [question]",
		Short: "AI-powered container vulnerability assistant",
		Long: `QScanner Agent is an AI-powered assistant that helps you understand
and prioritize container vulnerability risk using Qualys QScanner
and the Qualys Container Security platform.

LLM Provider Options:
  --local    Force use of local Ollama model (no API costs, requires Ollama running)
  --cloud    Force use of Claude API (best quality, requires ANTHROPIC_API_KEY)
  (default)  Auto-route: simple queries to local, complex to cloud

Examples:
  qscanner "What are my critical vulnerabilities?"
  qscanner --local "list my images"
  qscanner --cloud "analyze and prioritize all runtime risks"
  qscanner chat
  qscanner serve --port 8080`,
		Args: cobra.ArbitraryArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = config.Load()
			if err != nil {
				return err
			}

			level, _ := zerolog.ParseLevel(cfg.LogLevel)
			logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
				Level(level).
				With().
				Timestamp().
				Logger()

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			question := strings.Join(args, " ")
			return runAsk(question)
		},
	}

	rootCmd.PersistentFlags().StringVar(&llmProvider, "llm", "auto", "LLM provider: auto, local, cloud")
	rootCmd.PersistentFlags().BoolP("local", "l", false, "Use local Ollama model")
	rootCmd.PersistentFlags().BoolP("cloud", "c", false, "Use Claude API")

	rootCmd.AddCommand(chatCmd())
	rootCmd.AddCommand(askCmd())
	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(testCmd())
	rootCmd.AddCommand(configCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func chatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "chat",
		Short: "Start an interactive chat session",
		Long:  "Start an interactive chat session with the AI assistant to analyze vulnerabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChat()
		},
	}
}

func askCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ask [question]",
		Short: "Ask a single question",
		Long:  "Ask a single question and get an AI-powered response",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			question := strings.Join(args, " ")
			return runAsk(question)
		},
	}
}

func serveCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the REST API server",
		Long:  "Start the REST API server for programmatic access",
		RunE: func(cmd *cobra.Command, args []string) error {
			if port > 0 {
				cfg.ServerPort = port
			}
			return runServer()
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 0, "Port to listen on (default: 8080)")
	return cmd
}

func createAgent() *agent.AgentV2 {
	router := llm.NewHybridRouter(
		cfg.OllamaURL,
		cfg.OllamaModel,
		cfg.AnthropicAPIKey,
		"",
		cfg.PreferLocal,
	)

	if router.LocalAvailable() {
		logger.Info().Str("model", cfg.OllamaModel).Msg("local Ollama available")
	}
	if cfg.AnthropicAPIKey != "" {
		logger.Info().Msg("Claude API available")
	}

	qscannerExec := qscanner.NewExecutor(cfg, logger)
	qualysClient := qualys.NewClient(cfg, logger)

	return agent.NewAgentV2(router, qscannerExec, qualysClient, logger)
}

func runChat() error {
	ag := createAgent()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nGoodbye!")
		cancel()
		os.Exit(0)
	}()

	fmt.Println("QScanner Agent - AI-Powered Container Security Assistant")
	fmt.Println("=========================================================")
	fmt.Println("Ask me about your container vulnerabilities, security posture,")
	fmt.Println("or request a scan of specific images.")
	fmt.Println()
	fmt.Println("Type 'exit' or 'quit' to end the session.")
	fmt.Println()

	var history []agent.Message
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("You: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if input == "exit" || input == "quit" {
			fmt.Println("Goodbye!")
			return nil
		}

		if input == "clear" {
			history = nil
			fmt.Println("Conversation cleared.")
			continue
		}

		fmt.Println()
		fmt.Print("Thinking...")

		response, newHistory, err := ag.Chat(ctx, input, history)
		if err != nil {
			fmt.Printf("\rError: %v\n\n", err)
			continue
		}

		history = newHistory

		fmt.Print("\r")
		fmt.Printf("Assistant: %s\n\n", response)
	}
}

func runAsk(question string) error {
	ag := createAgent()

	ctx, cancel := context.WithTimeout(context.Background(), 5*60*1000000000)
	defer cancel()

	response, _, err := ag.Chat(ctx, question, nil)
	if err != nil {
		return err
	}

	fmt.Println(response)
	return nil
}

func runServer() error {
	ag := createAgent()
	server := api.NewServer(ag, cfg.ServerPort, logger, cfg)

	return server.Start()
}

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Test Qualys API connectivity",
		Long:  "Test connectivity to Qualys API and QScanner binary",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTest()
		},
	}
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage credentials stored in OS keychain",
		Long: `Manage API credentials stored securely in your OS keychain.

Credentials are stored in:
  - macOS: Keychain Access
  - Windows: Credential Manager
  - Linux: Secret Service (GNOME Keyring)

Examples:
  qscanner config setup          # Interactive setup
  qscanner config show           # Show configured credentials
  qscanner config clear          # Remove all stored credentials`,
	}

	cmd.AddCommand(configSetupCmd())
	cmd.AddCommand(configShowCmd())
	cmd.AddCommand(configClearCmd())

	return cmd
}

func configSetupCmd() *cobra.Command {
	var anthropicKey, qualysToken, qualysPOD string

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure API credentials",
		Long:  "Interactively configure and store API credentials in OS keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			reader := bufio.NewReader(os.Stdin)

			if anthropicKey == "" {
				fmt.Print("Anthropic API Key (press Enter to skip): ")
				key, _ := readPassword()
				anthropicKey = strings.TrimSpace(key)
			}

			if qualysToken == "" {
				fmt.Print("Qualys Bearer Token (press Enter to skip): ")
				token, _ := readPassword()
				qualysToken = strings.TrimSpace(token)
			}

			if qualysPOD == "" {
				fmt.Print("Qualys POD [US1-4, EU1-3, CA1, IN1, AE1, UK1, AU1] (default: US2): ")
				pod, _ := reader.ReadString('\n')
				qualysPOD = strings.TrimSpace(pod)
				if qualysPOD == "" {
					qualysPOD = "US2"
				}
			}

			if err := credentials.Setup(anthropicKey, qualysToken, qualysPOD); err != nil {
				return fmt.Errorf("failed to store credentials: %w", err)
			}

			fmt.Println("\nCredentials stored securely in OS keychain.")
			fmt.Println("You can now run qscanner without setting environment variables.")
			return nil
		},
	}

	cmd.Flags().StringVar(&anthropicKey, "anthropic-key", "", "Anthropic API key")
	cmd.Flags().StringVar(&qualysToken, "qualys-token", "", "Qualys bearer token")
	cmd.Flags().StringVar(&qualysPOD, "qualys-pod", "", "Qualys POD (US1-4, EU1-3, CA1, etc.)")

	return cmd
}

func configShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show configured credentials",
		Long:  "Display which credentials are configured in the OS keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			configured := credentials.ListConfigured()

			fmt.Println("Credential Status (stored in OS keychain):")
			fmt.Println("==========================================")

			status := func(ok bool) string {
				if ok {
					return "configured"
				}
				return "not set"
			}

			fmt.Printf("  Anthropic API Key:   %s\n", status(configured[credentials.KeyAnthropic]))
			fmt.Printf("  Qualys Bearer Token: %s\n", status(configured[credentials.KeyQualysToken]))

			if configured[credentials.KeyQualysPOD] {
				pod, _ := credentials.Get(credentials.KeyQualysPOD)
				fmt.Printf("  Qualys POD:          %s\n", pod)
			} else {
				fmt.Printf("  Qualys POD:          not set (default: US2)\n")
			}

			fmt.Println("\nNote: Environment variables override keychain values.")
			return nil
		},
	}
}

func configClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Clear all stored credentials",
		Long:  "Remove all credentials from the OS keychain",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("Are you sure you want to clear all stored credentials? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response != "y" && response != "yes" {
				fmt.Println("Cancelled.")
				return nil
			}

			if err := credentials.ClearAll(); err != nil {
				fmt.Printf("Warning: some credentials may not have been cleared: %v\n", err)
			}

			fmt.Println("All credentials cleared from keychain.")
			return nil
		},
	}
}

func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println()
		bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(bytes), err
	}
	reader := bufio.NewReader(os.Stdin)
	return reader.ReadString('\n')
}

func runTest() error {
	fmt.Println("Testing Qualys Container Security API connectivity...")
	fmt.Printf("  POD: %s\n", cfg.QualysPOD)
	fmt.Printf("  API URL: %s\n", cfg.QualysAPIURL)
	fmt.Printf("  Auth Method: %s\n", cfg.GetQualysAuthMethod())

	qualysClient := qualys.NewClient(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	images, total, err := qualysClient.ListImages(ctx, qualys.ListOptions{PageSize: 5})
	if err != nil {
		fmt.Printf("  FAILED: %v\n", err)
		return err
	}

	fmt.Printf("  OK - Found %d images\n\n", total)

	if len(images) > 0 {
		fmt.Println("Sample images:")
		for i, img := range images {
			if i >= 5 {
				break
			}
			fmt.Printf("  - %s:%s (Critical: %d, High: %d)\n",
				img.Name, img.Tag,
				img.SeverityCounts.Critical,
				img.SeverityCounts.High)
		}
	}

	return nil
}
