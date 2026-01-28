package qscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/nelssec/qualys-qscanner-llm/config"
	"github.com/rs/zerolog"
)

type Executor struct {
	binaryPath   string
	pod          string
	username     string
	password     string
	clientID     string
	clientSecret string
	bearerToken  string
	authMethod   config.QualysAuthMethod
	logger       zerolog.Logger
}

func NewExecutor(cfg *config.Config, logger zerolog.Logger) *Executor {
	return &Executor{
		binaryPath:   cfg.QScannerPath,
		pod:          cfg.QualysPOD,
		username:     cfg.QualysUsername,
		password:     cfg.QualysPassword,
		clientID:     cfg.QualysClientID,
		clientSecret: cfg.QualysClientSecret,
		bearerToken:  cfg.QualysBearerToken,
		authMethod:   cfg.GetQualysAuthMethod(),
		logger:       logger,
	}
}

func (e *Executor) ScanImage(ctx context.Context, opts ScanOptions) (*ScanOutput, error) {
	args := e.buildImageArgs(opts)
	return e.runScan(ctx, args)
}

func (e *Executor) ScanDirectory(ctx context.Context, opts ScanOptions) (*ScanOutput, error) {
	args := e.buildDirectoryArgs(opts)
	return e.runScan(ctx, args)
}

func (e *Executor) ScanContainer(ctx context.Context, opts ScanOptions) (*ScanOutput, error) {
	args := e.buildContainerArgs(opts)
	return e.runScan(ctx, args)
}

func (e *Executor) buildImageArgs(opts ScanOptions) []string {
	args := []string{
		"--pod", e.pod,
		"--output", "json",
		"image", opts.Image,
	}

	if opts.Mode != "" {
		args = append(args, "--"+opts.Mode)
	}

	if len(opts.ScanType) > 0 {
		args = append(args, "--scan-type", strings.Join(opts.ScanType, ","))
	}

	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	return args
}

func (e *Executor) buildDirectoryArgs(opts ScanOptions) []string {
	args := []string{
		"--pod", e.pod,
		"--output", "json",
		"rootfs", opts.Path,
	}

	if len(opts.ScanType) > 0 {
		args = append(args, "--scan-type", strings.Join(opts.ScanType, ","))
	}

	return args
}

func (e *Executor) buildContainerArgs(opts ScanOptions) []string {
	args := []string{
		"--pod", e.pod,
		"--output", "json",
		"container", opts.ContainerID,
	}

	if len(opts.ScanType) > 0 {
		args = append(args, "--scan-type", strings.Join(opts.ScanType, ","))
	}

	return args
}

func (e *Executor) runScan(ctx context.Context, args []string) (*ScanOutput, error) {
	e.logger.Debug().
		Str("binary", e.binaryPath).
		Strs("args", args).
		Msg("executing qscanner")

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.binaryPath, args...)

	switch e.authMethod {
	case config.QualysAuthBearer:
		cmd.Env = append(cmd.Environ(),
			fmt.Sprintf("QUALYS_ACCESS_TOKEN=%s", e.bearerToken),
		)
	case config.QualysAuthOAuth:
		cmd.Env = append(cmd.Environ(),
			fmt.Sprintf("QUALYS_CLIENT_ID=%s", e.clientID),
			fmt.Sprintf("QUALYS_CLIENT_SECRET=%s", e.clientSecret),
		)
	default:
		cmd.Env = append(cmd.Environ(),
			fmt.Sprintf("QUALYS_USERNAME=%s", e.username),
			fmt.Sprintf("QUALYS_PASSWORD=%s", e.password),
		)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	e.logger.Debug().
		Dur("duration", duration).
		Int("exit_code", cmd.ProcessState.ExitCode()).
		Msg("qscanner completed")

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("scan timed out after %v", duration)
		}
		return nil, fmt.Errorf("scan failed: %w, stderr: %s", err, stderr.String())
	}

	var output ScanOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse scan output: %w", err)
	}

	return &output, nil
}
