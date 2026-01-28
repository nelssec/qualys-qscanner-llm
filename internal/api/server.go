package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nelssec/qualys-qscanner-llm/config"
	"github.com/nelssec/qualys-qscanner-llm/internal/agent"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

type Server struct {
	agent  agent.ChatAgent
	port   int
	logger zerolog.Logger
	store  *agent.ConversationStore
	config *config.Config
}

func NewServer(ag agent.ChatAgent, port int, logger zerolog.Logger, cfg *config.Config) *Server {
	return &Server{
		agent:  ag,
		port:   port,
		logger: logger,
		store:  agent.NewConversationStore(),
		config: cfg,
	}
}

func (s *Server) Start() error {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.loggingMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(5 * time.Minute))

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/chat", s.handleChat)
		r.Get("/health", s.handleHealth)
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: r,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		s.logger.Info().Msg("shutting down server")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	s.logger.Info().Int("port", s.port).Msg("starting API server")
	return srv.ListenAndServe()
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			s.logger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", ww.Status()).
				Dur("duration", time.Since(start)).
				Msg("request")
		}()

		next.ServeHTTP(ww, r)
	})
}
