package main

import (
	"TestTaskAuthorization/internal/auth"
	"TestTaskAuthorization/internal/config"
	"TestTaskAuthorization/internal/handler"
	"TestTaskAuthorization/internal/middleware"
	"TestTaskAuthorization/internal/repository"
	postgres "TestTaskAuthorization/internal/repository"
	"TestTaskAuthorization/internal/router"
	"TestTaskAuthorization/internal/service"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	cfg, err := config.NewConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	db, err := postgres.NewDB(cfg.DBConnStr)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	defer db.Close()

	repo := repository.NewRepository(db, logger)
	auth := auth.NewAuth(cfg.SecretKey, cfg.AccessTokenDuration, cfg.RefreshTokenDuration, logger)
	service := service.NewService(repo, auth, *cfg, logger)
	middleware := middleware.NewAuthMiddleware(auth, logger)
	handler := handler.NewHandler(service, logger)
	app := router.SetupRouter(handler, middleware)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := app.Listen(cfg.Port); err != nil && err != http.ErrServerClosed {
			slog.Error("failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	fmt.Println("Server is running on port", cfg.Port)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		slog.Error("Server forced to shutdown: ", "error", err)
		os.Exit(1)
	}

	log.Println("Server exiting")

}
