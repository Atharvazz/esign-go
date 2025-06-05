package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/esign-go/internal/config"
	"github.com/esign-go/internal/controller"
	"github.com/esign-go/internal/middleware"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/internal/service"
	"github.com/esign-go/pkg/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize logger
	logger.Init()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	db, err := repository.InitDB(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := repository.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize repositories
	esignRepo := repository.NewEsignRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	aspRepo := repository.NewASPRepository(db)

	// Initialize services
	xmlValidator := service.NewXMLValidator()
	cryptoService := service.NewCryptoService(cfg.Security)
	templateService := service.NewTemplateService(cfg.Templates.Path)
	esignService := service.NewEsignService(esignRepo, auditRepo, aspRepo, xmlValidator, cryptoService, cfg)
	
	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit)

	// Initialize Gin router
	router := gin.New()

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())
	router.Use(middleware.RequestID())
	router.Use(middleware.CORS(cfg.CORS))

	// Static files
	router.Static("/static", "./static")
	router.LoadHTMLGlob("templates/*")

	// Initialize controllers
	authController := controller.NewAuthenticateController(esignService, templateService, cfg)

	// Routes
	api := router.Group("/authenticate")
	{
		// Apply rate limiting to esign-doc endpoint
		api.POST("/esign-doc", 
			rateLimiter.Middleware("esign-doc", cfg.RateLimit.EsignDoc),
			authController.EsignDoc,
		)
		
		api.POST("/es", authController.Es)
		api.POST("/otp-request", authController.OTPRequest)
		api.POST("/validate-otp", authController.ValidateOTP)
		api.GET("/status/:txnId", authController.CheckStatus)
		api.POST("/callback", authController.Callback)
	}

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"build":  cfg.App.Build,
			"time":   time.Now().UTC(),
		})
	})

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}