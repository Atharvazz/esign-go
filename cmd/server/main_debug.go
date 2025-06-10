package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/esign-go/internal/config"
	"github.com/esign-go/internal/controller"
	"github.com/esign-go/internal/middleware"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/internal/service"
	"github.com/esign-go/pkg/logger"
	"github.com/esign-go/pkg/xmlparser"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize logger
	logger.Init()

	// Debug: Show working directory
	cwd, _ := os.Getwd()
	log.Printf("Working Directory: %s", cwd)

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
	aspRepo := repository.NewASPRepository(db)

	// Initialize services
	xmlValidator := xmlparser.NewXMLValidator()
	
	// Load test keys for development - in production load from config
	privateKey, err := os.ReadFile("test-keys/private.key")
	if err != nil {
		log.Printf("Warning: Failed to load private key: %v", err)
		privateKey = []byte{}
	}
	
	certificate, err := os.ReadFile("test-keys/certificate.crt")
	if err != nil {
		log.Printf("Warning: Failed to load certificate: %v", err)
		certificate = []byte{}
	}
	
	cryptoService, err := service.NewCryptoService(privateKey, certificate)
	if err != nil {
		log.Fatalf("Failed to create crypto service: %v", err)
	}
	templateService := service.NewTemplateService(cfg.Templates.Path)

	// Create remote signing service
	// Load CA keys for development - in production load from config
	caCert, err := os.ReadFile("test-keys/ca-certificate.crt")
	if err != nil {
		log.Printf("Warning: Failed to load CA certificate: %v", err)
		caCert = []byte{}
	}
	
	caKey, err := os.ReadFile("test-keys/ca-private.key")
	if err != nil {
		log.Printf("Warning: Failed to load CA private key: %v", err)
		caKey = []byte{}
	}
	
	remoteSigningService, err := service.NewRemoteSigningService(cryptoService, esignRepo, caCert, caKey)
	if err != nil {
		log.Printf("Warning: Failed to create remote signing service: %v", err)
		// Create a basic instance for development
		remoteSigningService = &service.RemoteSigningService{}
	}
	
	// Convert config.Config to models.Config
	modelConfig := &models.Config{
		BiometricEnv:         cfg.Biometric.Environment,
		BiometricResponseURL: cfg.Biometric.ResponseURL,
		ConsentText:          cfg.Biometric.ConsentText,
		AuthAttempts:         cfg.Auth.MaxAttempts,
		OTPRetryAttempts:     cfg.Auth.OTPRetryAttempts,
		Build:                cfg.Server.Version,
		Environment:          cfg.Server.Environment,
		RequestTimeout:       cfg.Server.RequestTimeout,
		CheckStatusASPs:      cfg.CheckStatus.AllowedASPs,
	}
	
	// Set RateLimit struct
	modelConfig.RateLimit.EsignDoc = cfg.RateLimit.EsignDoc.Rate
	modelConfig.RateLimit.CheckStatus = cfg.RateLimit.CheckStatus.Rate
	modelConfig.RateLimit.Enabled = cfg.RateLimit.Enabled
	modelConfig.RateLimit.WindowSize = 60
	modelConfig.RateLimit.FallbackEnabled = false
	
	// Set Debug struct
	modelConfig.Debug.LogLevel = "debug"
	modelConfig.Debug.LogRequests = true
	modelConfig.Debug.LogResponses = true
	
	// Set Security struct
	modelConfig.Security.MaxXMLSize = 100 * 1024 // 100KB
	
	esignService := service.NewEsignService(esignRepo, aspRepo, xmlValidator, cryptoService, remoteSigningService, remoteSigningService, modelConfig)
	kycService := service.NewKYCService(modelConfig, cryptoService)
	
	// Create session service
	sessionService := service.NewSessionService(nil, "esign", 3600)

	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.Enabled)

	// Initialize Gin router
	gin.SetMode(gin.DebugMode) // Force debug mode to see template loading
	router := gin.New()

	// Create session store
	store := cookie.NewStore([]byte("secret-key-for-sessions"))
	store.Options(sessions.Options{
		MaxAge:   3600, // 1 hour
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})

	// Global middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger())
	router.Use(middleware.RequestID())
	router.Use(sessions.Sessions("esign-session", store)) // Add session middleware
	router.Use(middleware.CORS(cfg.CORS))

	// Static files
	router.Static("/static", "./static")
	
	// Load templates with better error handling
	// Use absolute path to templates directory
	projectRoot := filepath.Join(cwd, "..", "..")
	templatesPath := filepath.Join(projectRoot, "templates", "*")
	log.Printf("Loading templates from: %s", templatesPath)
	
	// Check if templates directory exists
	templatesDir := filepath.Join(projectRoot, "templates")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		log.Fatalf("Templates directory not found at: %s", templatesDir)
	}
	
	// List template files
	matches, err := filepath.Glob(templatesPath)
	if err != nil {
		log.Printf("Error globbing templates: %v", err)
	} else {
		log.Printf("Found %d template files:", len(matches))
		for _, match := range matches {
			log.Printf("  - %s", filepath.Base(match))
		}
	}
	
	router.LoadHTMLGlob(templatesPath)

	// Initialize controllers
	authController := controller.NewAuthenticateController(esignService, kycService, templateService, sessionService, modelConfig)

	// Routes
	api := router.Group("/authenticate")
	{
		// Apply rate limiting to esign-doc endpoint
		api.POST("/esign-doc",
			rateLimiter.Middleware("esign-doc", middleware.RateLimitRule{
				Rate:     cfg.RateLimit.EsignDoc.Rate,
				Duration: cfg.RateLimit.EsignDoc.Period,
			}),
			authController.EsignDoc,
		)

		api.POST("/es", authController.ProcessEsign)
		api.POST("/otp", authController.GenerateOTP)
		api.POST("/otpAction", authController.VerifyOTP)
		api.GET("/auth-ra", authController.AuthRA)
		api.GET("/es-ra", authController.EsignRedirect)
		api.POST("/postRequestdata", authController.BiometricAuth)
		api.POST("/esignCancel", authController.CancelEsign)
		api.GET("/sigError", authController.SignatureError)
		api.POST("/check-status", authController.CheckStatus)
		api.POST("/check-status-api", authController.CheckStatusAPI)
	}

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"build":  cfg.App.Build,
			"time":   time.Now().UTC(),
		})
	})

	// Debug endpoint to test templates
	router.GET("/debug/templates", func(c *gin.Context) {
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": "Test message",
			"u":   "http://example.com",
		})
	})
	
	// Debug endpoint to list templates
	router.GET("/debug/info", func(c *gin.Context) {
		templates, _ := filepath.Glob("templates/*")
		c.JSON(http.StatusOK, gin.H{
			"working_directory": cwd,
			"templates_found":   len(templates),
			"template_files":    templates,
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