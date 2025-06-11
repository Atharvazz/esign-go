package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/esign-go/internal/controller"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/internal/service"
	"github.com/esign-go/pkg/logger"
	"github.com/esign-go/pkg/xmlparser"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	// Initialize logger
	logger.Init()

	// Debug: Show working directory
	cwd, _ := os.Getwd()
	log.Printf("Working Directory: %s", cwd)

	// Create a fixed config with correct database settings
	cfg := &models.Config{
		App: models.AppConfig{
			Name:        "eSign Service",
			Environment: "development",
			Build:       "1.0.0",
			Debug:       true,
		},
		Server: models.ServerConfig{
			Address:        ":8080",
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    120 * time.Second,
			Version:        "1.0",
			Environment:    "development",
			RequestTimeout: 30,
		},
		Database: models.DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			User:         "atharvaz",
			Password:     "",
			DBName:       "esign_db", // Fixed database name
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 25,
			MaxLifetime:  15 * time.Minute,
		},
		Security: models.SecurityConfig{
			JWTSecret:       "your-secret-key-here",
			SessionTimeout:  30 * time.Minute,
			MaxAuthAttempts: 3,
		},
		UIDAI: models.UIDAIConfig{
			AuthURL:     "https://auth.uidai.gov.in/auth/2.0",
			OTPAuthURL:  "https://auth.uidai.gov.in/otp/2.0",
			EKYCAuthURL: "https://auth.uidai.gov.in/ekyc/2.0",
			Timeout:     30 * time.Second,
		},
		Templates: models.TemplateConfig{
			Path:           "templates",
			CacheTemplates: true,
		},
		Logging: models.LoggingConfig{
			Level:           "debug",
			Format:          "json",
			OutputPath:      "stdout",
			ErrorOutputPath: "stderr",
			RequestLogging:  true,
			XMLLogging:      false,
		},
		Auth: models.AuthConfig{
			MaxAttempts:      3,
			OTPRetryAttempts: 3,
			SessionTimeout:   30,
		},
	}

	log.Printf("Database config: %s@%s:%d/%s", cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)

	// Initialize database with direct connection
	connStr := "host=localhost port=5432 user=atharvaz dbname=esign_db sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("✓ Database connected successfully!")

	// Run migrations
	if err := repository.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("✓ Migrations completed successfully!")

	// Initialize services
	xmlSvc := xmlparser.NewService()

	// Initialize Gin
	gin.SetMode(gin.DebugMode)
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Setup session store
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("esign-session", store))

	// Load templates
	templatePath := filepath.Join(cwd, "templates", "*.html")
	router.LoadHTMLGlob(templatePath)

	// Static files
	router.Static("/static", "./static")

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "healthy",
			"build":    cfg.App.Build,
			"database": "connected",
		})
	})

	// API version
	router.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version": cfg.Server.Version,
			"build":   cfg.App.Build,
		})
	})

	// Initialize controllers with fixed components
	authController := &controller.AuthController{
		AuthService: &service.AuthService{
			XMLService: xmlSvc,
		},
		Config: cfg,
	}

	esignController := &controller.ESignController{
		ESignService: &service.ESignService{
			XMLService: xmlSvc,
		},
		Config: cfg,
	}

	// API routes
	apiV1 := router.Group("/api/v1")
	{
		// ESign routes
		apiV1.POST("/esign/request", esignController.HandleESignRequest)
		apiV1.POST("/esign/send-otp", authController.SendOTP)
		apiV1.POST("/esign/verify-otp", authController.VerifyOTP)
		apiV1.POST("/esign/get-certificate", esignController.GetCertificate)
		apiV1.POST("/esign/sign-document", esignController.SignDocument)
		apiV1.POST("/esign/cancel", esignController.CancelESign)
		apiV1.POST("/esign/check-status", esignController.CheckStatus)
	}

	// UI routes
	router.GET("/esign/auth", authController.ShowAuthPage)
	router.POST("/esign/process-auth", authController.ProcessAuth)
	router.GET("/esign/success", esignController.ShowSuccessPage)
	router.GET("/esign/failure", esignController.ShowFailurePage)
	router.GET("/esign/cancel", esignController.ShowCancelPage)

	// Start server
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Graceful shutdown
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("✓ Server starting on %s", cfg.Server.Address)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
