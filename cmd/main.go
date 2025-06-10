package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/esign-go/internal/controller"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/internal/service"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create a basic config for testing
	config := &models.Config{
		Server: struct {
			Port         int    `yaml:"port"`
			Host         string `yaml:"host"`
			ReadTimeout  int    `yaml:"readTimeout"`
			WriteTimeout int    `yaml:"writeTimeout"`
		}{
			Port: 8080,
			Host: "localhost",
		},
		BiometricEnv:         "TEST",
		BiometricResponseURL: "http://localhost:8080/callback",
		ConsentText:          "I consent to digital signature",
		AuthAttempts:         3,
		OTPRetryAttempts:     3,
		Build:                "1.0.0",
		Environment:          "development",
		RequestTimeout:       5,
	}

	// Initialize services (with mock implementations for now)
	esignService := &service.EsignService{}
	kycService := &service.KYCService{}
	templateService := service.NewTemplateService("./templates")
	sessionService := service.NewSessionService(nil, "esign", 3600)

	// Create controller
	authController := controller.NewAuthenticateController(
		esignService,
		kycService,
		templateService,
		sessionService,
		config,
	)

	// Setup Gin router
	router := gin.Default()

	// Load templates
	router.LoadHTMLGlob("templates/*")

	// Setup routes
	api := router.Group("/api/v1")
	authController.RegisterRoutes(api)

	// Add a health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"build":  config.Build,
		})
	})

	// Start server
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	log.Printf("Starting eSign API server on %s", addr)
	
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}