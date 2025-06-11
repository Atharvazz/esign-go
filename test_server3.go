package main

import (
	"database/sql"
	"log"
	"net/http"
	"fmt"
	"time"
	
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/esign-go/internal/repository"
)

func main() {
	log.Println("Starting test server with direct connection...")
	
	// Direct connection
	connStr := "host=localhost port=5432 user=atharvaz dbname=esign_db sslmode=disable"
	log.Printf("Connection string: %s", connStr)
	
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
		log.Printf("Warning: Failed to run migrations: %v", err)
		// Continue anyway for testing
	} else {
		log.Println("✓ Migrations completed successfully!")
	}
	
	// Simple Gin server
	router := gin.Default()
	
	// Load templates with proper pattern
	router.LoadHTMLGlob("templates/*.html")
	
	// Static files
	router.Static("/static", "./static")
	
	// Test endpoints
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"database": "connected",
			"timestamp": fmt.Sprintf("%v", time.Now()),
		})
	})
	
	router.GET("/test", func(c *gin.Context) {
		c.HTML(http.StatusOK, "auth.html", gin.H{
			"title": "Test Page",
			"msg1": "Test ASP",
			"msg3": "TEST-TXN-001",
			"msg4": fmt.Sprintf("%v", time.Now()),
			"rid": 12345,
			"ln": "Test Legal Name",
			"v1": "Test Purpose",
			"build": "1.0.0",
		})
	})
	
	// API endpoint to test
	router.POST("/api/test", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"received": body,
			"timestamp": time.Now(),
		})
	})
	
	// Callback endpoint for eSign responses
	router.POST("/callback", func(c *gin.Context) {
		// Log the callback
		log.Printf("Callback received from: %s", c.ClientIP())
		
		// Read the body
		body, err := c.GetRawData()
		if err != nil {
			log.Printf("Error reading callback body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			return
		}
		
		log.Printf("Callback body: %s", string(body))
		
		// Try to parse as form data
		if err := c.Request.ParseForm(); err == nil {
			for key, values := range c.Request.PostForm {
				log.Printf("Form field %s: %v", key, values)
			}
		}
		
		c.JSON(http.StatusOK, gin.H{
			"message": "Callback received successfully",
			"status": "success",
			"timestamp": fmt.Sprintf("%v", time.Now()),
		})
	})
	
	// GET version of callback for testing
	router.GET("/callback", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Callback endpoint is working",
			"status": "ready",
			"timestamp": fmt.Sprintf("%v", time.Now()),
		})
	})
	
	// Serve test forms
	router.StaticFile("/test-esign-form.html", "./test-esign-form.html")
	router.StaticFile("/test-esign-enhanced.html", "./test-esign-enhanced.html")
	router.StaticFile("/showcase", "./test-template-showcase.html")
	
	log.Println("✓ Server started successfully on :8090")
	log.Println("\nTest URLs:")
	log.Println("  Health Check:    http://localhost:8090/health")
	log.Println("  Test Page:       http://localhost:8090/test")
	log.Println("  Test Form:       http://localhost:8090/test-esign-form.html")
	log.Println("  Enhanced Test:   http://localhost:8090/test-esign-enhanced.html")
	log.Println("\nPress Ctrl+C to stop the server")
	
	if err := router.Run(":8090"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}