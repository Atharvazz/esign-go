package main

import (
	"database/sql"
	"log"
	"net/http"
	"fmt"
	
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"github.com/esign-go/internal/repository"
	"time"
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
	}
	
	// Simple Gin server
	router := gin.Default()
	
	// Load templates
	router.LoadHTMLGlob("templates/*")
	
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
		})
	})
	
	// Serve test forms
	router.StaticFile("/test-esign-form.html", "./test-esign-form.html")
	router.StaticFile("/test-esign-enhanced.html", "./test-esign-enhanced.html")
	
	log.Println("Starting server on :8090...")
	log.Println("Test URLs:")
	log.Println("  Health: http://localhost:8090/health")
	log.Println("  Test Form: http://localhost:8090/test-esign-form.html")
	log.Println("  Enhanced Test: http://localhost:8090/test-esign-enhanced.html")
	
	if err := router.Run(":8090"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}