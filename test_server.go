package main

import (
	"log"
	"net/http"
	
	"github.com/gin-gonic/gin"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/internal/config"
)

func main() {
	// Create a test config with correct database settings
	cfg := &config.Config{
		Server: config.ServerConfig{
			Address: ":8090",
		},
		Database: config.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "atharvaz",
			Password: "",
			DBName:   "esign_db",
			SSLMode:  "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 25,
		},
	}
	
	log.Println("Starting test server with hardcoded config...")
	log.Printf("Database: %s@%s:%d/%s", cfg.Database.User, cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
	
	// Initialize database
	db, err := repository.InitDB(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	
	log.Println("✓ Database connected successfully!")
	
	// Run migrations
	if err := repository.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	
	log.Println("✓ Migrations completed successfully!")
	
	// Simple Gin server
	router := gin.Default()
	
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"database": "connected",
		})
	})
	
	log.Println("Starting server on :8090...")
	if err := router.Run(":8090"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}