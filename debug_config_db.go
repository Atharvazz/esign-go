package main

import (
	"fmt"
	"log"
	
	"github.com/esign-go/internal/config"
	"github.com/esign-go/internal/repository"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Print database config
	fmt.Println("=== Database Configuration ===")
	fmt.Printf("Host: %s\n", cfg.Database.Host)
	fmt.Printf("Port: %d\n", cfg.Database.Port)
	fmt.Printf("User: %s\n", cfg.Database.User)
	fmt.Printf("DBName: %s\n", cfg.Database.DBName)
	fmt.Printf("SSLMode: %s\n", cfg.Database.SSLMode)
	
	// Build connection string manually
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, 
		cfg.Database.Password, cfg.Database.DBName, cfg.Database.SSLMode,
	)
	
	fmt.Printf("\nConnection String: %s\n", connStr)
	
	// Try to initialize DB
	fmt.Println("\n=== Attempting Database Connection ===")
	db, err := repository.InitDB(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	
	fmt.Println("✓ Database connected successfully!")
}