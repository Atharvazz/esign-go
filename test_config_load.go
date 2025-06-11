package main

import (
	"fmt"
	"log"
	
	"github.com/esign-go/internal/config"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Print database config
	fmt.Println("=== Loaded Configuration ===")
	fmt.Printf("Database Host: %s\n", cfg.Database.Host)
	fmt.Printf("Database Port: %d\n", cfg.Database.Port)
	fmt.Printf("Database User: %s\n", cfg.Database.User)
	fmt.Printf("Database Name: %s\n", cfg.Database.DBName)
	fmt.Printf("Database SSLMode: %s\n", cfg.Database.SSLMode)
	
	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, 
		cfg.Database.Password, cfg.Database.DBName, cfg.Database.SSLMode,
	)
	
	fmt.Printf("\nConnection String: %s\n", connStr)
}