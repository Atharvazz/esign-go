package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
	
	"github.com/esign-go/internal/config"
	_ "github.com/lib/pq"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Print database config
	fmt.Println("=== Config Values ===")
	fmt.Printf("cfg.Database.Host: %s\n", cfg.Database.Host)
	fmt.Printf("cfg.Database.Port: %d\n", cfg.Database.Port)
	fmt.Printf("cfg.Database.User: %s\n", cfg.Database.User)
	fmt.Printf("cfg.Database.DBName: %s\n", cfg.Database.DBName)
	fmt.Printf("cfg.Database.SSLMode: %s\n", cfg.Database.SSLMode)
	
	// Build connection string step by step
	fmt.Println("\n=== Building Connection String ===")
	host := cfg.Database.Host
	port := cfg.Database.Port
	user := cfg.Database.User
	password := cfg.Database.Password
	dbname := cfg.Database.DBName
	sslmode := cfg.Database.SSLMode
	
	fmt.Printf("host: %s\n", host)
	fmt.Printf("port: %d\n", port)
	fmt.Printf("user: %s\n", user)
	fmt.Printf("password: %s\n", password)
	fmt.Printf("dbname: %s\n", dbname)
	fmt.Printf("sslmode: %s\n", sslmode)
	
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)
	
	fmt.Printf("\nFinal Connection String: %s\n", connStr)
	
	// Try direct connection
	fmt.Println("\n=== Direct Connection Test ===")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	
	fmt.Println("✓ Database connected successfully!")
}