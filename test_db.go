package main

import (
	"database/sql"
	"fmt"
	"log"
	
	_ "github.com/lib/pq"
)

func main() {
	// Direct connection string
	connStr := "host=localhost port=5432 user=atharvaz dbname=esign_db sslmode=disable"
	
	fmt.Println("Testing database connection...")
	fmt.Println("Connection string:", connStr)
	
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()
	
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping database:", err)
	}
	
	fmt.Println("✓ Database connection successful!")
	
	// Test query
	var result int
	err = db.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		log.Fatal("Failed to execute test query:", err)
	}
	
	fmt.Printf("✓ Test query successful! Result: %d\n", result)
}