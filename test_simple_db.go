package main

import (
	"database/sql"
	"fmt"
	"log"
	
	_ "github.com/lib/pq"
)

func main() {
	// Test 1: Hardcoded connection string
	fmt.Println("Test 1: Hardcoded connection string")
	connStr1 := "host=localhost port=5432 user=atharvaz dbname=esign_db sslmode=disable"
	fmt.Printf("Connection string: %s\n", connStr1)
	
	db1, err := sql.Open("postgres", connStr1)
	if err != nil {
		log.Printf("Failed to open: %v", err)
	} else {
		err = db1.Ping()
		if err != nil {
			log.Printf("Failed to ping: %v", err)
		} else {
			fmt.Println("✓ Success!")
		}
		db1.Close()
	}
	
	// Test 2: Built connection string
	fmt.Println("\nTest 2: Built connection string")
	host := "localhost"
	port := 5432
	user := "atharvaz"
	password := ""
	dbname := "esign_db"
	sslmode := "disable"
	
	connStr2 := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
	fmt.Printf("Connection string: %s\n", connStr2)
	
	db2, err := sql.Open("postgres", connStr2)
	if err != nil {
		log.Printf("Failed to open: %v", err)
	} else {
		err = db2.Ping()
		if err != nil {
			log.Printf("Failed to ping: %v", err)
		} else {
			fmt.Println("✓ Success!")
		}
		db2.Close()
	}
	
	// Test 3: With empty password field removed
	fmt.Println("\nTest 3: Without empty password")
	connStr3 := fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=%s",
		host, port, user, dbname, sslmode)
	fmt.Printf("Connection string: %s\n", connStr3)
	
	db3, err := sql.Open("postgres", connStr3)
	if err != nil {
		log.Printf("Failed to open: %v", err)
	} else {
		err = db3.Ping()
		if err != nil {
			log.Printf("Failed to ping: %v", err)
		} else {
			fmt.Println("✓ Success!")
		}
		db3.Close()
	}
}