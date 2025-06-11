package main

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

func main() {
	// Set config file
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	
	// Read config
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	
	// Debug print all database values
	fmt.Println("=== Raw Viper Values ===")
	fmt.Printf("database.host: %v\n", viper.Get("database.host"))
	fmt.Printf("database.port: %v\n", viper.Get("database.port"))
	fmt.Printf("database.user: %v\n", viper.Get("database.user"))
	fmt.Printf("database.password: %v\n", viper.Get("database.password"))
	fmt.Printf("database.dbname: %v\n", viper.Get("database.dbname"))
	fmt.Printf("database.DBName: %v\n", viper.Get("database.DBName"))
	fmt.Printf("database.sslmode: %v\n", viper.Get("database.sslmode"))
	
	// Try different ways to get the values
	fmt.Println("\n=== GetString Values ===")
	fmt.Printf("database.dbname: %s\n", viper.GetString("database.dbname"))
	fmt.Printf("database.DBName: %s\n", viper.GetString("database.DBName"))
	
	// Check all keys
	fmt.Println("\n=== All Database Keys ===")
	settings := viper.AllSettings()
	if db, ok := settings["database"]; ok {
		if dbMap, ok := db.(map[string]interface{}); ok {
			for k, v := range dbMap {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}
}