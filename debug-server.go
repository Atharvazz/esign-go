package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func main() {
	// Show current working directory
	cwd, _ := os.Getwd()
	fmt.Println("=== Debug Information ===")
	fmt.Printf("Current Working Directory: %s\n", cwd)
	
	// Check if templates directory exists
	templatesPath := filepath.Join(cwd, "templates")
	fmt.Printf("Templates Path: %s\n", templatesPath)
	
	if stat, err := os.Stat(templatesPath); err == nil {
		fmt.Printf("Templates directory exists: %v\n", stat.IsDir())
		
		// List all files in templates directory
		files, _ := ioutil.ReadDir(templatesPath)
		fmt.Println("\nFiles in templates directory:")
		for _, file := range files {
			fmt.Printf("  - %s (size: %d bytes)\n", file.Name(), file.Size())
		}
	} else {
		fmt.Printf("ERROR: Templates directory not found: %v\n", err)
	}
	
	// Try to load templates with Gin
	fmt.Println("\n=== Gin Template Loading ===")
	gin.SetMode(gin.DebugMode)
	router := gin.New()
	
	// This will show debug output about template loading
	router.LoadHTMLGlob("templates/*")
	
	// Test endpoint
	router.GET("/test", func(c *gin.Context) {
		// Try to render rd.html
		c.HTML(200, "rd.html", gin.H{
			"msg": "Test",
			"u":   "http://test.com",
		})
	})
	
	// List all routes
	fmt.Println("\n=== Routes ===")
	for _, route := range router.Routes() {
		fmt.Printf("%s %s\n", route.Method, route.Path)
	}
	
	fmt.Println("\nStarting debug server on :9999")
	fmt.Println("Visit http://localhost:9999/test to test template rendering")
	
	router.Run(":9999")
}