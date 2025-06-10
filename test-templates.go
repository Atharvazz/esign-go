package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	// Set Gin to debug mode
	gin.SetMode(gin.DebugMode)
	
	// Create router
	router := gin.Default()
	
	// Load templates
	router.LoadHTMLGlob("templates/*")
	
	// List loaded templates
	fmt.Println("Testing template loading...")
	
	// Test endpoints
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": "Test message",
			"u":   "http://example.com",
		})
	})
	
	router.GET("/list", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"templates": "Check console output for loaded templates",
			"test_url":  "http://localhost:8081/",
		})
	})
	
	fmt.Println("\nTest server running on :8081")
	fmt.Println("Visit http://localhost:8081/ to test rd.html template")
	
	if err := router.Run(":8081"); err != nil {
		log.Fatal(err)
	}
}