package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	// Get the current directory
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	// Create file server
	fs := http.FileServer(http.Dir(dir))
	http.Handle("/", fs)

	// CORS middleware for API calls
	corsHandler := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			h.ServeHTTP(w, r)
		})
	}

	// Start server
	port := "3000"
	fmt.Printf("🌐 Frontend server starting on http://localhost:%s\n", port)
	fmt.Printf("📁 Serving files from: %s\n", dir)
	fmt.Println("\nAvailable pages:")
	fmt.Println("  • http://localhost:3000/index.html - Main portal")
	fmt.Println("  • http://localhost:3000/esign-test.html - eSign test interface")
	fmt.Println("  • http://localhost:3000/check-status.html - Status checker")
	fmt.Println("\nPress Ctrl+C to stop the server")
	
	log.Fatal(http.ListenAndServe(":"+port, corsHandler(fs)))
}