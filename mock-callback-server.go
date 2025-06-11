package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	// Callback handler
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		
		fmt.Printf("\n%s=============== CALLBACK RECEIVED ===============%s\n", "\033[32m", "\033[0m")
		fmt.Printf("Time: %s\n", timestamp)
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("\nHeaders:\n")
		for k, v := range r.Header {
			fmt.Printf("  %s: %s\n", k, v)
		}
		
		// Parse form data
		if err := r.ParseForm(); err == nil && len(r.Form) > 0 {
			fmt.Printf("\nForm Data:\n")
			for k, v := range r.Form {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
		
		// Read body
		body, err := io.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			fmt.Printf("\nBody:\n%s\n", string(body))
			
			// Try to parse as JSON
			var jsonData interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				pretty, _ := json.MarshalIndent(jsonData, "", "  ")
				fmt.Printf("\nParsed JSON:\n%s\n", string(pretty))
			}
		}
		
		fmt.Printf("%s=================================================%s\n\n", "\033[32m", "\033[0m")
		
		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"message": "Callback received",
			"timestamp": timestamp,
		})
	})
	
	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"service": "Mock Callback Server",
		})
	})
	
	// Home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
<!DOCTYPE html>
<html>
<head>
    <title>Mock Callback Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .status { color: green; font-weight: bold; }
        .endpoint { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }
        code { background: #e0e0e0; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Mock Callback Server</h1>
    <p class="status">✓ Server is running on port 8090</p>
    
    <h2>Available Endpoints:</h2>
    <div class="endpoint">
        <strong>POST /callback</strong> - Receives eSign callbacks
    </div>
    <div class="endpoint">
        <strong>GET /health</strong> - Health check endpoint
    </div>
    
    <h2>Usage:</h2>
    <p>Use <code>http://localhost:8091/callback</code> as your callback URL in eSign requests.</p>
    <p>Check the terminal to see incoming callback data.</p>
</body>
</html>`
		
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})
	
	fmt.Println("🚀 Mock Callback Server starting on http://localhost:8091")
	fmt.Println("📝 Callback endpoint: http://localhost:8091/callback")
	fmt.Println("💚 Health check: http://localhost:8091/health")
	fmt.Println("\nWaiting for callbacks...\n")
	
	log.Fatal(http.ListenAndServe(":8091", nil))
}