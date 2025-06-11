package main

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"time"
)

// EsignResponse represents the response from eSign service
type EsignResponse struct {
	XMLName    xml.Name `xml:"EsignResp"`
	ResCode    string   `xml:"resCode,attr"`
	TxnID      string   `xml:"txn,attr"`
	ErrCode    string   `xml:"errCode,attr"`
	ErrMsg     string   `xml:"errMsg,attr"`
	Timestamp  string   `xml:"ts,attr"`
	Status     string   `xml:"status,attr"`
	Signatures string   `xml:"Signatures"`
}

func main() {
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/", handleHome)
	
	port := ":8091"
	fmt.Printf("Starting callback server on http://localhost%s\n", port)
	fmt.Println("This server will receive and display eSign responses")
	fmt.Println("----------------------------------------")
	
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>eSign Callback Server</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .response { 
            background: #f0f0f0; 
            border: 1px solid #ccc; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px;
        }
        .success { border-color: #4CAF50; background: #e8f5e9; }
        .error { border-color: #f44336; background: #ffebee; }
        .timestamp { color: #666; font-size: 0.9em; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <h1>eSign Callback Server</h1>
    <p>Waiting for callbacks on /callback endpoint...</p>
    <div id="responses"></div>
    
    <script>
        // Auto-refresh every 5 seconds
        setInterval(function() {
            location.reload();
        }, 5000);
    </script>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("\n[%s] Received callback\n", timestamp)
	fmt.Printf("Method: %s\n", r.Method)
	fmt.Printf("Headers:\n")
	for key, values := range r.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}
	
	// Parse form data
	if err := r.ParseForm(); err != nil {
		fmt.Printf("Error parsing form: %v\n", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	
	// Get the response message
	msg := r.FormValue("msg")
	if msg == "" {
		// Try to get from query parameter
		msg = r.URL.Query().Get("msg")
	}
	
	if msg == "" {
		fmt.Println("No 'msg' parameter found")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK - No message"))
		return
	}
	
	fmt.Printf("\nEncoded Response Length: %d\n", len(msg))
	
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		fmt.Printf("Error decoding base64: %v\n", err)
		fmt.Printf("Raw message: %s\n", msg)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK - Decode error"))
		return
	}
	
	fmt.Printf("\nDecoded XML:\n%s\n", string(decoded))
	
	// Try to parse as XML
	var esignResp EsignResponse
	if err := xml.Unmarshal(decoded, &esignResp); err != nil {
		fmt.Printf("Error parsing XML: %v\n", err)
	} else {
		fmt.Printf("\nParsed Response:\n")
		fmt.Printf("  Response Code: %s\n", esignResp.ResCode)
		fmt.Printf("  Transaction ID: %s\n", esignResp.TxnID)
		fmt.Printf("  Status: %s\n", esignResp.Status)
		fmt.Printf("  Timestamp: %s\n", esignResp.Timestamp)
		if esignResp.ErrCode != "" {
			fmt.Printf("  Error Code: %s\n", esignResp.ErrCode)
			fmt.Printf("  Error Message: %s\n", esignResp.ErrMsg)
		}
	}
	
	fmt.Println("----------------------------------------")
	
	// Send response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Callback received successfully"))
}