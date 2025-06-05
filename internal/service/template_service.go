package service

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
)

// TemplateService implements the ITemplateService interface
type TemplateService struct {
	templatePath string
	templates    map[string]*template.Template
	mu           sync.RWMutex
	cacheEnabled bool
}

// NewTemplateService creates a new template service
func NewTemplateService(templatePath string) *TemplateService {
	return &TemplateService{
		templatePath: templatePath,
		templates:    make(map[string]*template.Template),
		cacheEnabled: true,
	}
}

// RenderCustomView renders a custom view template
func (ts *TemplateService) RenderCustomView(templateID string, data interface{}) ([]byte, error) {
	// Load template
	tmpl, err := ts.loadTemplate(templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to load template: %w", err)
	}

	// Render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to render template: %w", err)
	}

	return buf.Bytes(), nil
}

// LoadTemplate loads a template by ID
func (ts *TemplateService) LoadTemplate(templateID string) (string, error) {
	// Construct template path
	templatePath := filepath.Join(ts.templatePath, templateID+".html")

	// Read template file
	content, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to read template file: %w", err)
	}

	return string(content), nil
}

// RegisterTemplate registers a new template
func (ts *TemplateService) RegisterTemplate(templateID, templateContent string) error {
	// Parse template
	tmpl, err := template.New(templateID).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Store in cache
	ts.mu.Lock()
	ts.templates[templateID] = tmpl
	ts.mu.Unlock()

	// Optionally save to file
	if ts.templatePath != "" {
		templatePath := filepath.Join(ts.templatePath, templateID+".html")
		if err := ioutil.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
			return fmt.Errorf("failed to save template file: %w", err)
		}
	}

	return nil
}

// loadTemplate loads a template with caching
func (ts *TemplateService) loadTemplate(templateID string) (*template.Template, error) {
	// Check cache first
	if ts.cacheEnabled {
		ts.mu.RLock()
		tmpl, exists := ts.templates[templateID]
		ts.mu.RUnlock()

		if exists {
			return tmpl, nil
		}
	}

	// Load from file
	content, err := ts.LoadTemplate(templateID)
	if err != nil {
		return nil, err
	}

	// Parse template with custom functions
	tmpl, err := template.New(templateID).Funcs(ts.getTemplateFuncs()).Parse(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Cache template
	if ts.cacheEnabled {
		ts.mu.Lock()
		ts.templates[templateID] = tmpl
		ts.mu.Unlock()
	}

	return tmpl, nil
}

// getTemplateFuncs returns custom template functions
func (ts *TemplateService) getTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper":       strings.ToUpper,
		"lower":       strings.ToLower,
		"title":       strings.Title,
		"trim":        strings.TrimSpace,
		"replace":     strings.ReplaceAll,
		"contains":    strings.Contains,
		"hasPrefix":   strings.HasPrefix,
		"hasSuffix":   strings.HasSuffix,
		"maskAadhaar": maskAadhaar,
		"formatDate":  formatDate,
		"formatTime":  formatTime,
		"safeHTML":    safeHTML,
		"safeURL":     safeURL,
		"safeJS":      safeJS,
	}
}

// Template helper functions

func maskAadhaar(aadhaar string) string {
	if len(aadhaar) < 4 {
		return aadhaar
	}
	return "XXXX-XXXX-" + aadhaar[len(aadhaar)-4:]
}

func formatDate(t interface{}) string {
	switch v := t.(type) {
	case string:
		return v
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func formatTime(t interface{}) string {
	switch v := t.(type) {
	case string:
		return v
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func safeHTML(s string) template.HTML {
	return template.HTML(s)
}

func safeURL(s string) template.URL {
	return template.URL(s)
}

func safeJS(s string) template.JS {
	return template.JS(s)
}

// DefaultTemplateRenderer provides default template rendering
type DefaultTemplateRenderer struct {
	templates map[string]string
}

// NewDefaultTemplateRenderer creates a new default template renderer
func NewDefaultTemplateRenderer() *DefaultTemplateRenderer {
	return &DefaultTemplateRenderer{
		templates: getDefaultTemplates(),
	}
}

// Render renders a default template
func (dtr *DefaultTemplateRenderer) Render(templateName string, data interface{}) ([]byte, error) {
	tmplContent, exists := dtr.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	tmpl, err := template.New(templateName).Parse(tmplContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to render template: %w", err)
	}

	return buf.Bytes(), nil
}

// getDefaultTemplates returns default template definitions
func getDefaultTemplates() map[string]string {
	return map[string]string{
		"esign_auth": defaultEsignAuthTemplate,
		"otp_input":  defaultOTPInputTemplate,
		"success":    defaultSuccessTemplate,
		"error":      defaultErrorTemplate,
	}
}

// Default template definitions
const (
	defaultEsignAuthTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>eSign Authentication</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; }
        .info { background: #e9ecef; padding: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>eSign Authentication</h1>
        <div class="info">
            <p><strong>Transaction ID:</strong> {{.aspTxnId}}</p>
            <p><strong>ASP ID:</strong> {{.aspId}}</p>
        </div>
        
        <form method="POST" action="{{.contextPath}}/authenticate/es">
            <input type="hidden" name="requestId" value="{{.requestId}}">
            
            <div class="form-group">
                <label for="aadhaar">Aadhaar Number:</label>
                <input type="text" id="aadhaar" name="aadhaar" pattern="[0-9]{12}" maxlength="12" required>
            </div>
            
            <div class="form-group">
                <label for="authMode">Authentication Mode:</label>
                <select id="authMode" name="authMode" required>
                    <option value="OTP">OTP</option>
                    <option value="BIO">Biometric</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>
                    <input type="checkbox" name="consent" value="Y" required>
                    I consent to authenticate and sign the documents
                </label>
            </div>
            
            <button type="submit">Authenticate</button>
        </form>
    </div>
</body>
</html>`

	defaultOTPInputTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Enter OTP</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 400px; margin: 0 auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"] { width: 100%; padding: 8px; font-size: 18px; text-align: center; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .info { background: #e9ecef; padding: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Enter OTP</h1>
        <div class="info">
            <p>OTP has been sent to your registered mobile number: {{.maskedMobile}}</p>
        </div>
        
        <form method="POST" action="/authenticate/validate-otp">
            <input type="hidden" name="txnId" value="{{.txnId}}">
            <input type="hidden" name="aadhaar" value="{{.aadhaar}}">
            
            <div class="form-group">
                <label for="otp">Enter OTP:</label>
                <input type="text" id="otp" name="otp" pattern="[0-9]{6}" maxlength="6" required autofocus>
            </div>
            
            <button type="submit">Verify OTP</button>
        </form>
    </div>
</body>
</html>`

	defaultSuccessTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>eSign Successful</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .success { background: #d4edda; color: #155724; padding: 15px; margin-bottom: 20px; }
        .details { background: #f8f9fa; padding: 15px; }
        .details dt { font-weight: bold; }
        .details dd { margin-bottom: 10px; }
    </style>
    <script>
        // Auto-redirect after 5 seconds
        setTimeout(function() {
            window.location.href = '{{.redirectUrl}}';
        }, 5000);
    </script>
</head>
<body>
    <div class="container">
        <div class="success">
            <h1>Documents Signed Successfully!</h1>
            <p>Your documents have been digitally signed.</p>
        </div>
        
        <div class="details">
            <h2>Details</h2>
            <dl>
                <dt>Transaction ID:</dt>
                <dd>{{.response.RequestID}}</dd>
                
                <dt>Status:</dt>
                <dd>{{.response.Status}}</dd>
                
                <dt>Timestamp:</dt>
                <dd>{{.response.Timestamp}}</dd>
                
                <dt>Documents Signed:</dt>
                <dd>{{len .response.SignedDocs}}</dd>
            </dl>
        </div>
        
        <p>You will be redirected in 5 seconds...</p>
    </div>
</body>
</html>`

	defaultErrorTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; margin-bottom: 20px; }
        .details { background: #f8f9fa; padding: 15px; }
        button { padding: 10px 20px; background: #dc3545; color: white; border: none; cursor: pointer; }
        button:hover { background: #c82333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error">
            <h1>Error Occurred</h1>
            <p>{{.error}}</p>
        </div>
        
        <div class="details">
            <p><strong>Error Type:</strong> {{.errorType}}</p>
            <p><strong>Request ID:</strong> {{.requestId}}</p>
        </div>
        
        <button onclick="window.history.back()">Go Back</button>
    </div>
</body>
</html>`
)
