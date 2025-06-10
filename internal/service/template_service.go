package service

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
	"sync"

	"github.com/esign-go/internal/models"
	"github.com/esign-go/pkg/errors"
	"github.com/esign-go/pkg/logger"
)

// TemplateService implements ITemplateService interface
type TemplateService struct {
	templates   map[string]*template.Template
	templateDir string
	customViews map[string]map[string]*models.Template // aspID -> templateID -> template
	mu          sync.RWMutex
}

// NewTemplateService creates a new template service instance
func NewTemplateService(templateDir string) *TemplateService {
	return &TemplateService{
		templates:   make(map[string]*template.Template),
		templateDir: templateDir,
		customViews: make(map[string]map[string]*models.Template),
	}
}

// RenderCustomView renders a custom view template for an ASP
func (s *TemplateService) RenderCustomView(aspID, templateID string, params map[string]string, authMode string) (string, error) {
	log := logger.GetLogger()

	// Get template
	tmpl, err := s.GetTemplate(aspID, templateID)
	if err != nil {
		log.WithError(err).Error("Failed to get template")
		return "", err
	}

	// Check if template supports the auth mode
	if !s.supportsAuthMode(tmpl, authMode) {
		return "", errors.NewValidationError(fmt.Sprintf("Template does not support auth mode: %s", authMode))
	}

	// Process template
	result, err := s.ProcessTemplate(tmpl, params)
	if err != nil {
		log.WithError(err).Error("Failed to process template")
		return "", err
	}

	return result, nil
}

// GetTemplate retrieves a template by ASP ID and template ID
func (s *TemplateService) GetTemplate(aspID, templateID string) (*models.Template, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check custom views first
	if aspTemplates, ok := s.customViews[aspID]; ok {
		if tmpl, ok := aspTemplates[templateID]; ok {
			return tmpl, nil
		}
	}

	// Try to load from file system
	tmpl, err := s.loadTemplateFromFile(aspID, templateID)
	if err != nil {
		return nil, fmt.Errorf("template not found: %s/%s", aspID, templateID)
	}

	// Cache the loaded template
	s.cacheTemplate(aspID, templateID, tmpl)

	return tmpl, nil
}

// ProcessTemplate processes a template with the given parameters
func (s *TemplateService) ProcessTemplate(tmpl *models.Template, params map[string]string) (string, error) {
	// Validate required parameters
	for _, varName := range tmpl.Variables {
		if _, ok := params[varName]; !ok && isRequiredVariable(varName) {
			return "", errors.NewValidationError(fmt.Sprintf("Missing required parameter: %s", varName))
		}
	}

	// Parse template content
	t, err := template.New(tmpl.ID).Parse(tmpl.Content)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Add helper functions
	t = t.Funcs(s.getTemplateFuncs())

	// Execute template
	var buf bytes.Buffer
	if err := t.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// LoadDefaultTemplates loads default templates from the file system
func (s *TemplateService) LoadDefaultTemplates() error {
	log := logger.GetLogger()

	// Default template names
	defaultTemplates := []string{
		"auth",
		"auth_biometric",
		"auth_biometric_iris",
		"authFail",
		"rd",
		"esignFailed",
		"sigError",
	}

	for _, tmplName := range defaultTemplates {
		tmplPath := filepath.Join(s.templateDir, tmplName)
		content, err := ioutil.ReadFile(tmplPath)
		if err != nil {
			log.WithError(err).Warnf("Failed to load default template: %s", tmplName)
			continue
		}

		// Parse and cache template
		tmpl, err := template.New(tmplName).Parse(string(content))
		if err != nil {
			log.WithError(err).Errorf("Failed to parse template: %s", tmplName)
			continue
		}

		s.templates[tmplName] = tmpl
	}

	return nil
}

// RegisterCustomView registers a custom view template for an ASP
func (s *TemplateService) RegisterCustomView(aspID string, tmpl *models.Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate template
	if err := s.validateTemplate(tmpl); err != nil {
		return err
	}

	// Initialize ASP templates map if needed
	if _, ok := s.customViews[aspID]; !ok {
		s.customViews[aspID] = make(map[string]*models.Template)
	}

	// Store template
	s.customViews[aspID][tmpl.ID] = tmpl

	return nil
}

// Helper methods

func (s *TemplateService) loadTemplateFromFile(aspID, templateID string) (*models.Template, error) {
	// Construct file path
	tmplPath := filepath.Join(s.templateDir, "custom", aspID, templateID+".html")

	// Read file
	content, err := ioutil.ReadFile(tmplPath)
	if err != nil {
		return nil, err
	}

	// Parse metadata from content (if embedded)
	tmpl := &models.Template{
		ID:      templateID,
		AspID:   aspID,
		Name:    templateID,
		Content: string(content),
	}

	// Extract variables from template
	tmpl.Variables = s.extractVariables(tmpl.Content)

	// Default auth modes if not specified
	if len(tmpl.AuthModes) == 0 {
		tmpl.AuthModes = []string{"1", "2", "3"} // OTP, Bio, Iris
	}

	return tmpl, nil
}

func (s *TemplateService) cacheTemplate(aspID, templateID string, tmpl *models.Template) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.customViews[aspID]; !ok {
		s.customViews[aspID] = make(map[string]*models.Template)
	}

	s.customViews[aspID][templateID] = tmpl
}

func (s *TemplateService) supportsAuthMode(tmpl *models.Template, authMode string) bool {
	for _, mode := range tmpl.AuthModes {
		if mode == authMode {
			return true
		}
	}
	return false
}

func (s *TemplateService) validateTemplate(tmpl *models.Template) error {
	if tmpl.ID == "" {
		return errors.NewValidationError("Template ID is required")
	}

	if tmpl.Content == "" {
		return errors.NewValidationError("Template content is required")
	}

	// Validate template syntax
	if _, err := template.New(tmpl.ID).Parse(tmpl.Content); err != nil {
		return errors.NewValidationError(fmt.Sprintf("Invalid template syntax: %v", err))
	}

	return nil
}

func (s *TemplateService) extractVariables(content string) []string {
	// Extract template variables using regex or template parsing
	vars := make(map[string]bool)

	// Simple extraction of {{.Variable}} patterns
	// In production, use proper template parsing
	tmpl, err := template.New("temp").Parse(content)
	log.Println("Template parsed successfully", tmpl)
	if err != nil {
		return []string{}
	}

	// Get all actions from the template tree
	// This is a simplified approach
	commonVars := []string{
		"rid", "contextPath", "msg1", "msg3", "msg4",
		"v1", "v2", "v3", "ln", "bioEnv", "adr",
		"authMod", "sid", "build",
	}

	for _, v := range commonVars {
		if strings.Contains(content, "{{."+v+"}}") || strings.Contains(content, "{{ ."+v+" }}") {
			vars[v] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(vars))
	for v := range vars {
		result = append(result, v)
	}

	return result
}

func (s *TemplateService) getTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper":    strings.ToUpper,
		"lower":    strings.ToLower,
		"trim":     strings.TrimSpace,
		"contains": strings.Contains,
		"replace":  strings.Replace,
		"split":    strings.Split,
		"join":     strings.Join,
		"default": func(defaultVal, val string) string {
			if val == "" {
				return defaultVal
			}
			return val
		},
		"mask": func(val string, showLast int) string {
			if len(val) <= showLast {
				return val
			}
			masked := strings.Repeat("*", len(val)-showLast)
			return masked + val[len(val)-showLast:]
		},
		"formatDate": func(date, format string) string {
			// Simple date formatting
			return date
		},
	}
}

func isRequiredVariable(varName string) bool {
	// Define which variables are required
	required := map[string]bool{
		"rid":     true,
		"msg1":    true,
		"msg3":    true,
		"authMod": true,
	}

	return required[varName]
}

// GetStandardTemplate returns a standard template by name
func (s *TemplateService) GetStandardTemplate(name string) (*template.Template, error) {
	if tmpl, ok := s.templates[name]; ok {
		return tmpl, nil
	}

	return nil, fmt.Errorf("standard template not found: %s", name)
}
