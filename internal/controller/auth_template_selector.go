package controller

import (
	"fmt"
	"strings"

	"github.com/esign-go/internal/service"
	"github.com/gin-gonic/gin"
)

// AuthTemplateSelector handles template selection logic for authentication flows
type AuthTemplateSelector struct {
	config         map[string]TemplateConfig
	defaultConfig  TemplateConfig
}

// TemplateConfig defines templates for different auth modes
type TemplateConfig struct {
	OTPTemplate           string
	OTPTemplateUX         string
	BiometricTemplate     string
	BiometricTemplateUX   string
	IrisTemplate          string
	IrisTemplateUX        string
	OfflineKYCTemplate    string
	OfflineKYCTemplateUX  string
	AuthSelectTemplate    string // For selecting between biometric methods
}

// NewAuthTemplateSelector creates a new template selector
func NewAuthTemplateSelector() *AuthTemplateSelector {
	// Default template configuration
	defaultConfig := TemplateConfig{
		OTPTemplate:          "auth.html",
		OTPTemplateUX:        "auth_otp_ux.html",
		BiometricTemplate:    "auth_biometric_fingerprint.html",
		BiometricTemplateUX:  "auth_biometric_fingerprint_ux.html",
		IrisTemplate:         "auth_biometric_iris.html",
		IrisTemplateUX:       "auth_biometric_iris_ux.html",
		OfflineKYCTemplate:   "auth_offline_kyc.html",
		OfflineKYCTemplateUX: "auth_offline_kyc_ux.html",
		AuthSelectTemplate:   "auth_biometric.html",
	}

	// ASP-specific template configurations
	aspConfigs := map[string]TemplateConfig{
		"HDFC": {
			OTPTemplate:          "custom-asp/hdfc/auth_otp.html",
			OTPTemplateUX:        "custom-asp/hdfc/auth_otp_ux.html",
			BiometricTemplate:    "custom-asp/hdfc/auth_biometric.html",
			BiometricTemplateUX:  "custom-asp/hdfc/auth_biometric_ux.html",
			IrisTemplate:         "custom-asp/hdfc/auth_iris.html",
			IrisTemplateUX:       "custom-asp/hdfc/auth_iris_ux.html",
			OfflineKYCTemplate:   "custom-asp/hdfc/auth_offline_kyc.html",
			OfflineKYCTemplateUX: "custom-asp/hdfc/auth_offline_kyc_ux.html",
			AuthSelectTemplate:   "custom-asp/hdfc/auth_select.html",
		},
		"ICICI": {
			OTPTemplate:          "custom-asp/icici/auth_otp.html",
			OTPTemplateUX:        "custom-asp/icici/auth_otp_ux.html",
			BiometricTemplate:    "custom-asp/icici/auth_biometric.html",
			BiometricTemplateUX:  "custom-asp/icici/auth_biometric_ux.html",
			IrisTemplate:         "custom-asp/icici/auth_iris.html",
			IrisTemplateUX:       "custom-asp/icici/auth_iris_ux.html",
			OfflineKYCTemplate:   "custom-asp/icici/auth_offline_kyc.html",
			OfflineKYCTemplateUX: "custom-asp/icici/auth_offline_kyc_ux.html",
			AuthSelectTemplate:   "custom-asp/icici/auth_select.html",
		},
		"KARNATAKA-GOV": {
			OTPTemplate:          "custom-asp/karnataka-gov/auth_otp.html",
			OTPTemplateUX:        "custom-asp/karnataka-gov/auth_otp_ux.html",
			BiometricTemplate:    "custom-asp/karnataka-gov/auth_biometric.html",
			BiometricTemplateUX:  "custom-asp/karnataka-gov/auth_biometric_ux.html",
			IrisTemplate:         "custom-asp/karnataka-gov/auth_iris.html",
			IrisTemplateUX:       "custom-asp/karnataka-gov/auth_iris_ux.html",
			OfflineKYCTemplate:   "custom-asp/karnataka-gov/auth_offline_kyc.html",
			OfflineKYCTemplateUX: "custom-asp/karnataka-gov/auth_offline_kyc_ux.html",
			AuthSelectTemplate:   "custom-asp/karnataka-gov/auth_select.html",
		},
	}

	return &AuthTemplateSelector{
		config:        aspConfigs,
		defaultConfig: defaultConfig,
	}
}

// GetAuthTemplate returns the appropriate template based on auth mode and ASP
func (ats *AuthTemplateSelector) GetAuthTemplate(authMode string, aspID string, useEnhancedUX bool, c *gin.Context) string {
	// Get ASP config or use default
	config := ats.defaultConfig
	if aspConfig, exists := ats.config[strings.ToUpper(aspID)]; exists {
		config = aspConfig
	}

	// Check for specific auth sub-modes from query params
	biometricType := c.Query("bio_type")
	
	// Determine template based on auth mode
	switch authMode {
	case "1": // OTP
		if useEnhancedUX {
			return config.OTPTemplateUX
		}
		return config.OTPTemplate
		
	case "2": // Biometric
		// Check if specific biometric type is requested
		if biometricType == "iris" {
			if useEnhancedUX {
				return config.IrisTemplateUX
			}
			return config.IrisTemplate
		} else if biometricType == "fingerprint" {
			if useEnhancedUX {
				return config.BiometricTemplateUX
			}
			return config.BiometricTemplate
		} else {
			// Show biometric selection page
			return config.AuthSelectTemplate
		}
		
	case "3": // Iris (legacy mode)
		if useEnhancedUX {
			return config.IrisTemplateUX
		}
		return config.IrisTemplate
		
	case "4": // Offline KYC
		if useEnhancedUX {
			return config.OfflineKYCTemplateUX
		}
		return config.OfflineKYCTemplate
		
	default:
		return "authFail.html"
	}
}

// GetTemplateData prepares template data with ASP-specific customizations
func (ats *AuthTemplateSelector) GetTemplateData(sessionData *service.SessionData, aspID string) gin.H {
	// Base template data
	data := gin.H{
		"bioEnv":      sessionData.BiometricEnv,
		"msg1":        sessionData.LegalName,
		"sid":         sessionData.SignerID,
		"msg3":        sessionData.TransactionID,
		"msg4":        sessionData.Timestamp,
		"ln":          sessionData.LegalName,
		"v1":          sessionData.V1,
		"v2":          sessionData.V2,
		"v3":          sessionData.V3,
		"rid":         sessionData.RequestID,
		"authMod":     sessionData.AuthMode,
		"build":       sessionData.Build,
		"adr":         sessionData.Adr,
		"cv_output":   sessionData.CustomViewOutput,
		"filler1":     sessionData.Filler1,
		"filler2":     sessionData.Filler2,
		"filler3":     sessionData.Filler3,
		"filler4":     sessionData.Filler4,
		"filler5":     sessionData.Filler5,
		
		// Additional fields for templates
		"ASPName":      sessionData.LegalName,
		"TransactionID": sessionData.TransactionID,
		"Timestamp":    sessionData.Timestamp,
	}

	// Add ASP-specific customizations
	switch strings.ToUpper(aspID) {
	case "HDFC":
		data["aspThemeColor"] = "#004c8f"
		data["aspLogoPath"] = "/static/images/hdfc-logo.jpg"
		data["aspName"] = "HDFC Bank"
		
	case "ICICI":
		data["aspThemeColor"] = "#f26522"
		data["aspLogoPath"] = "/static/images/icici-logo.jpg"
		data["aspName"] = "ICICI Bank"
		
	case "KARNATAKA-GOV":
		data["aspThemeColor"] = "#FF9933"
		data["aspLogoPath"] = "/static/images/karnataka-emblem.png"
		data["aspName"] = "Karnataka Government"
		data["enableMultiLang"] = true
		
	default:
		data["aspThemeColor"] = "#0d6efd"
		data["aspLogoPath"] = "/static/images/logo.png"
		data["aspName"] = sessionData.LegalName
	}

	return data
}

// HasCustomTemplate checks if an ASP has custom templates configured
func (ats *AuthTemplateSelector) HasCustomTemplate(aspID string) bool {
	_, exists := ats.config[strings.ToUpper(aspID)]
	return exists
}

// GetErrorTemplate returns the appropriate error template for the ASP
func (ats *AuthTemplateSelector) GetErrorTemplate(errorType string, aspID string) string {
	// Map error types to templates
	templates := map[string]string{
		"expired":   "authExpired.html",
		"failed":    "authFail.html",
		"cancelled": "esign-cancelled.html",
		"error":     "error.html",
		"sigError":  "sigError.html",
	}

	// Check if ASP has custom error templates
	if ats.HasCustomTemplate(aspID) {
		customTemplate := fmt.Sprintf("custom-asp/%s/%s", strings.ToLower(aspID), templates[errorType])
		// In production, check if file exists before returning
		// For now, return the custom path
		return customTemplate
	}

	// Return default template
	if template, exists := templates[errorType]; exists {
		return template
	}
	return "error.html"
}

// GetSuccessTemplate returns the success template for the ASP
func (ats *AuthTemplateSelector) GetSuccessTemplate(aspID string, useEnhancedUX bool) string {
	if ats.HasCustomTemplate(aspID) {
		if useEnhancedUX {
			return fmt.Sprintf("custom-asp/%s/success_ux.html", strings.ToLower(aspID))
		}
		return fmt.Sprintf("custom-asp/%s/success.html", strings.ToLower(aspID))
	}

	if useEnhancedUX {
		return "esign-success_ux.html"
	}
	return "esign-success.html"
}