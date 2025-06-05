package service

import (
	"crypto/x509"
	
	"github.com/esign-go/internal/models"
)

// IEsignService defines the interface for esign service
type IEsignService interface {
	// ParseAndValidateRequest parses and validates the incoming XML request
	ParseAndValidateRequest(xmlData string, clientIP string) (*models.EsignRequest, error)
	
	// Authenticate performs authentication with UIDAI
	Authenticate(request *models.EsignRequest, authData *models.AuthenticationData) (*models.AuthResponse, error)
	
	// GenerateOTP generates OTP for the given Aadhaar
	GenerateOTP(aadhaar string, clientIP string) (*models.OTPResponse, error)
	
	// ValidateOTP validates the OTP
	ValidateOTP(txnID, otp, aadhaar string) (*models.AuthResponse, error)
	
	// GenerateDigitalCertificate generates a digital certificate based on auth response
	GenerateDigitalCertificate(authResponse *models.AuthResponse) (*x509.Certificate, error)
	
	// SignDocuments signs the provided documents
	SignDocuments(documents []models.Document, cert *x509.Certificate) ([]models.SignedDocument, error)
	
	// GetTransactionStatus retrieves the status of a transaction
	GetTransactionStatus(txnID string) (*models.TransactionStatus, error)
	
	// ProcessCallback processes callback from UIDAI
	ProcessCallback(data *models.CallbackData) error
}

// IXMLValidator defines the interface for XML validation
type IXMLValidator interface {
	// ValidateEsignRequest validates the esign request XML against schema
	ValidateEsignRequest(xmlData []byte) error
	
	// ValidateASPSignature validates the ASP's signature on the request
	ValidateASPSignature(xmlData []byte, signature []byte, publicKey []byte) error
}

// ICryptoService defines the interface for cryptographic operations
type ICryptoService interface {
	// SignData signs the given data
	SignData(data []byte) ([]byte, error)
	
	// VerifySignature verifies a signature
	VerifySignature(data, signature, publicKey []byte) error
	
	// EncryptData encrypts data using the public key
	EncryptData(data, publicKey []byte) ([]byte, error)
	
	// DecryptData decrypts data using the private key
	DecryptData(encryptedData []byte) ([]byte, error)
	
	// GenerateKeyPair generates a new RSA key pair
	GenerateKeyPair() (privateKey, publicKey []byte, error)
	
	// GenerateCertificate generates a new X.509 certificate
	GenerateCertificate(subjectInfo *models.SubjectInfo, publicKey []byte) (*x509.Certificate, error)
}

// ITemplateService defines the interface for template rendering
type ITemplateService interface {
	// RenderCustomView renders a custom view template
	RenderCustomView(templateID string, data interface{}) ([]byte, error)
	
	// LoadTemplate loads a template by ID
	LoadTemplate(templateID string) (string, error)
	
	// RegisterTemplate registers a new template
	RegisterTemplate(templateID, templateContent string) error
}

// IUIDAIService defines the interface for UIDAI integration
type IUIDAIService interface {
	// SendAuthRequest sends authentication request to UIDAI
	SendAuthRequest(authRequest *models.UIDAIAuthRequest) (*models.UIDAIAuthResponse, error)
	
	// SendOTPRequest sends OTP request to UIDAI
	SendOTPRequest(otpRequest *models.UIDAIOTPRequest) (*models.UIDAIOTPResponse, error)
	
	// SendEKYCRequest sends eKYC request to UIDAI
	SendEKYCRequest(ekycRequest *models.UIDAIEKYCRequest) (*models.UIDAIEKYCResponse, error)
}

// IAuditService defines the interface for audit logging
type IAuditService interface {
	// LogTransaction logs a transaction
	LogTransaction(transaction *models.Transaction) error
	
	// LogAuthAttempt logs an authentication attempt
	LogAuthAttempt(attempt *models.AuthAttempt) error
	
	// GetTransactionLogs retrieves transaction logs
	GetTransactionLogs(filter *models.TransactionFilter) ([]*models.Transaction, error)
}