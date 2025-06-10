package service

import (
	"net/http"
	
	"github.com/esign-go/internal/models"
)


// IXMLValidator defines the interface for XML validation
type IXMLValidator interface {
	// ValidateEsignRequest validates the esign request XML against schema
	ValidateEsignRequest(xmlData []byte) error
	
	// ValidateASPSignature validates the ASP's signature on the request
	ValidateASPSignature(xmlData []byte, signature []byte, publicKey []byte) error
}

// ICryptoService defines the interface for cryptographic operations
type ICryptoService interface {
	// SignXML signs XML document
	SignXML(xmlData string, privateKey, certificate []byte) (string, error)
	
	// VerifyXMLSignature verifies XML signature
	VerifyXMLSignature(xmlData string) (*models.SignatureInfo, error)
	
	// GenerateCertificate generates X.509 certificate
	GenerateCertificate(subject *models.SubjectInfo, validityDays int) ([]byte, []byte, error)
	
	// EncryptData encrypts data using public key
	EncryptData(data []byte, publicKey []byte) ([]byte, error)
	
	// DecryptData decrypts data using private key
	DecryptData(encryptedData []byte, privateKey []byte) ([]byte, error)
	
	// GenerateHash generates hash of data
	GenerateHash(data []byte, algorithm string) (string, error)
	
	// VerifyHash verifies hash of data
	VerifyHash(data []byte, hash string, algorithm string) bool
}

// IKYCService defines the interface for KYC service
type IKYCService interface {
	// GenerateOTP generates OTP for Aadhaar
	GenerateOTP(aadhaar string, requestID int64, req *http.Request, txn, aspID string, attempts int) (*models.OTPGenerationResponse, error)
	
	// VerifyOTP verifies OTP
	VerifyOTP(otpTxn, otp, aadhaar string, requestID int64, req *http.Request, txn, aspID string) (*models.AadhaarDetailsVO, error)
	
	// AuthenticateBiometric authenticates using biometric data
	AuthenticateBiometric(bioData *models.BiometricData, requestID int64, req *http.Request, txn, aspID string) (*models.AadhaarDetailsVO, error)
	
	// PerformOfflineKYC performs offline KYC
	PerformOfflineKYC(xmlData string, shareCode string, requestID int64) (*models.AadhaarDetailsVO, error)
	
	// ProcessOkycOTPRequest processes offline KYC OTP request
	ProcessOkycOTPRequest(req *models.OkycOtpRequest, clientIP string) (*models.OKYCOTPResponse, error)
	
	// VerifyOkycOTP verifies offline KYC OTP
	VerifyOkycOTP(req *models.OkycVerificationModel, clientIP string) (*models.OkycVerificationResponse, error)

	// ProcessFaceRecognition processes face recognition request
	ProcessFaceRecognition(req *models.FaceRecognitionRequest, clientIP string) (*models.FaceRecognitionResult, error)
}

// ITemplateService defines the interface for template service
type ITemplateService interface {
	// RenderCustomView renders custom view template
	RenderCustomView(aspID, templateID string, params map[string]string, authMode string) (string, error)
	
	// GetTemplate gets template by ID
	GetTemplate(aspID, templateID string) (*models.Template, error)
	
	// ProcessTemplate processes template with parameters
	ProcessTemplate(template *models.Template, params map[string]string) (string, error)
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

// IRemoteSigningService defines the interface for remote signing
type IRemoteSigningService interface {
	// SignDocument signs a document remotely
	SignDocument(docHash string, certificate []byte, privateKey []byte) (string, error)
	
	// SignMultipleDocuments signs multiple documents
	SignMultipleDocuments(docHashes []string, certificate []byte, privateKey []byte) ([]string, error)
	
	// GetSigningCertificate gets signing certificate for user
	GetSigningCertificate(userID string, kycData *models.AadhaarDetailsVO) ([]byte, []byte, error)

	// HealthCheck checks remote signing service health
	HealthCheck() error

	// GenerateErrorResponse generates an error response
	GenerateErrorResponse(errorCode, errorMessage string) string
}

// Missing interface methods to add to IEsignService
type IEsignServiceExtended interface {
	IEsignService
	// ValidateAndProcessCheckStatus validates and processes check status request
	ValidateAndProcessCheckStatus(xmlData string, req *http.Request) (string, error)
	
	// CheckTransactionStatus checks transaction status by ASP ID and TXN
	CheckTransactionStatus(aspID, txnID string) (*models.EsignStatusVO, error)
	
	// GenerateSignedXMLResponse generates signed XML response
	GenerateSignedXMLResponse(requestID int64, errCode, errMsg, status, txn, resCode, clientIP string) (string, error)
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