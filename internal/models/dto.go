package models

import (
	"crypto/x509"
	"time"
)

// EsignRequestDTO represents the esign request data transfer object
type EsignRequestDTO struct {
	RequestID         int64              `json:"requestId"`
	EsignRequest      *EsignRequest      `json:"esignRequest"`
	AspID             string             `json:"aspId"`
	LegalName         string             `json:"legalName"`
	V1                string             `json:"v1"`
	V2                string             `json:"v2"`
	V3                string             `json:"v3"`
	ResponseURL       string             `json:"responseUrl"`
	ErrorMsg          string             `json:"errorMsg,omitempty"`
	IsError           bool               `json:"isError"`
	IsReSubmit        bool               `json:"isReSubmit"`
	Txn               string             `json:"txn"`
	OtpRetryAttempts  int                `json:"otpRetryAttempts"`
	AuthAttempts      int                `json:"authAttempts"`
	Adr               string             `json:"adr"` // Last 4 digits of Aadhaar
	Subject           string             `json:"subject,omitempty"`
	CertificateSerial string             `json:"certificateSerial,omitempty"`
	AumID             string             `json:"aumId,omitempty"`
	Status            int                `json:"status"`
	CreatedOn         time.Time          `json:"createdOn"`
	CancelReason      string             `json:"cancelReason,omitempty"`
	ErrorCode         string             `json:"errorCode,omitempty"`
	RequestTransition string             `json:"requestTransition"`
	KycID             int64              `json:"kycId,omitempty"`
	KYC               *EsignKycDetailDTO `json:"kyc,omitempty"`
}

// EsignRequest represents the parsed esign XML request
type EsignRequest struct {
	Ver             string `xml:"ver,attr"`
	Sc              string `xml:"sc,attr"`
	Ts              string `xml:"ts,attr"`
	Txn             string `xml:"txn,attr"`
	EkycID          string `xml:"ekycId,attr"`
	EkycIDType      string `xml:"ekycIdType,attr"`
	AspID           string `xml:"aspId,attr"`
	AuthMode        string `xml:"AuthMode,attr"`
	ResponseSigType string `xml:"responseSigType,attr"`
	ResponseURL     string `xml:"responseUrl,attr"`
	SignerID        string `xml:"signerid,attr"`
	MaxWaitPeriod   string `xml:"maxWaitPeriod,attr"`
	RedirectURL     string `xml:"redirectUrl,attr"`
	SigningAlgo     string `xml:"signingAlgorithm,attr"`
	Docs            *Docs  `xml:"Docs"`
}

// Docs represents the documents section in esign request
type Docs struct {
	InputHash []InputHash `xml:"InputHash"`
}

// InputHash represents a document hash in the request
type InputHash struct {
	ID            string `xml:"id,attr"`
	HashAlgorithm string `xml:"hashAlgorithm,attr"`
	DocInfo       string `xml:"docInfo,attr"`
	Value         string `xml:",chardata"`
}

// SignatureInfo contains information about XML signature
type SignatureInfo struct {
	Subject       string
	SerialNumber  string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	SignatureAlgo string
	Certificate   *x509.Certificate
}

// OTPGenerationResponse represents OTP generation response
type OTPGenerationResponse struct {
	Status       string `json:"status"`
	OtpTxn       string `json:"otpTxn"`
	MaskedMobile string `json:"maskedMobile"`
	RetryCount   int    `json:"retryCount"`
}

// OTPRequest represents OTP generation request
type OTPRequest struct {
	RequestID int64  `json:"rid"`
	Aadhaar   string `json:"uid"`
}

// OTPResponse represents OTP response
type OTPResponse struct {
	Status     string `json:"status"`
	Msg        string `json:"msg"`
	Form       string `json:"form,omitempty"`
	OtpTxn     string `json:"otpTxn,omitempty"`
	RetryCount int    `json:"retryCount"`
}

// OTPVerifyRequest represents OTP verification request
type OTPVerifyRequest struct {
	RequestID int64  `json:"rid"`
	OtpTxn    string `json:"otpTxn"`
	OTP       string `json:"otp"`
	Aadhaar   string `json:"uid"`
}

// BiometricRequest represents biometric authentication request
type BiometricRequest struct {
	Request      string `json:"request"`
	RequestID    int64  `json:"rid"`
	Aadhaar      string `json:"uid"`
	BiometricXML string `json:"biometricXML"`
}

// BiometricResponse represents biometric authentication response
type BiometricResponse struct {
	Success     bool   `json:"success"`
	Msg         string `json:"msg,omitempty"`
	AuthMode    string `json:"authMode,omitempty"`
	Wadh        string `json:"wadh,omitempty"`
	ConsentText string `json:"consentText,omitempty"`
	ResponseURL string `json:"responseURL,omitempty"`
}

// BiometricData represents biometric data
type BiometricData struct {
	Type   string `json:"type"` // FMR, FIR, IIR
	Pos    string `json:"pos"`
	Data   string `json:"data"`
	Wadh   string `json:"wadh"`
	Device string `json:"device"`
}

// AadhaarDetailsVO represents Aadhaar KYC details
type AadhaarDetailsVO struct {
	Name         string       `json:"name"`
	Gender       string       `json:"gender"`
	Dob          string       `json:"dob"`
	State        string       `json:"state"`
	Pincode      string       `json:"pincode"`
	Address      *AddressInfo `json:"address,omitempty"`
	Photo        string       `json:"photo,omitempty"`
	ResponseCode string       `json:"responseCode"`
	Token        string       `json:"token"`
	AadhaarNo    string       `json:"aadhaarNo"` // Last 4 digits only
	EmailId      string       `json:"emailId,omitempty"`
	MobileNumber int64        `json:"mobileNumber,omitempty"`
	Locality     string       `json:"locality,omitempty"`
}

// AddressInfo contains address details
type AddressInfo struct {
	House    string `json:"house"`
	Street   string `json:"street"`
	Landmark string `json:"landmark"`
	Locality string `json:"locality"`
	VTC      string `json:"vtc"`
}

// EsignKycDetailDTO represents KYC details DTO
type EsignKycDetailDTO struct {
	ResidentName string    `json:"residentName"`
	Gender       string    `json:"gender"`
	Dob          string    `json:"dob"`
	State        string    `json:"state"`
	PostalCode   string    `json:"postalCode"`
	Address1     string    `json:"address1"`
	Address2     string    `json:"address2"`
	Address3     string    `json:"address3"`
	Address4     string    `json:"address4"`
	Locality     string    `json:"locality"`
	PhotoHash    string    `json:"photoHash"`
	ResponseCode string    `json:"responseCode"`
	Token        string    `json:"token"`
	Uid          string    `json:"uid"` // Last 4 digits
	RequestTime  time.Time `json:"requestTime"`
	ResponseTime time.Time `json:"responseTime"`
	Email        string    `json:"email,omitempty"`
	Mobile       int64     `json:"mobile,omitempty"`
	Photo        string    `json:"photo,omitempty"`
}

// Session represents session data
type Session struct {
	Values map[string]interface{}
}

// Save saves the session
func (s *Session) Save(req interface{}, writer interface{}) error {
	// Implementation depends on session store
	return nil
}

// Template represents a custom view template
type Template struct {
	ID        string            `json:"id"`
	AspID     string            `json:"aspId"`
	Name      string            `json:"name"`
	Content   string            `json:"content"`
	Variables []string          `json:"variables"`
	AuthModes []string          `json:"authModes"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// Config represents application configuration
// NOTE: Config has been moved to internal/config package to avoid conflicts
/*
type Config struct {
	Server struct {
		Port         int    `yaml:"port"`
		Host         string `yaml:"host"`
		ReadTimeout  int    `yaml:"readTimeout"`
		WriteTimeout int    `yaml:"writeTimeout"`
	} `yaml:"server"`

	Database struct {
		Host         string `yaml:"host"`
		Port         int    `yaml:"port"`
		User         string `yaml:"user"`
		Password     string `yaml:"password"`
		DBName       string `yaml:"dbName"`
		SSLMode      string `yaml:"sslMode"`
		MaxOpenConns int    `yaml:"maxOpenConns"`
		MaxIdleConns int    `yaml:"maxIdleConns"`
		MaxLifetime  int    `yaml:"maxLifetime"`
	} `yaml:"database"`

	Redis struct {
		Host        string `yaml:"host"`
		Port        int    `yaml:"port"`
		Password     string `yaml:"password"`
		DB          int    `yaml:"db"`
		MaxRetries  int    `yaml:"maxRetries"`
		PoolSize    int    `yaml:"poolSize"`
		ReadTimeout int    `yaml:"readTimeout"`
	} `yaml:"redis"`

	RateLimit struct {
		EsignDoc        int  `yaml:"esignDoc"`
		CheckStatus     int  `yaml:"checkStatus"`
		Enabled         bool `yaml:"enabled"`
		WindowSize      int  `yaml:"windowSize"`
		FallbackEnabled bool `yaml:"fallbackEnabled"`
	} `yaml:"rateLimit"`

	ESP struct {
		BaseURL    string `yaml:"baseUrl"`
		HealthPath string `yaml:"healthPath"`
		Timeout    int    `yaml:"timeout"`
		RetryCount int    `yaml:"retryCount"`
		RetryDelay int    `yaml:"retryDelay"`
	} `yaml:"esp"`

	UIDAI struct {
		AuthURL     string `yaml:"authUrl"`
		OtpURL      string `yaml:"otpUrl"`
		EkycURL     string `yaml:"ekycUrl"`
		SubAUA      string `yaml:"subAua"`
		LicenseKey  string `yaml:"licenseKey"`
		PublicKey   string `yaml:"publicKey"`
		PrivateKey  string `yaml:"privateKey"`
		Certificate string `yaml:"certificate"`
		Timeout     int    `yaml:"timeout"`
	} `yaml:"uidai"`

	Security struct {
		JWTSecret      string   `yaml:"jwtSecret"`
		SessionSecret  string   `yaml:"sessionSecret"`
		CSRFEnabled    bool     `yaml:"csrfEnabled"`
		AllowedOrigins []string `yaml:"allowedOrigins"`
		TrustedProxies []string `yaml:"trustedProxies"`
		MaxUploadSize  int64    `yaml:"maxUploadSize"`
		XMLMaxSize     int64    `yaml:"xmlMaxSize"`
		MaxXMLSize     int64    `yaml:"maxXMLSize"`
	} `yaml:"security"`

	Debug struct {
		LogLevel     string `yaml:"logLevel"`
		LogRequests  bool   `yaml:"logRequests"`
		LogResponses bool   `yaml:"logResponses"`
	} `yaml:"debug"`

	BiometricEnv         string   `yaml:"biometricEnv"`
	BiometricResponseURL string   `yaml:"biometricResponseUrl"`
		ConsentText          string   `yaml:"consentText"`
	AuthAttempts         int      `yaml:"authAttempts"`
	OTPRetryAttempts     int      `yaml:"otpRetryAttempts"`
	Build                string   `yaml:"build"`
	Environment          string   `yaml:"environment"`
	RequestTimeout       int      `yaml:"requestTimeout"`
	CheckStatusASPs      []string `yaml:"checkStatusAsps"`
}
*/

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	EsignDoc    int `yaml:"esignDoc"`
	CheckStatus int `yaml:"checkStatus"`
}

// DebugConfig represents debug configuration
type DebugConfig struct {
	LogRequests   bool `yaml:"logRequests"`
	LogResponses  bool `yaml:"logResponses"`
	PrettyPrint   bool `yaml:"prettyPrint"`
	SkipXMLVerify bool `yaml:"skipXMLVerify"`
}

// Transaction status constants (string)
const (
	StatusInitiated                    = "INITIATED"
	StatusOTPSent                      = "OTP_SENT"
	StatusOTPVerified                  = "OTP_VERIFIED"
	StatusBioSubmitted                 = "BIO_SUBMITTED"
	StatusBioVerified                  = "BIO_VERIFIED"
	StatusCompleted                    = "COMPLETED"
	StatusFailed                       = "FAILED"
	StatusExpired                      = "EXPIRED"
	StatusAuthorized                   = "REQUEST_AUTHORISED"
	StatusCancelled                    = "CANCELLED"
	StatusBiometricFingerprintVerified = "BIOMETRIC_FINGERPRINT_VERIFIED"
	StatusBiometricIrisVerified        = "BIOMETRIC_IRIS_VERIFIED"
	StatusRequestAuthorized            = "REQUEST_AUTHORIZED"
)

// Numeric status constants
const (
	StatusNumInitiated = -1
	StatusNumCompleted = 0
	StatusNumFailed    = 1
	StatusNumExpired   = 2

	// Additional status constants for repository
	TransactionStatusSigned  = "SIGNED"
	TransactionStatusFailed  = "FAILED"
	TransactionStatusExpired = "EXPIRED"
	TransactionStatusPending = "PENDING"

	// Auth status constants
	AuthStatusSuccess = "SUCCESS"
	AuthStatusFailed  = "FAILED"
	AuthStatusPending = "PENDING"

	// Auth mode constants
	AuthModeOTP        = "OTP"
	AuthModeBiometric  = "BIOMETRIC"
	AuthModeOfflineKYC = "OFFLINE_KYC"

	// CheckStatus config constant
	CheckStatusRateLimit = 10
)

// Additional model definitions

// SignedDocument represents a digitally signed document
type SignedDocument struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Hash            string    `json:"hash"`
	Signature       string    `json:"signature"`
	Certificate     string    `json:"certificate"`
	SignedAt        time.Time `json:"signedAt"`
	SignatureFormat string    `json:"signatureFormat"`
}

// Document represents a document to be signed
type Document struct {
	ID       string `json:"id"`
	Info     string `json:"info"`
	Hash     string `json:"hash"`
	HashAlgo string `json:"hashAlgo"`
}

// ErrorCode represents an error code mapping
type ErrorCode struct {
	Code            string `json:"code"`
	InternalMessage string `json:"internalMessage"`
	ExternalCode    string `json:"externalCode"`
	ExternalMessage string `json:"externalMessage"`
}

// ASPDetails represents ASP information
type ASPDetails struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	CertUserCN       string            `json:"certUserCN"`
	CertSerialNo     string            `json:"certSerialNo"`
	CertValidFrom    time.Time         `json:"certValidFrom"`
	CertValidTo      time.Time         `json:"certValidTo"`
	Overdraft        int               `json:"overdraft"`
	AvailableQuota   int               `json:"availableQuota"`
	IsActive         bool              `json:"isActive"`
	Status           string            `json:"status"`
	AumID            string            `json:"aumId"`
	OrgName          string            `json:"orgName"`
	ConsentVariables map[string]string `json:"consentVariables"`
	QuotaMode        string            `json:"quotaMode"`
	AcmID            string            `json:"acmId"`
}

// ResubmitInfo contains resubmit information
type ResubmitInfo struct {
	RequestID         int64     `json:"requestId"`
	Status            int       `json:"status"`
	IsDuplicate       bool      `json:"isDuplicate"`
	IsResubmit        bool      `json:"isResubmit"`
	CreatedOn         time.Time `json:"createdOn"`
	RequestTransition string    `json:"requestTransition"`
	CertificateID     string    `json:"certificateId"`
	EsignStatus       string    `json:"esignStatus"`
}

// EsignRequestDetail represents detailed esign request
type EsignRequestDetail struct {
	RequestID       int64           `json:"requestId"`
	AspID           string          `json:"aspId"`
	Txn             string          `json:"txn"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	AuthMode        string          `json:"authMode"`
	ResponseSigType string          `json:"responseSigType"`
	ResponseURL     string          `json:"responseUrl"`
	Status          int             `json:"status"`
	RequestIP       string          `json:"requestIp"`
	UserAgent       string          `json:"userAgent"`
	CreatedOn       time.Time       `json:"createdOn"`
	AcmID           *string         `json:"acmId,omitempty"`
	Documents       []EsignDocument `json:"documents"`
	Adr             string          `json:"adr,omitempty"` // Last 4 digits of Aadhaar
}

// EsignDocument represents a document in esign request
type EsignDocument struct {
	DocID         string `json:"docId"`
	DocInfo       string `json:"docInfo"`
	HashAlgorithm string `json:"hashAlgorithm"`
	HashValue     string `json:"hashValue"`
}

// EsignRawLog represents raw log entry
type EsignRawLog struct {
	ID        int64     `json:"id"`
	RequestID int64     `json:"requestId"`
	Data      string    `json:"data"`
	Type      string    `json:"type"`
	ClientIP  string    `json:"clientIp"`
	CreatedOn time.Time `json:"createdOn"`
}

// Raw log types
const (
	RawLogTypeASPRequest  = "ASP_REQUEST"
	RawLogTypeESPResponse = "ESP_RESPONSE"
)

// Transaction represents a transaction record
type Transaction struct {
	ID           string    `json:"id" db:"id"`
	ASPID        string    `json:"aspId" db:"asp_id"`
	ASPTxnID     string    `json:"aspTxnId" db:"asp_txn_id"`
	RequestTime  time.Time `json:"requestTime" db:"request_time"`
	ResponseTime time.Time `json:"responseTime" db:"response_time"`
	UpdateTime   time.Time `json:"updateTime" db:"update_time"`
	ClientIP     string    `json:"clientIp" db:"client_ip"`
	Status       string    `json:"status" db:"status"`
	ErrorCode    string    `json:"errorCode" db:"error_code"`
	ErrorMessage string    `json:"errorMessage" db:"error_message"`
}

// AuthAttempt represents an authentication attempt
type AuthAttempt struct {
	ID            string    `json:"id" db:"id"`
	TransactionID string    `json:"transactionId" db:"transaction_id"`
	Aadhaar       string    `json:"aadhaar" db:"aadhaar_hash"`
	AuthMode      string    `json:"authMode" db:"auth_mode"`
	AttemptTime   time.Time `json:"attemptTime" db:"attempt_time"`
	Status        string    `json:"status" db:"status"`
	ErrorCode     string    `json:"errorCode" db:"error_code"`
	ResponseCode  string    `json:"responseCode" db:"response_code"`
	ClientIP      string    `json:"clientIp" db:"client_ip"`
}

// CertificateRecord represents a stored certificate
type CertificateRecord struct {
	ID            string     `json:"id" db:"id"`
	TransactionID string     `json:"transactionId" db:"transaction_id"`
	Certificate   []byte     `json:"certificate" db:"certificate"`
	PrivateKey    []byte     `json:"privateKey" db:"private_key"`
	IssuedAt      time.Time  `json:"issuedAt" db:"issued_at"`
	ExpiresAt     time.Time  `json:"expiresAt" db:"expires_at"`
	RevokedAt     *time.Time `json:"revokedAt" db:"revoked_at"`
}

// SigningRecord represents a document signing record
type SigningRecord struct {
	ID            string    `json:"id" db:"id"`
	TransactionID string    `json:"transactionId" db:"transaction_id"`
	DocumentID    string    `json:"documentId" db:"document_id"`
	DocumentHash  string    `json:"documentHash" db:"document_hash"`
	Signature     string    `json:"signature" db:"signature"`
	SignedAt      time.Time `json:"signedAt" db:"signed_at"`
}

// CallbackData represents callback data from UIDAI
type CallbackData struct {
	TxnID     string `json:"txnId"`
	Status    string `json:"status"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
}

// TransactionFilter for querying transactions
type TransactionFilter struct {
	ASPID     string
	Status    string
	StartDate time.Time
	EndDate   time.Time
	Limit     int
	Offset    int
}

// ASP represents an Application Service Provider
type ASP struct {
	ID               string    `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	PublicKey        []byte    `json:"publicKey" db:"public_key"`
	CallbackURL      string    `json:"callbackUrl" db:"callback_url"`
	IsActive         bool      `json:"isActive" db:"is_active"`
	RequireSignature bool      `json:"requireSignature" db:"require_signature"`
	CreatedAt        time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time `json:"updatedAt" db:"updated_at"`
}

// SubjectInfo contains certificate subject information
type SubjectInfo struct {
	Name         string
	Email        string
	Organization string
	Country      string
}

// UIDAI Request/Response models

// UIDAIAuthRequest represents authentication request to UIDAI
type UIDAIAuthRequest struct {
	UID           string    `xml:"uid"`
	TxnID         string    `xml:"txn"`
	AuthType      string    `xml:"authType"`
	SubAUA        string    `xml:"subAua"`
	LicenseKey    string    `xml:"licenseKey"`
	Consent       bool      `xml:"consent"`
	ClientIP      string    `xml:"clientIp"`
	Timestamp     time.Time `xml:"timestamp"`
	OTP           string    `xml:"otp,omitempty"`
	BiometricData string    `xml:"bio,omitempty"`
}

// UIDAIAuthResponse represents authentication response from UIDAI
type UIDAIAuthResponse struct {
	Success      bool      `xml:"success"`
	TxnID        string    `xml:"txn"`
	AuthCode     string    `xml:"authCode"`
	ResponseCode string    `xml:"responseCode"`
	ErrorMessage string    `xml:"errorMessage"`
	MaskedMobile string    `xml:"maskedMobile"`
	KYCData      *KYCData  `xml:"kycData,omitempty"`
	ResponseTime time.Time `xml:"responseTime"`
	Status       string    `xml:"status"`
}

// UIDAIOTPRequest represents OTP request to UIDAI
type UIDAIOTPRequest struct {
	UID       string    `xml:"uid"`
	TxnID     string    `xml:"txn"`
	Timestamp time.Time `xml:"timestamp"`
	ClientIP  string    `xml:"clientIp"`
}

// UIDAIOTPResponse represents OTP response from UIDAI
type UIDAIOTPResponse struct {
	Success      bool   `xml:"success"`
	TxnID        string `xml:"txn"`
	MaskedMobile string `xml:"maskedMobile"`
	ErrorMessage string `xml:"errorMessage"`
}

// UIDAIEKYCRequest represents eKYC request to UIDAI
type UIDAIEKYCRequest struct {
	UID       string    `xml:"uid"`
	TxnID     string    `xml:"txn"`
	AuthCode  string    `xml:"authCode"`
	Timestamp time.Time `xml:"timestamp"`
}

// UIDAIEKYCResponse represents eKYC response from UIDAI
type UIDAIEKYCResponse struct {
	Success      bool     `xml:"success"`
	TxnID        string   `xml:"txn"`
	KYCData      *KYCData `xml:"kycData"`
	ErrorMessage string   `xml:"errorMessage"`
}

// KYCData contains KYC information
type KYCData struct {
	Name        string `json:"name"`
	DOB         string `json:"dob"`
	Gender      string `json:"gender"`
	Address     string `json:"address"`
	Photo       string `json:"photo"`
	AadhaarHash string `json:"aadhaarHash"`
}

// EsignResponse represents the esign response
type EsignResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	ResponseURL string `json:"responseUrl"`
	ErrorCode   string `json:"errorCode,omitempty"`
	Form        string `json:"form,omitempty"`
	ErrCode     string `json:"errCode,omitempty"`
	ErrMsg      string `json:"errMsg,omitempty"`
	Ts          string `json:"ts,omitempty"`
	Txn         string `json:"txn,omitempty"`
	ResCode     string `json:"resCode,omitempty"`
}

// EsignStatusModel represents check status request model
type EsignStatusModel struct {
	AspID string `json:"aspId"`
	Txn   string `json:"txn"`
}

// EsignStatusVO represents check status response
type EsignStatusVO struct {
	Msg string `json:"msg"`
	Sts int    `json:"sts"`
}

// OkycOtpRequest represents offline KYC OTP request
type OkycOtpRequest struct {
	RequestID          int64  `json:"rid"`
	LastDigitOfAadhaar string `json:"lastDigitOfAadhaar"`
	Msg1               string `json:"msg1"`
	ZipFile            []byte `json:"zipFile"`
	ShareCode          string `json:"shareCode"`
}

// OKYCOTPResponse represents offline KYC OTP response
type OKYCOTPResponse struct {
	Status     string `json:"status"`
	Form       string `json:"form,omitempty"`
	Msg        string `json:"msg"`
	OtpTxn     string `json:"otpTxn,omitempty"`
	RetryCount int    `json:"retryCount,omitempty"`
}

// OkycVerificationModel represents offline KYC verification request
type OkycVerificationModel struct {
	RequestID int64  `json:"rid"`
	OtpTxn    string `json:"otpTxn"`
	OTP       string `json:"otp"`
	ShareCode string `json:"shareCode"`
}

// OkycVerificationResponse represents offline KYC verification response
type OkycVerificationResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Form   string `json:"form,omitempty"`
}

// FaceRecognitionRequest represents face recognition request
type FaceRecognitionRequest struct {
	TransactionID    string `json:"transactionId"`
	VideoFileName    string `json:"videoFileName"`
	VideoData        []byte `json:"-"`
	VideoContentType string `json:"videoContentType"`
}

// FaceRecognitionResult represents face recognition result
type FaceRecognitionResult struct {
	Success bool   `json:"success"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// SendOTPAPIRequest represents modern API request for sending OTP
type SendOTPAPIRequest struct {
	RID     int64  `json:"rid" binding:"required"`
	UID     string `json:"uid" binding:"required,len=12|len=16"`
	AspID   string `json:"aspId,omitempty"`
}

// VerifyOTPAPIRequest represents modern API request for verifying OTP
type VerifyOTPAPIRequest struct {
	RID     int64  `json:"rid" binding:"required"`
	UID     string `json:"uid" binding:"required,len=12|len=16"`
	OtpTxn  string `json:"otpTxn" binding:"required"`
	OTP     string `json:"otp" binding:"required,len=6"`
	AspID   string `json:"aspId,omitempty"`
}

// BiometricAuthAPIRequest represents modern API request for biometric auth
type BiometricAuthAPIRequest struct {
	RID           int64                  `json:"rid" binding:"required"`
	UID           string                 `json:"uid" binding:"required,len=12|len=16"`
	AuthType      string                 `json:"authType" binding:"required,oneof=BIOMETRIC_FP BIOMETRIC_IRIS"`
	BiometricData map[string]interface{} `json:"biometricData" binding:"required"`
	DeviceInfo    map[string]interface{} `json:"deviceInfo" binding:"required"`
}

// OfflineKYCAPIRequest represents modern API request for offline KYC
type OfflineKYCAPIRequest struct {
	RID         int64  `json:"rid" binding:"required"`
	AuthType    string `json:"authType" binding:"required,eq=OFFLINE_KYC"`
	OfflineXML  string `json:"offlineXML" binding:"required"`
	ShareCode   string `json:"shareCode" binding:"required,len=4"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}
