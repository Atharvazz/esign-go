package models

import (
	"time"
)

// Authentication modes
const (
	AuthModeOTP       = "OTP"
	AuthModeBiometric = "BIO"
	AuthModeIRIS      = "IRIS"
)

// Transaction statuses
const (
	TransactionStatusPending       = "PENDING"
	TransactionStatusAuthenticated = "AUTHENTICATED"
	TransactionStatusSigned        = "SIGNED"
	TransactionStatusFailed        = "FAILED"
	TransactionStatusExpired       = "EXPIRED"
)

// Auth statuses
const (
	AuthStatusSuccess = "SUCCESS"
	AuthStatusFailed  = "FAILED"
	AuthStatusPending = "PENDING"
)

// EsignRequest represents the incoming esign request
type EsignRequest struct {
	TransactionID string     `json:"transactionId" xml:"transactionId"`
	ASPID         string     `json:"aspId" xml:"aspId"`
	ASPTxnID      string     `json:"aspTxnId" xml:"aspTxnId"`
	AuthMode      string     `json:"authMode" xml:"authMode"`
	ResponseURL   string     `json:"responseUrl" xml:"responseUrl"`
	ErrorURL      string     `json:"errorUrl" xml:"errorUrl"`
	SignerInfo    SignerInfo `json:"signerInfo" xml:"signerInfo"`
	Documents     []Document `json:"documents" xml:"documents"`
	Signature     []byte     `json:"signature,omitempty" xml:"signature,omitempty"`
	ClientIP      string     `json:"clientIp"`
	RequestTime   time.Time  `json:"requestTime"`
}

// SignerInfo contains signer information
type SignerInfo struct {
	Name     string `json:"name" xml:"name"`
	Email    string `json:"email" xml:"email"`
	Mobile   string `json:"mobile" xml:"mobile"`
	Location string `json:"location" xml:"location"`
	Reason   string `json:"reason" xml:"reason"`
}

// Document represents a document to be signed
type Document struct {
	ID      string `json:"id" xml:"id"`
	Name    string `json:"name" xml:"name"`
	Type    string `json:"type" xml:"type"`
	Content string `json:"content" xml:"content"`
	Hash    string `json:"hash" xml:"hash"`
	PageNo  int    `json:"pageNo" xml:"pageNo"`
	X       int    `json:"x" xml:"x"`
	Y       int    `json:"y" xml:"y"`
	Width   int    `json:"width" xml:"width"`
	Height  int    `json:"height" xml:"height"`
}

// SignedDocument represents a signed document
type SignedDocument struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Content         string    `json:"content"`
	Hash            string    `json:"hash"`
	Signature       string    `json:"signature"`
	Certificate     string    `json:"certificate"`
	SignedAt        time.Time `json:"signedAt"`
	SignatureFormat string    `json:"signatureFormat"`
}

// AuthenticationData contains authentication information
type AuthenticationData struct {
	Aadhaar       string `json:"aadhaar"`
	AuthMode      string `json:"authMode"`
	OTP           string `json:"otp,omitempty"`
	BiometricData string `json:"biometricData,omitempty"`
	Consent       bool   `json:"consent"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Success      bool      `json:"success"`
	RequiresOTP  bool      `json:"requiresOtp"`
	TxnID        string    `json:"txnId"`
	AuthCode     string    `json:"authCode"`
	MaskedMobile string    `json:"maskedMobile"`
	KYCData      *KYCData  `json:"kycData,omitempty"`
	ResponseTime time.Time `json:"responseTime"`
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

// OTPRequest represents OTP generation request
type OTPRequest struct {
	Aadhaar string `json:"aadhaar" binding:"required"`
}

// OTPResponse represents OTP generation response
type OTPResponse struct {
	TxnID        string `json:"txnId"`
	MaskedMobile string `json:"maskedMobile"`
	Success      bool   `json:"success"`
}

// ValidateOTPRequest represents OTP validation request
type ValidateOTPRequest struct {
	TxnID   string `json:"txnId" binding:"required"`
	OTP     string `json:"otp" binding:"required"`
	Aadhaar string `json:"aadhaar" binding:"required"`
}

// EsignResponse represents the esign response
type EsignResponse struct {
	Status       string           `json:"status"`
	RequestID    string           `json:"requestId"`
	Timestamp    time.Time        `json:"timestamp"`
	Certificate  string           `json:"certificate,omitempty"`
	SignedDocs   []SignedDocument `json:"signedDocs,omitempty"`
	ResponseCode string           `json:"responseCode"`
	ResponseMsg  string           `json:"responseMsg"`
	Error        string           `json:"error,omitempty"`
	ErrorType    string           `json:"errorType,omitempty"`
}

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

// TransactionStatus represents transaction status
type TransactionStatus struct {
	TransactionID string    `json:"transactionId"`
	ASPTxnID      string    `json:"aspTxnId"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	DocumentCount int       `json:"documentCount"`
	SignedCount   int       `json:"signedCount"`
}

// CallbackData represents callback data from UIDAI
type CallbackData struct {
	TxnID     string `json:"txnId"`
	Status    string `json:"status"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
	Timestamp string `json:"timestamp"`
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

// SubjectInfo contains certificate subject information
type SubjectInfo struct {
	Name         string
	Email        string
	Organization string
	Country      string
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
