package repository

import (
	"github.com/esign-go/internal/models"
)

// Tx represents a database transaction
type Tx interface {
	Commit() error
	Rollback() error
}

// IEsignRepository defines the interface for esign repository
type IEsignRepository interface {
	// GetTransaction retrieves a transaction by ID
	GetTransaction(id string) (*models.Transaction, error)

	// CreateTransaction creates a new transaction
	CreateTransaction(transaction *models.Transaction) error

	// UpdateTransactionStatus updates the status of a transaction
	UpdateTransactionStatus(id, status string) error

	// UpdateTransactionFromCallback updates transaction from callback data
	UpdateTransactionFromCallback(data *models.CallbackData) error

	// GetCertificateBySerial retrieves a certificate by serial number
	GetCertificateBySerial(serial string) (*models.CertificateRecord, error)

	// StoreCertificate stores a certificate record
	StoreCertificate(cert *models.CertificateRecord) error

	// StoreSigningRecord stores a signing record
	StoreSigningRecord(record *models.SigningRecord) error

	// GetSigningRecords retrieves signing records for a transaction
	GetSigningRecords(transactionID string) ([]*models.SigningRecord, error)

	// InsertEsignRequest inserts a new esign request
	InsertEsignRequest(req *models.EsignRequestDTO) (int64, error)

	// GetRequestByID retrieves request by ID
	GetRequestByID(id int64) (*models.EsignRequestDTO, error)

	// SaveRawLog saves raw log entry
	SaveRawLog(log *models.EsignRawLog) error

	// GetRequestDetailWithKYC gets request details with KYC
	GetRequestDetailWithKYC(requestID int64) (*models.EsignRequestDTO, error)

	// UpdateRetryAttempt updates retry attempt count
	UpdateRetryAttempt(requestID int64) error

	// UpdateAuthAttempt updates authentication attempt count
	UpdateAuthAttempt(requestID int64) error

	// UpdateTransition updates transaction status
	UpdateTransition(requestID int64, status string) error

	// UpdateKYCDetails updates KYC details for request
	UpdateKYCDetails(requestID int64, kyc *models.EsignKycDetailDTO, status string) error

	// UpdateOTPRetryAttempt updates OTP retry attempt count
	UpdateOTPRetryAttempt(requestID int64) error

	// BeginTx begins a transaction
	BeginTx() (Tx, error)

	// UpdateKYCDetailsTx updates KYC details in transaction
	UpdateKYCDetailsTx(tx Tx, requestID int64, kyc *models.EsignKycDetailDTO, status string) error

	// UpdateTransitionTx updates transaction status in transaction
	UpdateTransitionTx(tx Tx, requestID int64, status string) error

	// GetRequestWithKYC gets request with KYC details
	GetRequestWithKYC(requestID int64) (*models.EsignRequestDTO, error)

	// UpdateRequestStatus updates request status
	UpdateRequestStatus(requestID int64, status string) error

	// Ping checks database connectivity
	Ping() error

	// GetRequestByASPAndTxn gets request by ASP ID and transaction ID
	GetRequestByASPAndTxn(aspID, txnID string) (*models.ResubmitInfo, error)
}

// IAuditRepository defines the interface for audit repository
type IAuditRepository interface {
	// CreateTransaction logs a transaction
	CreateTransaction(transaction *models.Transaction) error

	// LogAuthAttempt logs an authentication attempt
	LogAuthAttempt(attempt *models.AuthAttempt) error

	// GetAuthAttempts retrieves authentication attempts for a transaction
	GetAuthAttempts(transactionID string) ([]*models.AuthAttempt, error)

	// GetTransactionLogs retrieves transaction logs based on filter
	GetTransactionLogs(filter *models.TransactionFilter) ([]*models.Transaction, error)
}

// IASPRepository defines the interface for ASP repository
type IASPRepository interface {
	// GetByID retrieves an ASP by ID
	GetByID(id string) (*models.ASP, error)

	// GetByName retrieves an ASP by name
	GetByName(name string) (*models.ASP, error)

	// Create creates a new ASP
	Create(asp *models.ASP) error

	// Update updates an existing ASP
	Update(asp *models.ASP) error

	// List retrieves all ASPs
	List() ([]*models.ASP, error)

	// GetASPDetails retrieves ASP details by ID
	GetASPDetails(aspID string) (*models.ASPDetails, error)
}
