package repository

import (
	"github.com/esign-go/internal/models"
)

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
}
