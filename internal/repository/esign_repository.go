package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/esign-go/internal/models"
)

// EsignRepository implements IEsignRepository
type EsignRepository struct {
	db *sql.DB
}

// NewEsignRepository creates a new esign repository
func NewEsignRepository(db *sql.DB) *EsignRepository {
	return &EsignRepository{db: db}
}

// GetTransaction retrieves a transaction by ID
func (r *EsignRepository) GetTransaction(id string) (*models.Transaction, error) {
	query := `
		SELECT id, asp_id, asp_txn_id, request_time, response_time, update_time,
		       client_ip, status, error_code, error_message
		FROM transactions
		WHERE id = $1
	`

	var transaction models.Transaction
	var responseTime, updateTime sql.NullTime
	var errorCode, errorMessage sql.NullString

	err := r.db.QueryRow(query, id).Scan(
		&transaction.ID,
		&transaction.ASPID,
		&transaction.ASPTxnID,
		&transaction.RequestTime,
		&responseTime,
		&updateTime,
		&transaction.ClientIP,
		&transaction.Status,
		&errorCode,
		&errorMessage,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("transaction not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	// Handle nullable fields
	if responseTime.Valid {
		transaction.ResponseTime = responseTime.Time
	}
	if updateTime.Valid {
		transaction.UpdateTime = updateTime.Time
	}
	if errorCode.Valid {
		transaction.ErrorCode = errorCode.String
	}
	if errorMessage.Valid {
		transaction.ErrorMessage = errorMessage.String
	}

	return &transaction, nil
}

// CreateTransaction creates a new transaction
func (r *EsignRepository) CreateTransaction(transaction *models.Transaction) error {
	query := `
		INSERT INTO transactions (id, asp_id, asp_txn_id, request_time, client_ip, status)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(
		query,
		transaction.ID,
		transaction.ASPID,
		transaction.ASPTxnID,
		transaction.RequestTime,
		transaction.ClientIP,
		transaction.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}

	return nil
}

// UpdateTransactionStatus updates the status of a transaction
func (r *EsignRepository) UpdateTransactionStatus(id, status string) error {
	query := `
		UPDATE transactions 
		SET status = $1, update_time = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	result, err := r.db.Exec(query, status, id)
	if err != nil {
		return fmt.Errorf("failed to update transaction status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("transaction not found")
	}

	return nil
}

// UpdateTransactionFromCallback updates transaction from callback data
func (r *EsignRepository) UpdateTransactionFromCallback(data *models.CallbackData) error {
	// Parse callback status and update transaction
	status := models.TransactionStatusFailed
	if data.Status == "SUCCESS" {
		status = models.TransactionStatusSigned
	}

	query := `
		UPDATE transactions 
		SET status = $1, response_time = CURRENT_TIMESTAMP, update_time = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := r.db.Exec(query, status, data.TxnID)
	if err != nil {
		return fmt.Errorf("failed to update transaction from callback: %w", err)
	}

	return nil
}

// GetCertificateBySerial retrieves a certificate by serial number
func (r *EsignRepository) GetCertificateBySerial(serial string) (*models.CertificateRecord, error) {
	// For simplicity, using transaction_id as serial
	query := `
		SELECT id, transaction_id, certificate, private_key, issued_at, expires_at, revoked_at
		FROM certificates
		WHERE transaction_id = $1 AND revoked_at IS NULL
		ORDER BY issued_at DESC
		LIMIT 1
	`

	var cert models.CertificateRecord
	var revokedAt sql.NullTime

	err := r.db.QueryRow(query, serial).Scan(
		&cert.ID,
		&cert.TransactionID,
		&cert.Certificate,
		&cert.PrivateKey,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&revokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if revokedAt.Valid {
		cert.RevokedAt = &revokedAt.Time
	}

	return &cert, nil
}

// StoreCertificate stores a certificate record
func (r *EsignRepository) StoreCertificate(cert *models.CertificateRecord) error {
	query := `
		INSERT INTO certificates (id, transaction_id, certificate, private_key, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(
		query,
		cert.ID,
		cert.TransactionID,
		cert.Certificate,
		cert.PrivateKey,
		cert.IssuedAt,
		cert.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store certificate: %w", err)
	}

	return nil
}

// StoreSigningRecord stores a signing record
func (r *EsignRepository) StoreSigningRecord(record *models.SigningRecord) error {
	query := `
		INSERT INTO signing_records (id, transaction_id, document_id, document_hash, signature, signed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(
		query,
		record.ID,
		record.TransactionID,
		record.DocumentID,
		record.DocumentHash,
		record.Signature,
		record.SignedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store signing record: %w", err)
	}

	return nil
}

// GetSigningRecords retrieves signing records for a transaction
func (r *EsignRepository) GetSigningRecords(transactionID string) ([]*models.SigningRecord, error) {
	query := `
		SELECT id, transaction_id, document_id, document_hash, signature, signed_at
		FROM signing_records
		WHERE transaction_id = $1
		ORDER BY signed_at
	`

	rows, err := r.db.Query(query, transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing records: %w", err)
	}
	defer rows.Close()

	var records []*models.SigningRecord
	for rows.Next() {
		var record models.SigningRecord
		err := rows.Scan(
			&record.ID,
			&record.TransactionID,
			&record.DocumentID,
			&record.DocumentHash,
			&record.Signature,
			&record.SignedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan signing record: %w", err)
		}
		records = append(records, &record)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating signing records: %w", err)
	}

	return records, nil
}

// Additional helper methods

// GetTransactionsByASP retrieves transactions for a specific ASP
func (r *EsignRepository) GetTransactionsByASP(aspID string, limit, offset int) ([]*models.Transaction, error) {
	query := `
		SELECT id, asp_id, asp_txn_id, request_time, response_time, update_time,
		       client_ip, status, error_code, error_message
		FROM transactions
		WHERE asp_id = $1
		ORDER BY request_time DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(query, aspID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions by ASP: %w", err)
	}
	defer rows.Close()

	var transactions []*models.Transaction
	for rows.Next() {
		var transaction models.Transaction
		var responseTime, updateTime sql.NullTime
		var errorCode, errorMessage sql.NullString

		err := rows.Scan(
			&transaction.ID,
			&transaction.ASPID,
			&transaction.ASPTxnID,
			&transaction.RequestTime,
			&responseTime,
			&updateTime,
			&transaction.ClientIP,
			&transaction.Status,
			&errorCode,
			&errorMessage,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}

		// Handle nullable fields
		if responseTime.Valid {
			transaction.ResponseTime = responseTime.Time
		}
		if updateTime.Valid {
			transaction.UpdateTime = updateTime.Time
		}
		if errorCode.Valid {
			transaction.ErrorCode = errorCode.String
		}
		if errorMessage.Valid {
			transaction.ErrorMessage = errorMessage.String
		}

		transactions = append(transactions, &transaction)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating transactions: %w", err)
	}

	return transactions, nil
}

// CleanupExpiredTransactions removes expired transactions
func (r *EsignRepository) CleanupExpiredTransactions(expiryDuration time.Duration) error {
	cutoffTime := time.Now().Add(-expiryDuration)

	query := `
		UPDATE transactions 
		SET status = $1
		WHERE status = $2 AND request_time < $3
	`

	_, err := r.db.Exec(query, models.TransactionStatusExpired, models.TransactionStatusPending, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired transactions: %w", err)
	}

	return nil
}
