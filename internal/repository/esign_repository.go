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

// BeginTx begins a transaction
func (r *EsignRepository) BeginTx() (Tx, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &sqlTx{tx: tx}, nil
}

// sqlTx wraps sql.Tx to implement Tx interface
type sqlTx struct {
	tx *sql.Tx
}

func (t *sqlTx) Commit() error {
	return t.tx.Commit()
}

func (t *sqlTx) Rollback() error {
	return t.tx.Rollback()
}

// GetRequestByASPAndTxn gets request by ASP ID and transaction ID
func (r *EsignRepository) GetRequestByASPAndTxn(aspID, txnID string) (*models.ResubmitInfo, error) {
	query := `
		SELECT id, status, created_on, request_transition
		FROM esign_requests
		WHERE asp_id = $1 AND txn = $2
		ORDER BY created_on DESC
		LIMIT 1
	`

	var info models.ResubmitInfo
	var requestTransition sql.NullString

	err := r.db.QueryRow(query, aspID, txnID).Scan(
		&info.RequestID,
		&info.Status,
		&info.CreatedOn,
		&requestTransition,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No previous request found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request by ASP and TXN: %w", err)
	}

	// Handle nullable fields
	if requestTransition.Valid {
		info.RequestTransition = requestTransition.String
	}

	// Check if this is a duplicate or resubmit
	info.IsDuplicate = info.Status == models.StatusNumCompleted
	info.IsResubmit = info.Status != models.StatusNumCompleted

	return &info, nil
}

// Implement remaining repository methods that were missing

// InsertEsignRequest inserts a new esign request
func (r *EsignRepository) InsertEsignRequest(req *models.EsignRequestDTO) (int64, error) {
	query := `
		INSERT INTO esign_requests (
			asp_id, txn, legal_name, v1, v2, v3, response_url,
			error_msg, is_error, is_resubmit, otp_retry_attempts,
			auth_attempts, adr, subject, certificate_serial, aum_id,
			status, created_on, cancel_reason, error_code, request_transition
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		) RETURNING id
	`

	var requestID int64
	err := r.db.QueryRow(
		query,
		req.AspID,
		req.Txn,
		req.LegalName,
		req.V1,
		req.V2,
		req.V3,
		req.ResponseURL,
		req.ErrorMsg,
		req.IsError,
		req.IsReSubmit,
		req.OtpRetryAttempts,
		req.AuthAttempts,
		req.Adr,
		req.Subject,
		req.CertificateSerial,
		req.AumID,
		req.Status,
		req.CreatedOn,
		req.CancelReason,
		req.ErrorCode,
		req.RequestTransition,
	).Scan(&requestID)

	if err != nil {
		return 0, fmt.Errorf("failed to insert esign request: %w", err)
	}

	req.RequestID = requestID
	return requestID, nil
}

// GetRequestByID retrieves request by ID
func (r *EsignRepository) GetRequestByID(id int64) (*models.EsignRequestDTO, error) {
	query := `
		SELECT id, asp_id, txn, legal_name, v1, v2, v3, response_url,
			   error_msg, is_error, is_resubmit, otp_retry_attempts,
			   auth_attempts, adr, subject, certificate_serial, aum_id,
			   status, created_on, cancel_reason, error_code, request_transition,
			   kyc_id
		FROM esign_requests
		WHERE id = $1
	`

	req := &models.EsignRequestDTO{}
	var errorMsg, cancelReason, errorCode, requestTransition, subject, certificateSerial, aumID sql.NullString
	var kycID sql.NullInt64

	err := r.db.QueryRow(query, id).Scan(
		&req.RequestID,
		&req.AspID,
		&req.Txn,
		&req.LegalName,
		&req.V1,
		&req.V2,
		&req.V3,
		&req.ResponseURL,
		&errorMsg,
		&req.IsError,
		&req.IsReSubmit,
		&req.OtpRetryAttempts,
		&req.AuthAttempts,
		&req.Adr,
		&subject,
		&certificateSerial,
		&aumID,
		&req.Status,
		&req.CreatedOn,
		&cancelReason,
		&errorCode,
		&requestTransition,
		&kycID,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("request not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request by ID: %w", err)
	}

	// Handle nullable fields
	if errorMsg.Valid {
		req.ErrorMsg = errorMsg.String
	}
	if cancelReason.Valid {
		req.CancelReason = cancelReason.String
	}
	if errorCode.Valid {
		req.ErrorCode = errorCode.String
	}
	if requestTransition.Valid {
		req.RequestTransition = requestTransition.String
	}
	if subject.Valid {
		req.Subject = subject.String
	}
	if certificateSerial.Valid {
		req.CertificateSerial = certificateSerial.String
	}
	if aumID.Valid {
		req.AumID = aumID.String
	}
	if kycID.Valid {
		req.KycID = kycID.Int64
	}

	return req, nil
}

// SaveRawLog saves raw log entry
func (r *EsignRepository) SaveRawLog(log *models.EsignRawLog) error {
	query := `
		INSERT INTO esign_raw_logs (request_id, data, type, client_ip, created_on)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.Exec(query, log.RequestID, log.Data, log.Type, log.ClientIP, log.CreatedOn)
	if err != nil {
		return fmt.Errorf("failed to save raw log: %w", err)
	}

	return nil
}

// GetRequestDetailWithKYC gets request details with KYC
func (r *EsignRepository) GetRequestDetailWithKYC(requestID int64) (*models.EsignRequestDTO, error) {
	// First get the request
	req, err := r.GetRequestByID(requestID)
	if err != nil {
		return nil, err
	}

	// If KYC ID exists, fetch KYC details
	if req.KycID > 0 {
		kycQuery := `
			SELECT resident_name, gender, dob, state, postal_code,
				   address1, address2, address3, address4, locality,
				   photo_hash, response_code, token, uid, request_time,
				   response_time, email, mobile, photo
			FROM esign_kyc_details
			WHERE id = $1
		`

		kyc := &models.EsignKycDetailDTO{}
		var email, photo sql.NullString
		var mobile sql.NullInt64

		err := r.db.QueryRow(kycQuery, req.KycID).Scan(
			&kyc.ResidentName,
			&kyc.Gender,
			&kyc.Dob,
			&kyc.State,
			&kyc.PostalCode,
			&kyc.Address1,
			&kyc.Address2,
			&kyc.Address3,
			&kyc.Address4,
			&kyc.Locality,
			&kyc.PhotoHash,
			&kyc.ResponseCode,
			&kyc.Token,
			&kyc.Uid,
			&kyc.RequestTime,
			&kyc.ResponseTime,
			&email,
			&mobile,
			&photo,
		)

		if err == nil {
			// Handle nullable fields
			if email.Valid {
				kyc.Email = email.String
			}
			if mobile.Valid {
				kyc.Mobile = mobile.Int64
			}
			if photo.Valid {
				kyc.Photo = photo.String
			}
			req.KYC = kyc
		}
	}

	return req, nil
}

// UpdateRetryAttempt updates retry attempt count
func (r *EsignRepository) UpdateRetryAttempt(requestID int64) error {
	query := `
		UPDATE esign_requests
		SET otp_retry_attempts = otp_retry_attempts + 1
		WHERE id = $1
	`

	_, err := r.db.Exec(query, requestID)
	if err != nil {
		return fmt.Errorf("failed to update retry attempt: %w", err)
	}

	return nil
}

// UpdateAuthAttempt updates authentication attempt count
func (r *EsignRepository) UpdateAuthAttempt(requestID int64) error {
	query := `
		UPDATE esign_requests
		SET auth_attempts = auth_attempts + 1
		WHERE id = $1
	`

	_, err := r.db.Exec(query, requestID)
	if err != nil {
		return fmt.Errorf("failed to update auth attempt: %w", err)
	}

	return nil
}

// UpdateTransition updates transaction status
func (r *EsignRepository) UpdateTransition(requestID int64, status string) error {
	query := `
		UPDATE esign_requests
		SET request_transition = $2, status = $3
		WHERE id = $1
	`

	// Map status string to numeric status
	numStatus := models.StatusNumInitiated
	switch status {
	case models.StatusCompleted:
		numStatus = models.StatusNumCompleted
	case models.StatusFailed:
		numStatus = models.StatusNumFailed
	case models.StatusExpired:
		numStatus = models.StatusNumExpired
	}

	_, err := r.db.Exec(query, requestID, status, numStatus)
	if err != nil {
		return fmt.Errorf("failed to update transition: %w", err)
	}

	return nil
}

// UpdateKYCDetails updates KYC details for request
func (r *EsignRepository) UpdateKYCDetails(requestID int64, kyc *models.EsignKycDetailDTO, status string) error {
	tx, err := r.BeginTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := r.UpdateKYCDetailsTx(tx, requestID, kyc, status); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateOTPRetryAttempt updates OTP retry attempt count
func (r *EsignRepository) UpdateOTPRetryAttempt(requestID int64) error {
	query := `
		UPDATE esign_requests
		SET otp_retry_attempts = otp_retry_attempts + 1
		WHERE id = $1
	`

	_, err := r.db.Exec(query, requestID)
	if err != nil {
		return fmt.Errorf("failed to update OTP retry attempt: %w", err)
	}

	return nil
}

// UpdateKYCDetailsTx updates KYC details in transaction
func (r *EsignRepository) UpdateKYCDetailsTx(tx Tx, requestID int64, kyc *models.EsignKycDetailDTO, status string) error {
	// Insert KYC details
	kycQuery := `
		INSERT INTO esign_kyc_details (
			resident_name, gender, dob, state, postal_code,
			address1, address2, address3, address4, locality,
			photo_hash, response_code, token, uid, request_time,
			response_time, email, mobile, photo
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		) RETURNING id
	`

	sqlTx := tx.(*sqlTx)
	var kycID int64
	err := sqlTx.tx.QueryRow(
		kycQuery,
		kyc.ResidentName,
		kyc.Gender,
		kyc.Dob,
		kyc.State,
		kyc.PostalCode,
		kyc.Address1,
		kyc.Address2,
		kyc.Address3,
		kyc.Address4,
		kyc.Locality,
		kyc.PhotoHash,
		kyc.ResponseCode,
		kyc.Token,
		kyc.Uid,
		kyc.RequestTime,
		kyc.ResponseTime,
		kyc.Email,
		kyc.Mobile,
		kyc.Photo,
	).Scan(&kycID)

	if err != nil {
		return fmt.Errorf("failed to insert KYC details: %w", err)
	}

	// Update request with KYC ID and status
	updateQuery := `
		UPDATE esign_requests
		SET kyc_id = $2, request_transition = $3
		WHERE id = $1
	`

	_, err = sqlTx.tx.Exec(updateQuery, requestID, kycID, status)
	if err != nil {
		return fmt.Errorf("failed to update request with KYC ID: %w", err)
	}

	return nil
}

// UpdateTransitionTx updates transaction status in transaction
func (r *EsignRepository) UpdateTransitionTx(tx Tx, requestID int64, status string) error {
	query := `
		UPDATE esign_requests
		SET request_transition = $2
		WHERE id = $1
	`

	sqlTx := tx.(*sqlTx)
	_, err := sqlTx.tx.Exec(query, requestID, status)
	if err != nil {
		return fmt.Errorf("failed to update transition in transaction: %w", err)
	}

	return nil
}

// GetRequestWithKYC gets request with KYC details
func (r *EsignRepository) GetRequestWithKYC(requestID int64) (*models.EsignRequestDTO, error) {
	return r.GetRequestDetailWithKYC(requestID)
}

// UpdateRequestStatus updates request status
func (r *EsignRepository) UpdateRequestStatus(requestID int64, status string) error {
	return r.UpdateTransition(requestID, status)
}

// Ping checks database connectivity
func (r *EsignRepository) Ping() error {
	return r.db.Ping()
}
