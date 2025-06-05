package repository

import (
	"database/sql"
	"fmt"

	"github.com/esign-go/internal/models"
)

// AuditRepository implements IAuditRepository
type AuditRepository struct {
	db *sql.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// CreateTransaction logs a transaction
func (r *AuditRepository) CreateTransaction(transaction *models.Transaction) error {
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

// LogAuthAttempt logs an authentication attempt
func (r *AuditRepository) LogAuthAttempt(attempt *models.AuthAttempt) error {
	query := `
		INSERT INTO auth_attempts (id, transaction_id, aadhaar_hash, auth_mode, 
		                          attempt_time, status, error_code, response_code, client_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Exec(
		query,
		attempt.ID,
		attempt.TransactionID,
		attempt.Aadhaar,
		attempt.AuthMode,
		attempt.AttemptTime,
		attempt.Status,
		attempt.ErrorCode,
		attempt.ResponseCode,
		attempt.ClientIP,
	)

	if err != nil {
		return fmt.Errorf("failed to log auth attempt: %w", err)
	}

	return nil
}

// GetAuthAttempts retrieves authentication attempts for a transaction
func (r *AuditRepository) GetAuthAttempts(transactionID string) ([]*models.AuthAttempt, error) {
	query := `
		SELECT id, transaction_id, aadhaar_hash, auth_mode, attempt_time, 
		       status, error_code, response_code, client_ip
		FROM auth_attempts
		WHERE transaction_id = $1
		ORDER BY attempt_time DESC
	`

	rows, err := r.db.Query(query, transactionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth attempts: %w", err)
	}
	defer rows.Close()

	var attempts []*models.AuthAttempt
	for rows.Next() {
		var attempt models.AuthAttempt
		var errorCode, responseCode sql.NullString

		err := rows.Scan(
			&attempt.ID,
			&attempt.TransactionID,
			&attempt.Aadhaar,
			&attempt.AuthMode,
			&attempt.AttemptTime,
			&attempt.Status,
			&errorCode,
			&responseCode,
			&attempt.ClientIP,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan auth attempt: %w", err)
		}

		// Handle nullable fields
		if errorCode.Valid {
			attempt.ErrorCode = errorCode.String
		}
		if responseCode.Valid {
			attempt.ResponseCode = responseCode.String
		}

		attempts = append(attempts, &attempt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating auth attempts: %w", err)
	}

	return attempts, nil
}

// GetTransactionLogs retrieves transaction logs based on filter
func (r *AuditRepository) GetTransactionLogs(filter *models.TransactionFilter) ([]*models.Transaction, error) {
	// Build dynamic query based on filter
	query := `
		SELECT id, asp_id, asp_txn_id, request_time, response_time, update_time,
		       client_ip, status, error_code, error_message
		FROM transactions
		WHERE 1=1
	`

	args := make([]interface{}, 0)
	argCount := 0

	// Add filters
	if filter.ASPID != "" {
		argCount++
		query += fmt.Sprintf(" AND asp_id = $%d", argCount)
		args = append(args, filter.ASPID)
	}

	if filter.Status != "" {
		argCount++
		query += fmt.Sprintf(" AND status = $%d", argCount)
		args = append(args, filter.Status)
	}

	if !filter.StartDate.IsZero() {
		argCount++
		query += fmt.Sprintf(" AND request_time >= $%d", argCount)
		args = append(args, filter.StartDate)
	}

	if !filter.EndDate.IsZero() {
		argCount++
		query += fmt.Sprintf(" AND request_time <= $%d", argCount)
		args = append(args, filter.EndDate)
	}

	// Add ordering and pagination
	query += " ORDER BY request_time DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	// Execute query
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction logs: %w", err)
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

// Additional audit methods

// GetFailedAuthAttemptsByIP gets failed authentication attempts by IP address
func (r *AuditRepository) GetFailedAuthAttemptsByIP(clientIP string, minutes int) (int, error) {
	query := `
		SELECT COUNT(*) 
		FROM auth_attempts 
		WHERE client_ip = $1 
		  AND status = $2 
		  AND attempt_time > NOW() - INTERVAL '%d minutes'
	`

	query = fmt.Sprintf(query, minutes)

	var count int
	err := r.db.QueryRow(query, clientIP, models.AuthStatusFailed).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get failed attempts by IP: %w", err)
	}

	return count, nil
}

// GetTransactionStatistics gets transaction statistics for reporting
func (r *AuditRepository) GetTransactionStatistics(aspID string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get total transactions
	var totalCount int
	err := r.db.QueryRow(`
		SELECT COUNT(*) FROM transactions WHERE asp_id = $1
	`, aspID).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get total count: %w", err)
	}
	stats["total"] = totalCount

	// Get status breakdown
	statusQuery := `
		SELECT status, COUNT(*) 
		FROM transactions 
		WHERE asp_id = $1 
		GROUP BY status
	`

	rows, err := r.db.Query(statusQuery, aspID)
	if err != nil {
		return nil, fmt.Errorf("failed to get status breakdown: %w", err)
	}
	defer rows.Close()

	statusCounts := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("failed to scan status count: %w", err)
		}
		statusCounts[status] = count
	}
	stats["statusBreakdown"] = statusCounts

	// Get daily transaction count for last 30 days
	dailyQuery := `
		SELECT DATE(request_time) as date, COUNT(*) as count
		FROM transactions
		WHERE asp_id = $1 AND request_time > NOW() - INTERVAL '30 days'
		GROUP BY DATE(request_time)
		ORDER BY date
	`

	rows, err = r.db.Query(dailyQuery, aspID)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily counts: %w", err)
	}
	defer rows.Close()

	type dailyCount struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}

	var dailyCounts []dailyCount
	for rows.Next() {
		var dc dailyCount
		if err := rows.Scan(&dc.Date, &dc.Count); err != nil {
			return nil, fmt.Errorf("failed to scan daily count: %w", err)
		}
		dailyCounts = append(dailyCounts, dc)
	}
	stats["dailyCounts"] = dailyCounts

	return stats, nil
}
