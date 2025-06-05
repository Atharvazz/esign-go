package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/esign-go/internal/models"
)

// ASPRepository implements IASPRepository
type ASPRepository struct {
	db *sql.DB
}

// NewASPRepository creates a new ASP repository
func NewASPRepository(db *sql.DB) *ASPRepository {
	return &ASPRepository{db: db}
}

// GetByID retrieves an ASP by ID
func (r *ASPRepository) GetByID(id string) (*models.ASP, error) {
	query := `
		SELECT id, name, public_key, callback_url, is_active, require_signature, created_at, updated_at
		FROM asps
		WHERE id = $1
	`

	var asp models.ASP
	err := r.db.QueryRow(query, id).Scan(
		&asp.ID,
		&asp.Name,
		&asp.PublicKey,
		&asp.CallbackURL,
		&asp.IsActive,
		&asp.RequireSignature,
		&asp.CreatedAt,
		&asp.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ASP not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ASP: %w", err)
	}

	return &asp, nil
}

// GetByName retrieves an ASP by name
func (r *ASPRepository) GetByName(name string) (*models.ASP, error) {
	query := `
		SELECT id, name, public_key, callback_url, is_active, require_signature, created_at, updated_at
		FROM asps
		WHERE name = $1
	`

	var asp models.ASP
	err := r.db.QueryRow(query, name).Scan(
		&asp.ID,
		&asp.Name,
		&asp.PublicKey,
		&asp.CallbackURL,
		&asp.IsActive,
		&asp.RequireSignature,
		&asp.CreatedAt,
		&asp.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ASP not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ASP: %w", err)
	}

	return &asp, nil
}

// Create creates a new ASP
func (r *ASPRepository) Create(asp *models.ASP) error {
	query := `
		INSERT INTO asps (id, name, public_key, callback_url, is_active, require_signature, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	now := time.Now()
	asp.CreatedAt = now
	asp.UpdatedAt = now

	_, err := r.db.Exec(
		query,
		asp.ID,
		asp.Name,
		asp.PublicKey,
		asp.CallbackURL,
		asp.IsActive,
		asp.RequireSignature,
		asp.CreatedAt,
		asp.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create ASP: %w", err)
	}

	return nil
}

// Update updates an existing ASP
func (r *ASPRepository) Update(asp *models.ASP) error {
	query := `
		UPDATE asps 
		SET name = $2, public_key = $3, callback_url = $4, is_active = $5, 
		    require_signature = $6, updated_at = $7
		WHERE id = $1
	`

	asp.UpdatedAt = time.Now()

	result, err := r.db.Exec(
		query,
		asp.ID,
		asp.Name,
		asp.PublicKey,
		asp.CallbackURL,
		asp.IsActive,
		asp.RequireSignature,
		asp.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update ASP: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("ASP not found")
	}

	return nil
}

// List retrieves all ASPs
func (r *ASPRepository) List() ([]*models.ASP, error) {
	query := `
		SELECT id, name, public_key, callback_url, is_active, require_signature, created_at, updated_at
		FROM asps
		ORDER BY name
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list ASPs: %w", err)
	}
	defer rows.Close()

	var asps []*models.ASP
	for rows.Next() {
		var asp models.ASP
		err := rows.Scan(
			&asp.ID,
			&asp.Name,
			&asp.PublicKey,
			&asp.CallbackURL,
			&asp.IsActive,
			&asp.RequireSignature,
			&asp.CreatedAt,
			&asp.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan ASP: %w", err)
		}
		asps = append(asps, &asp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating ASPs: %w", err)
	}

	return asps, nil
}

// Additional helper methods

// ListActive retrieves all active ASPs
func (r *ASPRepository) ListActive() ([]*models.ASP, error) {
	query := `
		SELECT id, name, public_key, callback_url, is_active, require_signature, created_at, updated_at
		FROM asps
		WHERE is_active = true
		ORDER BY name
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active ASPs: %w", err)
	}
	defer rows.Close()

	var asps []*models.ASP
	for rows.Next() {
		var asp models.ASP
		err := rows.Scan(
			&asp.ID,
			&asp.Name,
			&asp.PublicKey,
			&asp.CallbackURL,
			&asp.IsActive,
			&asp.RequireSignature,
			&asp.CreatedAt,
			&asp.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan ASP: %w", err)
		}
		asps = append(asps, &asp)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating ASPs: %w", err)
	}

	return asps, nil
}

// Activate activates an ASP
func (r *ASPRepository) Activate(id string) error {
	query := `UPDATE asps SET is_active = true, updated_at = $2 WHERE id = $1`

	result, err := r.db.Exec(query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to activate ASP: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("ASP not found")
	}

	return nil
}

// Deactivate deactivates an ASP
func (r *ASPRepository) Deactivate(id string) error {
	query := `UPDATE asps SET is_active = false, updated_at = $2 WHERE id = $1`

	result, err := r.db.Exec(query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to deactivate ASP: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("ASP not found")
	}

	return nil
}

// UpdatePublicKey updates the public key of an ASP
func (r *ASPRepository) UpdatePublicKey(id string, publicKey []byte) error {
	query := `UPDATE asps SET public_key = $2, updated_at = $3 WHERE id = $1`

	result, err := r.db.Exec(query, id, publicKey, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update public key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("ASP not found")
	}

	return nil
}

// GetStatistics gets statistics for an ASP
func (r *ASPRepository) GetStatistics(id string) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get ASP details
	asp, err := r.GetByID(id)
	if err != nil {
		return nil, err
	}
	stats["asp"] = asp

	// Get transaction count
	var transactionCount int
	err = r.db.QueryRow(`
		SELECT COUNT(*) FROM transactions WHERE asp_id = $1
	`, id).Scan(&transactionCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction count: %w", err)
	}
	stats["transactionCount"] = transactionCount

	// Get success rate
	var successCount int
	err = r.db.QueryRow(`
		SELECT COUNT(*) FROM transactions 
		WHERE asp_id = $1 AND status = $2
	`, id, models.TransactionStatusSigned).Scan(&successCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get success count: %w", err)
	}

	successRate := 0.0
	if transactionCount > 0 {
		successRate = float64(successCount) / float64(transactionCount) * 100
	}
	stats["successRate"] = successRate

	// Get last transaction time
	var lastTransactionTime sql.NullTime
	err = r.db.QueryRow(`
		SELECT MAX(request_time) FROM transactions WHERE asp_id = $1
	`, id).Scan(&lastTransactionTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get last transaction time: %w", err)
	}

	if lastTransactionTime.Valid {
		stats["lastTransactionTime"] = lastTransactionTime.Time
	}

	return stats, nil
}
