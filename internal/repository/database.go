package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/esign-go/internal/config"
	_ "github.com/lib/pq"
)

// InitDB initializes the database connection
func InitDB(cfg config.DatabaseConfig) (*sql.DB, error) {
	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode,
	)

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.MaxLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// RunMigrations runs database migrations
func RunMigrations(db *sql.DB) error {
	// Create tables if not exists
	queries := []string{
		// ASP table
		`CREATE TABLE IF NOT EXISTS asps (
			id VARCHAR(50) PRIMARY KEY,
			name VARCHAR(255) UNIQUE NOT NULL,
			public_key TEXT NOT NULL,
			callback_url VARCHAR(500),
			is_active BOOLEAN DEFAULT true,
			require_signature BOOLEAN DEFAULT true,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Transactions table
		`CREATE TABLE IF NOT EXISTS transactions (
			id VARCHAR(50) PRIMARY KEY,
			asp_id VARCHAR(50) NOT NULL,
			asp_txn_id VARCHAR(100) NOT NULL,
			request_time TIMESTAMP NOT NULL,
			response_time TIMESTAMP,
			update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			client_ip VARCHAR(45),
			status VARCHAR(20) NOT NULL,
			error_code VARCHAR(50),
			error_message TEXT,
			FOREIGN KEY (asp_id) REFERENCES asps(id)
		)`,

		// Create indexes for transactions
		`CREATE INDEX IF NOT EXISTS idx_asp_txn ON transactions (asp_id, asp_txn_id)`,
		`CREATE INDEX IF NOT EXISTS idx_status ON transactions (status)`,
		`CREATE INDEX IF NOT EXISTS idx_request_time ON transactions (request_time)`,

		// Authentication attempts table
		`CREATE TABLE IF NOT EXISTS auth_attempts (
			id VARCHAR(50) PRIMARY KEY,
			transaction_id VARCHAR(50) NOT NULL,
			aadhaar_hash VARCHAR(64) NOT NULL,
			auth_mode VARCHAR(10) NOT NULL,
			attempt_time TIMESTAMP NOT NULL,
			status VARCHAR(20) NOT NULL,
			error_code VARCHAR(50),
			response_code VARCHAR(50),
			client_ip VARCHAR(45),
			FOREIGN KEY (transaction_id) REFERENCES transactions(id)
		)`,

		// Create indexes for auth_attempts
		`CREATE INDEX IF NOT EXISTS idx_transaction ON auth_attempts (transaction_id)`,
		`CREATE INDEX IF NOT EXISTS idx_attempt_time ON auth_attempts (attempt_time)`,

		// Certificates table
		`CREATE TABLE IF NOT EXISTS certificates (
			id VARCHAR(50) PRIMARY KEY,
			transaction_id VARCHAR(50) NOT NULL,
			certificate BYTEA NOT NULL,
			private_key BYTEA NOT NULL,
			issued_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP,
			FOREIGN KEY (transaction_id) REFERENCES transactions(id)
		)`,

		// Create indexes for certificates
		`CREATE INDEX IF NOT EXISTS idx_transaction_cert ON certificates (transaction_id)`,
		`CREATE INDEX IF NOT EXISTS idx_expires ON certificates (expires_at)`,

		// Signing records table
		`CREATE TABLE IF NOT EXISTS signing_records (
			id VARCHAR(50) PRIMARY KEY,
			transaction_id VARCHAR(50) NOT NULL,
			document_id VARCHAR(100) NOT NULL,
			document_hash VARCHAR(64) NOT NULL,
			signature TEXT NOT NULL,
			signed_at TIMESTAMP NOT NULL,
			FOREIGN KEY (transaction_id) REFERENCES transactions(id)
		)`,

		// Create indexes for signing_records
		`CREATE INDEX IF NOT EXISTS idx_transaction_sign ON signing_records (transaction_id)`,
		`CREATE INDEX IF NOT EXISTS idx_document ON signing_records (document_id)`,

		// Esign requests table
		`CREATE TABLE IF NOT EXISTS esign_requests (
			id SERIAL PRIMARY KEY,
			asp_id VARCHAR(50) NOT NULL,
			txn VARCHAR(100) NOT NULL,
			legal_name VARCHAR(255),
			v1 VARCHAR(255),
			v2 VARCHAR(255),
			v3 VARCHAR(255),
			response_url TEXT,
			error_msg TEXT,
			is_error BOOLEAN DEFAULT false,
			is_resubmit BOOLEAN DEFAULT false,
			otp_retry_attempts INTEGER DEFAULT 0,
			auth_attempts INTEGER DEFAULT 0,
			adr VARCHAR(255),
			subject TEXT,
			certificate_serial VARCHAR(100),
			aum_id VARCHAR(50),
			status INTEGER DEFAULT -1,
			created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			cancel_reason TEXT,
			error_code VARCHAR(50),
			request_transition VARCHAR(50),
			kyc_id BIGINT,
			FOREIGN KEY (asp_id) REFERENCES asps(id)
		)`,

		// Create indexes for esign_requests
		`CREATE INDEX IF NOT EXISTS idx_asp_txn_req ON esign_requests (asp_id, txn)`,
		`CREATE INDEX IF NOT EXISTS idx_status_req ON esign_requests (status)`,
		`CREATE INDEX IF NOT EXISTS idx_created_req ON esign_requests (created_on)`,

		// Esign KYC details table
		`CREATE TABLE IF NOT EXISTS esign_kyc_details (
			id SERIAL PRIMARY KEY,
			resident_name VARCHAR(255),
			gender VARCHAR(10),
			dob VARCHAR(20),
			state VARCHAR(100),
			postal_code VARCHAR(10),
			address1 VARCHAR(255),
			address2 VARCHAR(255),
			address3 VARCHAR(255),
			address4 VARCHAR(255),
			locality VARCHAR(255),
			photo_hash VARCHAR(64),
			response_code VARCHAR(50),
			token VARCHAR(255),
			uid VARCHAR(100),
			request_time TIMESTAMP,
			response_time TIMESTAMP,
			email VARCHAR(255),
			mobile BIGINT,
			photo TEXT
		)`,

		// Esign raw logs table
		`CREATE TABLE IF NOT EXISTS esign_raw_logs (
			id SERIAL PRIMARY KEY,
			request_id BIGINT,
			data TEXT,
			type VARCHAR(50),
			client_ip VARCHAR(45),
			created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (request_id) REFERENCES esign_requests(id)
		)`,

		// Create update trigger for updated_at
		`CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql'`,

		`DO $$ 
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger 
				WHERE tgname = 'update_asps_updated_at'
			) THEN
				CREATE TRIGGER update_asps_updated_at BEFORE UPDATE
				ON asps FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
			END IF;
		END $$;`,
	}

	// Execute migrations
	for i, query := range queries {
		if _, err := db.Exec(query); err != nil {
			// Get first 100 chars of query for debugging
			queryPreview := query
			if len(queryPreview) > 100 {
				queryPreview = queryPreview[:100] + "..."
			}
			return fmt.Errorf("migration %d failed: %w (query: %s)", i, err, queryPreview)
		}
	}

	// Insert default ASPs if needed
	if err := insertDefaultASPs(db); err != nil {
		return fmt.Errorf("failed to insert default ASPs: %w", err)
	}

	return nil
}

func insertDefaultASPs(db *sql.DB) error {
	// Check if any ASPs exist
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM asps").Scan(&count); err != nil {
		return err
	}

	if count > 0 {
		return nil // ASPs already exist
	}

	// Insert default test ASP
	_, err := db.Exec(`
		INSERT INTO asps (id, name, public_key, callback_url, is_active, require_signature)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, "TEST001", "Test ASP", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
		"https://test.example.com/callback", true, false)

	return err
}
