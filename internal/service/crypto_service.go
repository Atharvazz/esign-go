package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/esign-go/internal/config"
	"github.com/esign-go/internal/models"
)

// CryptoService implements the ICryptoService interface
type CryptoService struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	certificate *x509.Certificate
	config      config.SecurityConfig
}

// NewCryptoService creates a new crypto service
func NewCryptoService(cfg config.SecurityConfig) *CryptoService {
	cs := &CryptoService{
		config: cfg,
	}

	// Load keys and certificates
	if err := cs.loadKeys(); err != nil {
		// Log error but don't fail - keys might be generated later
		fmt.Printf("Failed to load keys: %v\n", err)
	}

	return cs
}

// loadKeys loads the private key and certificate from files
func (cs *CryptoService) loadKeys() error {
	// Load private key
	if cs.config.SigningKeyPath != "" {
		keyData, err := ioutil.ReadFile(cs.config.SigningKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse PEM block containing private key")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse private key: %w", err)
			}
			var ok bool
			privateKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("not an RSA private key")
			}
		}

		cs.privateKey = privateKey
		cs.publicKey = &privateKey.PublicKey
	}

	// Load certificate
	if cs.config.SigningCertPath != "" {
		certData, err := ioutil.ReadFile(cs.config.SigningCertPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate: %w", err)
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			return fmt.Errorf("failed to parse PEM block containing certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		cs.certificate = cert
	}

	return nil
}

// SignData signs the given data
func (cs *CryptoService) SignData(data []byte) ([]byte, error) {
	if cs.privateKey == nil {
		return nil, fmt.Errorf("private key not loaded")
	}

	// Calculate hash
	hash := sha256.Sum256(data)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, cs.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies a signature
func (cs *CryptoService) VerifySignature(data, signature, publicKey []byte) error {
	// Parse public key
	pub, err := cs.parsePublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256(data)

	// Verify signature
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// EncryptData encrypts data using the public key
func (cs *CryptoService) EncryptData(data, publicKey []byte) ([]byte, error) {
	// Parse public key
	pub, err := cs.parsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Encrypt data
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return encrypted, nil
}

// DecryptData decrypts data using the private key
func (cs *CryptoService) DecryptData(encryptedData []byte) ([]byte, error) {
	if cs.privateKey == nil {
		return nil, fmt.Errorf("private key not loaded")
	}

	// Decrypt data
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, cs.privateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return decrypted, nil
}

// GenerateKeyPair generates a new RSA key pair
func (cs *CryptoService) GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	// Generate RSA key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode private key to PEM
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Encode public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return privPEM, pubPEM, nil
}

// GenerateCertificate generates a new X.509 certificate
func (cs *CryptoService) GenerateCertificate(subjectInfo *models.SubjectInfo, publicKey []byte) (*x509.Certificate, error) {
	// Parse public key
	pub, err := cs.parsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{subjectInfo.Country},
			Organization:       []string{subjectInfo.Organization},
			OrganizationalUnit: []string{"Digital Signature"},
			CommonName:         subjectInfo.Name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		EmailAddresses:        []string{subjectInfo.Email},
	}

	// Self-sign the certificate if we have a private key
	var certDER []byte
	if cs.privateKey != nil {
		certDER, err = x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			pub,
			cs.privateKey,
		)
	} else {
		// Generate a temporary key for self-signing
		tempKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate temporary key: %w", err)
		}

		certDER, err = x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			pub,
			tempKey,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// parsePublicKey parses a public key from PEM or DER format
func (cs *CryptoService) parsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	// Try PEM format first
	block, _ := pem.Decode(publicKey)
	if block != nil {
		publicKey = block.Bytes
	}

	// Parse public key
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		// Try parsing as certificate
		cert, certErr := x509.ParseCertificate(publicKey)
		if certErr != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		pub = cert.PublicKey
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// GetPublicKey returns the service's public key
func (cs *CryptoService) GetPublicKey() ([]byte, error) {
	if cs.publicKey == nil {
		return nil, fmt.Errorf("public key not loaded")
	}

	// Marshal public key
	pubASN1, err := x509.MarshalPKIXPublicKey(cs.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubPEM, nil
}

// GetCertificate returns the service's certificate
func (cs *CryptoService) GetCertificate() (*x509.Certificate, error) {
	if cs.certificate == nil {
		return nil, fmt.Errorf("certificate not loaded")
	}

	return cs.certificate, nil
}
