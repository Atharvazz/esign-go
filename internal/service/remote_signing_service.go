package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/esign-go/internal/models"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/pkg/logger"
)

// RemoteSigningService implements IRemoteSigningService interface
type RemoteSigningService struct {
	cryptoSvc    ICryptoService
	certRepo     repository.IEsignRepository
	certCache    map[string]*certificateInfo
	cacheMutex   sync.RWMutex
	caCert       *x509.Certificate
	caPrivateKey *rsa.PrivateKey
}

type certificateInfo struct {
	Certificate []byte
	PrivateKey  []byte
	ExpiresAt   time.Time
}

// NewRemoteSigningService creates a new remote signing service instance
func NewRemoteSigningService(cryptoSvc ICryptoService, certRepo repository.IEsignRepository, caCertPEM, caKeyPEM []byte) (*RemoteSigningService, error) {
	// Parse CA certificate
	caCert, err := parseCertificate(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return &RemoteSigningService{
		cryptoSvc:    cryptoSvc,
		certRepo:     certRepo,
		certCache:    make(map[string]*certificateInfo),
		caCert:       caCert,
		caPrivateKey: caKey,
	}, nil
}

// SignDocument signs a document hash remotely
func (s *RemoteSigningService) SignDocument(docHash string, certificate []byte, privateKey []byte) (string, error) {
	log := logger.GetLogger()

	// Decode hash from hex
	hashBytes, err := hex.DecodeString(docHash)
	if err != nil {
		return "", fmt.Errorf("invalid document hash: %w", err)
	}

	// Parse private key
	privKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign document: %w", err)
	}

	// Encode signature to base64
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	log.WithField("hash", docHash).Debug("Successfully signed document")
	return signatureB64, nil
}

// SignMultipleDocuments signs multiple document hashes
func (s *RemoteSigningService) SignMultipleDocuments(docHashes []string, certificate []byte, privateKey []byte) ([]string, error) {
	log := logger.GetLogger()

	// Parse private key once
	privKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signatures := make([]string, len(docHashes))

	for i, docHash := range docHashes {
		// Decode hash from hex
		hashBytes, err := hex.DecodeString(docHash)
		if err != nil {
			return nil, fmt.Errorf("invalid document hash at index %d: %w", i, err)
		}

		// Sign the hash
		signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to sign document at index %d: %w", i, err)
		}

		// Encode signature to base64
		signatures[i] = base64.StdEncoding.EncodeToString(signature)
	}

	log.WithField("count", len(docHashes)).Debug("Successfully signed multiple documents")
	return signatures, nil
}

// GetSigningCertificate gets or generates a signing certificate for the user
func (s *RemoteSigningService) GetSigningCertificate(userID string, kycData *models.AadhaarDetailsVO) ([]byte, []byte, error) {
	log := logger.GetLogger()

	// Check cache first
	s.cacheMutex.RLock()
	if certInfo, ok := s.certCache[userID]; ok {
		if time.Now().Before(certInfo.ExpiresAt) {
			s.cacheMutex.RUnlock()
			return certInfo.Certificate, certInfo.PrivateKey, nil
		}
	}
	s.cacheMutex.RUnlock()

	// Check database for existing certificate
	certRecord, err := s.certRepo.GetCertificateBySerial(userID)
	if err == nil && certRecord != nil && certRecord.ExpiresAt.After(time.Now()) {
		// Cache the certificate
		s.cacheCertificate(userID, certRecord.Certificate, certRecord.PrivateKey, certRecord.ExpiresAt)
		return certRecord.Certificate, certRecord.PrivateKey, nil
	}

	// Generate new certificate
	log.WithField("userID", userID).Info("Generating new signing certificate")

	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:         kycData.Name,
			Organization:       []string{"UIDAI"},
			Country:            []string{"IN"},
			Province:           []string{kycData.State},
			OrganizationalUnit: []string{"eSign"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(48 * time.Hour), // 48 hours validity
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: generateSubjectKeyID(&privKey.PublicKey),
		DNSNames:     []string{},
	}

	// Add Subject Alternative Name with Aadhaar hash
	if kycData.AadhaarNo != "" {
		// Create Aadhaar hash
		h := sha256.New()
		h.Write([]byte(kycData.AadhaarNo))
		aadhaarHash := hex.EncodeToString(h.Sum(nil))

		// Add as custom extension
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:    []int{2, 5, 29, 17}, // Subject Alternative Name OID
				Value: []byte(aadhaarHash),
			},
		}
	}

	// Sign certificate with CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		s.caCert,
		&privKey.PublicKey,
		s.caPrivateKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := encodeCertificatePEM(certDER)

	// Encode private key to PEM
	privKeyPEM := encodePrivateKeyPEM(privKey)

	// Store certificate in database
	certRecord = &models.CertificateRecord{
		ID:            userID,
		TransactionID: fmt.Sprintf("cert_%s_%d", userID, time.Now().Unix()),
		Certificate:   certPEM,
		PrivateKey:    privKeyPEM,
		IssuedAt:      time.Now(),
		ExpiresAt:     template.NotAfter,
	}

	if err := s.certRepo.StoreCertificate(certRecord); err != nil {
		log.WithError(err).Error("Failed to store certificate in database")
		// Continue anyway - certificate is still valid
	}

	// Cache the certificate
	s.cacheCertificate(userID, certPEM, privKeyPEM, template.NotAfter)

	return certPEM, privKeyPEM, nil
}

// Helper methods

func (s *RemoteSigningService) cacheCertificate(userID string, cert, privKey []byte, expiresAt time.Time) {
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()

	s.certCache[userID] = &certificateInfo{
		Certificate: cert,
		PrivateKey:  privKey,
		ExpiresAt:   expiresAt,
	}
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privKey, ok = privKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	return privKey, nil
}

func encodeCertificatePEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func encodePrivateKeyPEM(privKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
}

func generateSubjectKeyID(pubKey *rsa.PublicKey) []byte {
	// Generate Subject Key Identifier from public key
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	h := sha256.New()
	h.Write(pubKeyBytes)
	return h.Sum(nil)[:20] // Use first 20 bytes
}

// HealthCheck checks remote signing service health
func (s *RemoteSigningService) HealthCheck() error {
	// Check if CA certificate is valid
	if s.caCert == nil {
		return fmt.Errorf("CA certificate not loaded")
	}
	
	if time.Now().After(s.caCert.NotAfter) {
		return fmt.Errorf("CA certificate has expired")
	}
	
	// Test certificate generation
	testSubject := &models.SubjectInfo{
		Name:         "Health Check",
		Email:        "health@check.com",
		Organization: "Test",
		Country:      "IN",
	}
	
	_, _, err := s.cryptoSvc.GenerateCertificate(testSubject, 1)
	if err != nil {
		return fmt.Errorf("certificate generation test failed: %w", err)
	}
	
	return nil
}

// GenerateErrorResponse generates an error response
func (s *RemoteSigningService) GenerateErrorResponse(errorCode, errorMessage string) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
	
	// Create error response XML
	errorXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" ts="%s" txn="" responseSigType="pkcs7" sc="Y" aspId="" responseUrl="">
	<Resp status="1" errCode="%s" errMsg="%s" resCode="%s">
		<ts>%s</ts>
	</Resp>
</Esign>`, timestamp, errorCode, errorMessage, errorCode, timestamp)
	
	return errorXML
}
