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
	"time"

	"github.com/beevik/etree"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/pkg/logger"
)

// CryptoService implements ICryptoService interface
type CryptoService struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// NewCryptoService creates a new crypto service instance
func NewCryptoService(privateKeyPEM, certificatePEM []byte) (*CryptoService, error) {
	// Parse private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key PEM")
	}
	
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = privateKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}
	
	// Parse certificate
	certBlock, _ := pem.Decode(certificatePEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	return &CryptoService{
		privateKey:  privateKey,
		certificate: certificate,
	}, nil
}

// SignXML signs an XML document using XML-DSig
func (s *CryptoService) SignXML(xmlData string, privateKey, certificate []byte) (string, error) {
	log := logger.GetLogger()
	
	// Parse the XML
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return "", fmt.Errorf("failed to parse XML: %w", err)
	}
	
	// Create signature element
	signature := doc.CreateElement("Signature")
	signature.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	
	// Create SignedInfo
	signedInfo := signature.CreateElement("SignedInfo")
	
	// Add CanonicalizationMethod
	canonMethod := signedInfo.CreateElement("CanonicalizationMethod")
	canonMethod.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
	
	// Add SignatureMethod
	sigMethod := signedInfo.CreateElement("SignatureMethod")
	sigMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	
	// Add Reference
	reference := signedInfo.CreateElement("Reference")
	reference.CreateAttr("URI", "")
	
	// Add Transforms
	transforms := reference.CreateElement("Transforms")
	transform := transforms.CreateElement("Transform")
	transform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	
	transform2 := transforms.CreateElement("Transform")
	transform2.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
	
	// Add DigestMethod
	digestMethod := reference.CreateElement("DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	
	// Compute digest of the document (without signature)
	docCopy := doc.Copy()
	docBytes, err := docCopy.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("failed to serialize document: %w", err)
	}
	
	h := sha256.New()
	h.Write(docBytes)
	digest := h.Sum(nil)
	
	// Add DigestValue
	digestValue := reference.CreateElement("DigestValue")
	digestValue.SetText(base64.StdEncoding.EncodeToString(digest))
	
	// Canonicalize SignedInfo
	signedInfoDoc := etree.NewDocument()
	signedInfoDoc.SetRoot(signedInfo.Copy())
	signedInfoBytes, err := s.canonicalizeXML(signedInfoDoc)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}
	
	// Sign the canonicalized SignedInfo
	privKey := s.privateKey
	if privateKey != nil {
		// Parse provided private key
		block, _ := pem.Decode(privateKey)
		if block != nil {
			parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				privKey = parsedKey
			}
		}
	}
	
	signatureBytes, err := s.signData(signedInfoBytes, privKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}
	
	// Add SignatureValue
	sigValue := signature.CreateElement("SignatureValue")
	sigValue.SetText(base64.StdEncoding.EncodeToString(signatureBytes))
	
	// Add KeyInfo
	keyInfo := signature.CreateElement("KeyInfo")
	x509Data := keyInfo.CreateElement("X509Data")
	x509Cert := x509Data.CreateElement("X509Certificate")
	
	// Use provided certificate or default
	certData := certificate
	if certData == nil && s.certificate != nil {
		certData = s.certificate.Raw
	}
	x509Cert.SetText(base64.StdEncoding.EncodeToString(certData))
	
	// Add signature to document
	doc.Root().AddChild(signature)
	
	// Return signed XML
	signedXML, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to serialize signed XML: %w", err)
	}
	
	log.Debug("Successfully signed XML document")
	return signedXML, nil
}

// VerifyXMLSignature verifies the signature of an XML document
func (s *CryptoService) VerifyXMLSignature(xmlData string) (*models.SignatureInfo, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	
	// Find Signature element
	sigElem := doc.FindElement("//Signature")
	if sigElem == nil {
		return nil, fmt.Errorf("signature element not found")
	}
	
	// Extract certificate
	certElem := sigElem.FindElement(".//X509Certificate")
	if certElem == nil {
		return nil, fmt.Errorf("certificate not found in signature")
	}
	
	// Decode certificate
	certData, err := base64.StdEncoding.DecodeString(certElem.Text())
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}
	
	// Parse certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Extract signature value
	sigValueElem := sigElem.FindElement(".//SignatureValue")
	if sigValueElem == nil {
		return nil, fmt.Errorf("signature value not found")
	}
	
	_, err = base64.StdEncoding.DecodeString(sigValueElem.Text())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature value: %w", err)
	}
	
	// Extract digest value
	digestValueElem := sigElem.FindElement(".//DigestValue")
	if digestValueElem == nil {
		return nil, fmt.Errorf("digest value not found")
	}
	
	// TODO: Implement proper signature verification
	// This requires:
	// 1. Canonicalizing the XML without signature
	// 2. Computing digest and comparing with DigestValue
	// 3. Canonicalizing SignedInfo
	// 4. Verifying signature against canonicalized SignedInfo
	
	sigInfo := &models.SignatureInfo{
		Subject:       cert.Subject.String(),
		SerialNumber:  cert.SerialNumber.String(),
		Issuer:        cert.Issuer.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		Certificate:   cert,
	}
	
	return sigInfo, nil
}

// GenerateCertificate generates a new X.509 certificate
func (s *CryptoService) GenerateCertificate(subject *models.SubjectInfo, validityDays int) ([]byte, []byte, error) {
	// Generate RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	
	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:         subject.Name,
			Organization:       []string{subject.Organization},
			Country:            []string{subject.Country},
			OrganizationalUnit: []string{"eSign"},
		},
		EmailAddresses: []string{subject.Email},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, validityDays),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	
	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	
	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	// Encode private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	
	return certPEM, keyPEM, nil
}

// EncryptData encrypts data using RSA public key
func (s *CryptoService) EncryptData(data []byte, publicKey []byte) ([]byte, error) {
	// Parse public key
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("failed to parse public key PEM")
	}
	
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	
	// Encrypt data
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}
	
	return encrypted, nil
}

// DecryptData decrypts data using RSA private key
func (s *CryptoService) DecryptData(encryptedData []byte, privateKey []byte) ([]byte, error) {
	// Use provided private key or default
	privKey := s.privateKey
	if privateKey != nil {
		block, _ := pem.Decode(privateKey)
		if block != nil {
			parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				privKey = parsedKey
			}
		}
	}
	
	// Decrypt data
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	
	return decrypted, nil
}

// GenerateHash generates a hash of the data
func (s *CryptoService) GenerateHash(data []byte, algorithm string) (string, error) {
	var h crypto.Hash
	
	switch algorithm {
	case "SHA256", "sha256":
		h = crypto.SHA256
	case "SHA1", "sha1":
		h = crypto.SHA1
	case "SHA512", "sha512":
		h = crypto.SHA512
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
	
	hasher := h.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	
	return hex.EncodeToString(hash), nil
}

// VerifyHash verifies if the hash matches the data
func (s *CryptoService) VerifyHash(data []byte, hash string, algorithm string) bool {
	computedHash, err := s.GenerateHash(data, algorithm)
	if err != nil {
		return false
	}
	
	return computedHash == hash
}

// Helper methods

func (s *CryptoService) signData(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	h := crypto.SHA256
	hasher := h.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, h, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	
	return signature, nil
}

func (s *CryptoService) canonicalizeXML(doc *etree.Document) ([]byte, error) {
	// Simple canonicalization - in production use proper C14N
	// This is a placeholder implementation
	xml, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	
	return xml, nil
}
