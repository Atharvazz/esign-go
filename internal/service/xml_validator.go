package service

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// XMLValidator implements the IXMLValidator interface
type XMLValidator struct {
	schemas map[string]string
}

// NewXMLValidator creates a new XML validator
func NewXMLValidator() *XMLValidator {
	return &XMLValidator{
		schemas: loadSchemas(),
	}
}

// ValidateEsignRequest validates the esign request XML against schema
func (v *XMLValidator) ValidateEsignRequest(xmlData []byte) error {
	// Parse XML
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}

	// Get root element
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("XML has no root element")
	}

	// Validate root element name
	if root.Tag != "Esign" {
		return fmt.Errorf("invalid root element: expected 'Esign', got '%s'", root.Tag)
	}

	// Validate required attributes
	requiredAttrs := []string{"ver", "sc", "ts", "txn", "aspId"}
	for _, attr := range requiredAttrs {
		if root.SelectAttrValue(attr, "") == "" {
			return fmt.Errorf("missing required attribute: %s", attr)
		}
	}

	// Validate version
	version := root.SelectAttrValue("ver", "")
	if !isValidVersion(version) {
		return fmt.Errorf("unsupported version: %s", version)
	}

	// Validate child elements
	if err := v.validateChildElements(root); err != nil {
		return err
	}

	return nil
}

// ValidateASPSignature validates the ASP's signature on the request
func (v *XMLValidator) ValidateASPSignature(xmlData []byte, signature []byte, publicKeyPEM []byte) error {
	// Parse public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	// Calculate hash of XML data
	hash := sha256.Sum256(xmlData)

	// Verify signature
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// validateChildElements validates the child elements of the root
func (v *XMLValidator) validateChildElements(root *etree.Element) error {
	// Check for required child elements
	requiredElements := []string{"Docs"}

	for _, elemName := range requiredElements {
		elem := root.SelectElement(elemName)
		if elem == nil {
			return fmt.Errorf("missing required element: %s", elemName)
		}
	}

	// Validate Docs element
	docs := root.SelectElement("Docs")
	if docs != nil {
		if err := v.validateDocsElement(docs); err != nil {
			return err
		}
	}

	// Validate Signature if present
	sig := root.SelectElement("Signature")
	if sig != nil {
		if err := v.validateSignatureElement(sig); err != nil {
			return err
		}
	}

	return nil
}

// validateDocsElement validates the Docs element
func (v *XMLValidator) validateDocsElement(docs *etree.Element) error {
	// Check for at least one InputHash element
	inputHashes := docs.SelectElements("InputHash")
	if len(inputHashes) == 0 {
		return fmt.Errorf("Docs element must contain at least one InputHash")
	}

	// Validate each InputHash
	for i, ih := range inputHashes {
		// Check required attributes
		id := ih.SelectAttrValue("id", "")
		hashAlgorithm := ih.SelectAttrValue("hashAlgorithm", "")
		docInfo := ih.SelectAttrValue("docInfo", "")

		if id == "" {
			return fmt.Errorf("InputHash[%d] missing 'id' attribute", i)
		}
		if hashAlgorithm == "" {
			return fmt.Errorf("InputHash[%d] missing 'hashAlgorithm' attribute", i)
		}
		if docInfo == "" {
			return fmt.Errorf("InputHash[%d] missing 'docInfo' attribute", i)
		}

		// Validate hash algorithm
		if !isValidHashAlgorithm(hashAlgorithm) {
			return fmt.Errorf("InputHash[%d] invalid hash algorithm: %s", i, hashAlgorithm)
		}

		// Check hash value
		hashValue := ih.Text()
		if hashValue == "" {
			return fmt.Errorf("InputHash[%d] missing hash value", i)
		}

		// Validate base64 encoding
		if _, err := base64.StdEncoding.DecodeString(hashValue); err != nil {
			return fmt.Errorf("InputHash[%d] invalid base64 hash value: %w", i, err)
		}
	}

	return nil
}

// validateSignatureElement validates the Signature element
func (v *XMLValidator) validateSignatureElement(sig *etree.Element) error {
	// This would implement full XML Digital Signature validation
	// For now, we do basic structure validation

	// Check for SignedInfo
	signedInfo := sig.SelectElement("SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("Signature missing SignedInfo element")
	}

	// Check for SignatureValue
	sigValue := sig.SelectElement("SignatureValue")
	if sigValue == nil {
		return fmt.Errorf("Signature missing SignatureValue element")
	}

	// Check for KeyInfo (optional but recommended)
	keyInfo := sig.SelectElement("KeyInfo")
	if keyInfo != nil {
		// Validate KeyInfo structure
		x509Data := keyInfo.SelectElement("X509Data")
		if x509Data == nil {
			return fmt.Errorf("KeyInfo missing X509Data element")
		}
	}

	return nil
}

// Helper functions

func isValidVersion(version string) bool {
	validVersions := []string{"2.0", "2.1", "3.0"}
	for _, v := range validVersions {
		if v == version {
			return true
		}
	}
	return false
}

func isValidHashAlgorithm(algo string) bool {
	validAlgos := []string{"SHA256", "SHA384", "SHA512"}
	for _, a := range validAlgos {
		if strings.EqualFold(a, algo) {
			return true
		}
	}
	return false
}

func loadSchemas() map[string]string {
	// In production, load actual XSD schemas
	return map[string]string{
		"esign_2.0": esignSchema20,
		"esign_2.1": esignSchema21,
		"esign_3.0": esignSchema30,
	}
}

// Simplified schema definitions
const (
	esignSchema20 = `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <!-- Simplified eSign 2.0 schema -->
</xs:schema>`

	esignSchema21 = `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <!-- Simplified eSign 2.1 schema -->
</xs:schema>`

	esignSchema30 = `<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <!-- Simplified eSign 3.0 schema -->
</xs:schema>`
)

// XMLSignatureValidator handles XML digital signature validation
type XMLSignatureValidator struct {
	trustedCerts []*x509.Certificate
}

// NewXMLSignatureValidator creates a new XML signature validator
func NewXMLSignatureValidator(trustedCertsPEM [][]byte) (*XMLSignatureValidator, error) {
	var certs []*x509.Certificate

	for _, certPEM := range trustedCertsPEM {
		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	return &XMLSignatureValidator{
		trustedCerts: certs,
	}, nil
}

// Validate validates an XML digital signature
func (v *XMLSignatureValidator) Validate(xmlData []byte) error {
	// Parse XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return fmt.Errorf("failed to parse XML: %w", err)
	}

	// Find Signature element
	sig := doc.FindElement("//Signature")
	if sig == nil {
		return fmt.Errorf("no Signature element found")
	}

	// Extract signature value
	sigValueElem := sig.FindElement("SignatureValue")
	if sigValueElem == nil {
		return fmt.Errorf("no SignatureValue element found")
	}

	sigValue, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigValueElem.Text()))
	if err != nil {
		return fmt.Errorf("failed to decode signature value: %w", err)
	}

	// Get signed info and canonicalize
	signedInfo := sig.FindElement("SignedInfo")
	if signedInfo == nil {
		return fmt.Errorf("no SignedInfo element found")
	}

	// Canonicalize SignedInfo (simplified - use proper C14N in production)
	var buf bytes.Buffer
	signedInfo.WriteTo(&buf, &etree.WriteSettings{})
	canonicalSignedInfo := buf.Bytes()

	// Calculate digest
	hash := sha256.Sum256(canonicalSignedInfo)

	// Find certificate in KeyInfo
	cert, err := v.extractCertificate(sig)
	if err != nil {
		return fmt.Errorf("failed to extract certificate: %w", err)
	}

	// Verify certificate is trusted
	if err := v.verifyCertificate(cert); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Verify signature
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain RSA public key")
	}

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sigValue)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// extractCertificate extracts the certificate from the Signature element
func (v *XMLSignatureValidator) extractCertificate(sig *etree.Element) (*x509.Certificate, error) {
	keyInfo := sig.FindElement("KeyInfo")
	if keyInfo == nil {
		return nil, fmt.Errorf("no KeyInfo element found")
	}

	x509Cert := keyInfo.FindElement(".//X509Certificate")
	if x509Cert == nil {
		return nil, fmt.Errorf("no X509Certificate element found")
	}

	certData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(x509Cert.Text()))
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// verifyCertificate verifies that the certificate is trusted
func (v *XMLSignatureValidator) verifyCertificate(cert *x509.Certificate) error {
	// Create certificate pool with trusted certs
	roots := x509.NewCertPool()
	for _, trustedCert := range v.trustedCerts {
		roots.AddCert(trustedCert)
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Verify(opts)
	return err
}
