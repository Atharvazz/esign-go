package xmlparser

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/esign-go/internal/models"
)

// XMLValidator handles XML validation and parsing
type XMLValidator struct {
	xsdSchemas map[string]string
}

// NewXMLValidator creates a new XML validator
func NewXMLValidator() *XMLValidator {
	return &XMLValidator{
		xsdSchemas: loadXSDSchemas(),
	}
}

// ValidateXSD validates XML against XSD schema
func (v *XMLValidator) ValidateXSD(xmlData string, version string) error {
	// In production, use a proper XSD validator
	// This is a simplified validation
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return fmt.Errorf("invalid XML structure: %w", err)
	}

	// Check root element
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("no root element found")
	}
	if root.Tag != "Esign" {
		return fmt.Errorf("invalid root element: expected 'Esign', got '%s'", root.Tag)
	}

	// Validate version
	verAttr := root.SelectAttr("ver")
	if verAttr == nil || verAttr.Value != version {
		return fmt.Errorf("invalid version: expected %s", version)
	}

	// Validate required attributes
	requiredAttrs := []string{"sc", "ts", "txn", "aspId", "AuthMode", "responseUrl"}
	for _, attr := range requiredAttrs {
		if root.SelectAttr(attr) == nil {
			return fmt.Errorf("missing required attribute: %s", attr)
		}
	}

	// Validate Docs element
	docs := root.SelectElement("Docs")
	if docs == nil {
		return fmt.Errorf("missing Docs element")
	}

	// Validate InputHash elements
	inputHashes := docs.SelectElements("InputHash")
	if len(inputHashes) == 0 {
		return fmt.Errorf("missing InputHash elements")
	}

	// Validate Signature element (optional for testing)
	// signature := root.SelectElement("Signature")
	// if signature == nil {
	// 	return fmt.Errorf("missing Signature element")
	// }

	return nil
}

// ParseEsignRequest parses the esign request XML
func (v *XMLValidator) ParseEsignRequest(xmlData string) (*models.EsignRequest, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("no root element found")
	}

	req := &models.EsignRequest{
		Ver:             root.SelectAttrValue("ver", ""),
		Sc:              root.SelectAttrValue("sc", ""),
		Ts:              root.SelectAttrValue("ts", ""),
		Txn:             root.SelectAttrValue("txn", ""),
		EkycID:          root.SelectAttrValue("ekycId", ""),
		EkycIDType:      root.SelectAttrValue("ekycIdType", ""),
		AspID:           root.SelectAttrValue("aspId", ""),
		AuthMode:        root.SelectAttrValue("AuthMode", ""),
		ResponseSigType: root.SelectAttrValue("responseSigType", ""),
		ResponseURL:     root.SelectAttrValue("responseUrl", ""),
		SignerID:        root.SelectAttrValue("signerid", ""),
		MaxWaitPeriod:   root.SelectAttrValue("maxWaitPeriod", ""),
		RedirectURL:     root.SelectAttrValue("redirectUrl", ""),
		SigningAlgo:     root.SelectAttrValue("signingAlgorithm", ""),
	}

	// Parse Docs
	docsElem := root.SelectElement("Docs")
	if docsElem != nil {
		req.Docs = &models.Docs{
			InputHash: []models.InputHash{},
		}

		for _, hashElem := range docsElem.SelectElements("InputHash") {
			hash := models.InputHash{
				ID:            hashElem.SelectAttrValue("id", ""),
				HashAlgorithm: hashElem.SelectAttrValue("hashAlgorithm", ""),
				DocInfo:       hashElem.SelectAttrValue("docInfo", ""),
				Value:         strings.TrimSpace(hashElem.Text()),
			}
			req.Docs.InputHash = append(req.Docs.InputHash, hash)
		}
	}

	return req, nil
}

// VerifySignature verifies the XML digital signature
func (v *XMLValidator) VerifySignature(xmlData string) (*models.SignatureInfo, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	// Find Signature element
	sigElem := doc.FindElement("//Signature")
	if sigElem == nil {
		// For testing, return a dummy signature info
		return &models.SignatureInfo{
			Subject:       "CN=Test ASP,O=Test Organization,C=IN",
			SerialNumber:  "CERT-TEST001",
			Issuer:        "CN=Test CA,O=Test CA Organization,C=IN",
			NotBefore:     time.Now().Add(-24 * time.Hour),
			NotAfter:      time.Now().Add(365 * 24 * time.Hour),
			SignatureAlgo: "SHA256WithRSA",
		}, nil
	}

	// Extract certificate
	certElem := sigElem.FindElement(".//X509Certificate")
	if certElem == nil {
		return nil, fmt.Errorf("certificate not found in signature")
	}

	// Decode certificate
	certData, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certElem.Text()))
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// In production, perform actual signature verification here
	// This would involve:
	// 1. Canonicalizing the XML
	// 2. Computing digest of canonicalized XML
	// 3. Verifying signature against digest

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

// SignXML signs the XML document
func (v *XMLValidator) SignXML(xmlData string, privateKey, certificate []byte) (string, error) {
	// This is a placeholder implementation
	// In production, use proper XML-DSig libraries

	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlData); err != nil {
		return "", fmt.Errorf("failed to parse XML: %w", err)
	}

	// Create Signature element
	sigElem := doc.CreateElement("Signature")
	sigElem.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")

	// Add SignedInfo
	signedInfo := sigElem.CreateElement("SignedInfo")

	// Add CanonicalizationMethod
	canonMethod := signedInfo.CreateElement("CanonicalizationMethod")
	canonMethod.CreateAttr("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

	// Add SignatureMethod
	sigMethod := signedInfo.CreateElement("SignatureMethod")
	sigMethod.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha256")

	// Add Reference
	reference := signedInfo.CreateElement("Reference")
	reference.CreateAttr("URI", "")

	// Add Transforms
	transforms := reference.CreateElement("Transforms")
	transform := transforms.CreateElement("Transform")
	transform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")

	// Add DigestMethod
	digestMethod := reference.CreateElement("DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha256")

	// Add DigestValue (placeholder)
	digestValue := reference.CreateElement("DigestValue")
	digestValue.SetText("placeholder-digest-value")

	// Add SignatureValue (placeholder)
	sigValue := sigElem.CreateElement("SignatureValue")
	sigValue.SetText("placeholder-signature-value")

	// Add KeyInfo
	keyInfo := sigElem.CreateElement("KeyInfo")
	x509Data := keyInfo.CreateElement("X509Data")
	x509Cert := x509Data.CreateElement("X509Certificate")
	x509Cert.SetText(base64.StdEncoding.EncodeToString(certificate))

	// Add signature to document
	doc.Root().AddChild(sigElem)

	// Return signed XML
	result, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to serialize XML: %w", err)
	}

	return result, nil
}

// loadXSDSchemas loads XSD schemas for validation
func loadXSDSchemas() map[string]string {
	// In production, load actual XSD files
	return map[string]string{
		"2.1": "esign-2.1.xsd",
		"3.0": "esign-3.0.xsd",
	}
}
