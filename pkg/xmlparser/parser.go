package xmlparser

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/esign-go/internal/models"
)

// ParseEsignRequest parses the eSign request XML
func ParseEsignRequest(xmlData []byte) (*models.EsignRequest, error) {
	// Parse XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	// Get root element
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("XML has no root element")
	}

	// Create request object
	req := &models.EsignRequest{
		Documents: make([]models.Document, 0),
	}

	// Parse root attributes
	req.ASPID = root.SelectAttrValue("aspId", "")
	req.ASPTxnID = root.SelectAttrValue("txn", "")
	req.AuthMode = root.SelectAttrValue("authMode", "")
	req.ResponseURL = root.SelectAttrValue("responseUrl", "")
	req.ErrorURL = root.SelectAttrValue("errorUrl", "")
	
	// Parse timestamp
	tsStr := root.SelectAttrValue("ts", "")
	if tsStr != "" {
		if ts, err := parseTimestamp(tsStr); err == nil {
			req.RequestTime = ts
		}
	}

	// Parse signer info
	if signerElem := root.SelectElement("SignerInfo"); signerElem != nil {
		req.SignerInfo = parseSignerInfo(signerElem)
	}

	// Parse documents
	if docsElem := root.SelectElement("Docs"); docsElem != nil {
		for _, inputHashElem := range docsElem.SelectElements("InputHash") {
			doc := parseDocument(inputHashElem)
			req.Documents = append(req.Documents, doc)
		}
	}

	// Parse signature if present
	if sigElem := root.SelectElement("Signature"); sigElem != nil {
		if sigValueElem := sigElem.SelectElement("SignatureValue"); sigValueElem != nil {
			sigValue := strings.TrimSpace(sigValueElem.Text())
			if decoded, err := base64.StdEncoding.DecodeString(sigValue); err == nil {
				req.Signature = decoded
			}
		}
	}

	return req, nil
}

// parseSignerInfo parses the SignerInfo element
func parseSignerInfo(elem *etree.Element) models.SignerInfo {
	return models.SignerInfo{
		Name:     elem.SelectAttrValue("name", ""),
		Email:    elem.SelectAttrValue("email", ""),
		Mobile:   elem.SelectAttrValue("mobile", ""),
		Location: elem.SelectAttrValue("location", ""),
		Reason:   elem.SelectAttrValue("reason", ""),
	}
}

// parseDocument parses an InputHash element into a Document
func parseDocument(elem *etree.Element) models.Document {
	doc := models.Document{
		ID:   elem.SelectAttrValue("id", ""),
		Hash: strings.TrimSpace(elem.Text()),
		Type: elem.SelectAttrValue("docType", "pdf"),
	}

	// Parse document info
	docInfo := elem.SelectAttrValue("docInfo", "")
	if docInfo != "" {
		// Parse base64 encoded document info
		if decoded, err := base64.StdEncoding.DecodeString(docInfo); err == nil {
			// Parse the decoded info (could be JSON or custom format)
			parseDocInfo(string(decoded), &doc)
		}
	}

	// Parse signature position if provided
	if pageNo := elem.SelectAttrValue("pageNo", ""); pageNo != "" {
		fmt.Sscanf(pageNo, "%d", &doc.PageNo)
	}
	if x := elem.SelectAttrValue("x", ""); x != "" {
		fmt.Sscanf(x, "%d", &doc.X)
	}
	if y := elem.SelectAttrValue("y", ""); y != "" {
		fmt.Sscanf(y, "%d", &doc.Y)
	}
	if width := elem.SelectAttrValue("width", ""); width != "" {
		fmt.Sscanf(width, "%d", &doc.Width)
	}
	if height := elem.SelectAttrValue("height", ""); height != "" {
		fmt.Sscanf(height, "%d", &doc.Height)
	}

	return doc
}

// parseDocInfo parses document info string
func parseDocInfo(info string, doc *models.Document) {
	// Simple key-value parsing
	// Format: "name:document.pdf;content:base64data"
	parts := strings.Split(info, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			
			switch key {
			case "name":
				doc.Name = value
			case "content":
				doc.Content = value
			}
		}
	}
}

// parseTimestamp parses various timestamp formats
func parseTimestamp(ts string) (time.Time, error) {
	// Try different formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"20060102150405",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", ts)
}

// BuildEsignResponse builds the eSign response XML
func BuildEsignResponse(resp *models.EsignResponse) ([]byte, error) {
	// Create response document
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	// Create root element
	root := doc.CreateElement("EsignResp")
	root.CreateAttr("status", resp.Status)
	root.CreateAttr("ts", resp.Timestamp.Format(time.RFC3339))
	root.CreateAttr("txn", resp.RequestID)
	
	if resp.ResponseCode != "" {
		root.CreateAttr("resCode", resp.ResponseCode)
	}
	
	// Add response message
	if resp.ResponseMsg != "" {
		msgElem := root.CreateElement("RespMsg")
		msgElem.SetText(resp.ResponseMsg)
	}

	// Add error details if present
	if resp.Error != "" {
		errElem := root.CreateElement("Error")
		errElem.CreateAttr("code", resp.ErrorType)
		errElem.SetText(resp.Error)
	}

	// Add certificate if present
	if resp.Certificate != "" {
		certElem := root.CreateElement("UserX509Certificate")
		certElem.SetText(resp.Certificate)
	}

	// Add signed documents
	if len(resp.SignedDocs) > 0 {
		docsElem := root.CreateElement("Signatures")
		
		for _, doc := range resp.SignedDocs {
			docSigElem := docsElem.CreateElement("DocSignature")
			docSigElem.CreateAttr("id", doc.ID)
			docSigElem.CreateAttr("sigHashAlgorithm", "SHA256")
			docSigElem.CreateAttr("signedOn", doc.SignedAt.Format(time.RFC3339))
			
			// Add signature value
			sigElem := docSigElem.CreateElement("Signature")
			sigElem.SetText(doc.Signature)
		}
	}

	// Convert to string
	doc.Indent(2)
	return doc.WriteToBytes()
}

// XML structures for specific requests

// EsignXML represents the eSign XML request structure
type EsignXML struct {
	XMLName     xml.Name        `xml:"Esign"`
	Ver         string          `xml:"ver,attr"`
	Sc          string          `xml:"sc,attr"`
	Ts          string          `xml:"ts,attr"`
	Txn         string          `xml:"txn,attr"`
	AspID       string          `xml:"aspId,attr"`
	AuthMode    string          `xml:"authMode,attr"`
	ResponseURL string          `xml:"responseUrl,attr"`
	ErrorURL    string          `xml:"errorUrl,attr,omitempty"`
	Docs        *DocsXML        `xml:"Docs"`
	SignerInfo  *SignerInfoXML  `xml:"SignerInfo,omitempty"`
	Signature   *SignatureXML   `xml:"Signature,omitempty"`
}

// DocsXML represents the Docs element
type DocsXML struct {
	XMLName     xml.Name       `xml:"Docs"`
	InputHashes []InputHashXML `xml:"InputHash"`
}

// InputHashXML represents an InputHash element
type InputHashXML struct {
	XMLName       xml.Name `xml:"InputHash"`
	ID            string   `xml:"id,attr"`
	HashAlgorithm string   `xml:"hashAlgorithm,attr"`
	DocInfo       string   `xml:"docInfo,attr,omitempty"`
	DocType       string   `xml:"docType,attr,omitempty"`
	PageNo        string   `xml:"pageNo,attr,omitempty"`
	X             string   `xml:"x,attr,omitempty"`
	Y             string   `xml:"y,attr,omitempty"`
	Width         string   `xml:"width,attr,omitempty"`
	Height        string   `xml:"height,attr,omitempty"`
	Hash          string   `xml:",chardata"`
}

// SignerInfoXML represents the SignerInfo element
type SignerInfoXML struct {
	XMLName  xml.Name `xml:"SignerInfo"`
	Name     string   `xml:"name,attr,omitempty"`
	Email    string   `xml:"email,attr,omitempty"`
	Mobile   string   `xml:"mobile,attr,omitempty"`
	Location string   `xml:"location,attr,omitempty"`
	Reason   string   `xml:"reason,attr,omitempty"`
}

// SignatureXML represents the Signature element
type SignatureXML struct {
	XMLName        xml.Name            `xml:"Signature"`
	SignedInfo     *SignedInfoXML      `xml:"SignedInfo"`
	SignatureValue string              `xml:"SignatureValue"`
	KeyInfo        *KeyInfoXML         `xml:"KeyInfo,omitempty"`
}

// SignedInfoXML represents the SignedInfo element
type SignedInfoXML struct {
	XMLName                xml.Name               `xml:"SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	Reference              []ReferenceXML         `xml:"Reference"`
}

// CanonicalizationMethod represents the canonicalization method
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureMethod represents the signature method
type SignatureMethod struct {
	XMLName   xml.Name `xml:"SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// ReferenceXML represents a Reference element
type ReferenceXML struct {
	XMLName      xml.Name          `xml:"Reference"`
	URI          string            `xml:"URI,attr,omitempty"`
	Transforms   *TransformsXML    `xml:"Transforms,omitempty"`
	DigestMethod DigestMethodXML   `xml:"DigestMethod"`
	DigestValue  string            `xml:"DigestValue"`
}

// TransformsXML represents the Transforms element
type TransformsXML struct {
	XMLName   xml.Name       `xml:"Transforms"`
	Transform []TransformXML `xml:"Transform"`
}

// TransformXML represents a Transform element
type TransformXML struct {
	XMLName   xml.Name `xml:"Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// DigestMethodXML represents the DigestMethod element
type DigestMethodXML struct {
	XMLName   xml.Name `xml:"DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// KeyInfoXML represents the KeyInfo element
type KeyInfoXML struct {
	XMLName  xml.Name     `xml:"KeyInfo"`
	X509Data *X509DataXML `xml:"X509Data,omitempty"`
}

// X509DataXML represents the X509Data element
type X509DataXML struct {
	XMLName         xml.Name `xml:"X509Data"`
	X509Certificate string   `xml:"X509Certificate,omitempty"`
}

// ParseEsignXML parses eSign XML using struct unmarshaling
func ParseEsignXML(xmlData []byte) (*EsignXML, error) {
	var esign EsignXML
	if err := xml.Unmarshal(xmlData, &esign); err != nil {
		return nil, fmt.Errorf("failed to unmarshal XML: %w", err)
	}
	return &esign, nil
}

// ToEsignRequest converts EsignXML to models.EsignRequest
func (e *EsignXML) ToEsignRequest() *models.EsignRequest {
	req := &models.EsignRequest{
		ASPID:       e.AspID,
		ASPTxnID:    e.Txn,
		AuthMode:    e.AuthMode,
		ResponseURL: e.ResponseURL,
		ErrorURL:    e.ErrorURL,
		Documents:   make([]models.Document, 0),
	}

	// Parse timestamp
	if ts, err := parseTimestamp(e.Ts); err == nil {
		req.RequestTime = ts
	}

	// Parse signer info
	if e.SignerInfo != nil {
		req.SignerInfo = models.SignerInfo{
			Name:     e.SignerInfo.Name,
			Email:    e.SignerInfo.Email,
			Mobile:   e.SignerInfo.Mobile,
			Location: e.SignerInfo.Location,
			Reason:   e.SignerInfo.Reason,
		}
	}

	// Parse documents
	if e.Docs != nil {
		for _, ih := range e.Docs.InputHashes {
			doc := models.Document{
				ID:   ih.ID,
				Hash: ih.Hash,
				Type: ih.DocType,
			}
			
			// Parse numeric fields
			fmt.Sscanf(ih.PageNo, "%d", &doc.PageNo)
			fmt.Sscanf(ih.X, "%d", &doc.X)
			fmt.Sscanf(ih.Y, "%d", &doc.Y)
			fmt.Sscanf(ih.Width, "%d", &doc.Width)
			fmt.Sscanf(ih.Height, "%d", &doc.Height)
			
			req.Documents = append(req.Documents, doc)
		}
	}

	// Parse signature
	if e.Signature != nil && e.Signature.SignatureValue != "" {
		if decoded, err := base64.StdEncoding.DecodeString(e.Signature.SignatureValue); err == nil {
			req.Signature = decoded
		}
	}

	return req
}