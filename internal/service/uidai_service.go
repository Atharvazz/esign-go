package service

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/esign-go/internal/config"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/pkg/logger"
)

// UIDAIService implements the IUIDAIService interface
type UIDAIService struct {
	config     config.UIDAIConfig
	httpClient *http.Client
}

// NewUIDAIService creates a new UIDAI service
func NewUIDAIService(cfg config.UIDAIConfig) *UIDAIService {
	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Set to true only for testing
			},
		},
	}

	return &UIDAIService{
		config:     cfg,
		httpClient: httpClient,
	}
}

// SendAuthRequest sends authentication request to UIDAI
func (s *UIDAIService) SendAuthRequest(authRequest *models.UIDAIAuthRequest) (*models.UIDAIAuthResponse, error) {
	// Build XML request
	xmlReq, err := s.buildAuthXML(authRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to build auth XML: %w", err)
	}

	// Log request if enabled
	logger.Debug("UIDAI Auth Request: %s", string(xmlReq))

	// Send request
	resp, err := s.sendRequest(s.config.AuthURL, xmlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send auth request: %w", err)
	}

	// Parse response
	var authResp models.UIDAIAuthResponse
	if err := xml.Unmarshal(resp, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth response: %w", err)
	}

	// Log response if enabled
	logger.Debug("UIDAI Auth Response: %+v", authResp)

	return &authResp, nil
}

// SendOTPRequest sends OTP request to UIDAI
func (s *UIDAIService) SendOTPRequest(otpRequest *models.UIDAIOTPRequest) (*models.UIDAIOTPResponse, error) {
	// Build XML request
	xmlReq, err := s.buildOTPXML(otpRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to build OTP XML: %w", err)
	}

	// Log request if enabled
	logger.Debug("UIDAI OTP Request: %s", string(xmlReq))

	// Send request
	resp, err := s.sendRequest(s.config.OTPAuthURL, xmlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send OTP request: %w", err)
	}

	// Parse response
	var otpResp models.UIDAIOTPResponse
	if err := xml.Unmarshal(resp, &otpResp); err != nil {
		return nil, fmt.Errorf("failed to parse OTP response: %w", err)
	}

	// Log response if enabled
	logger.Debug("UIDAI OTP Response: %+v", otpResp)

	return &otpResp, nil
}

// SendEKYCRequest sends eKYC request to UIDAI
func (s *UIDAIService) SendEKYCRequest(ekycRequest *models.UIDAIEKYCRequest) (*models.UIDAIEKYCResponse, error) {
	// Build XML request
	xmlReq, err := s.buildEKYCXML(ekycRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to build eKYC XML: %w", err)
	}

	// Log request if enabled
	logger.Debug("UIDAI eKYC Request: %s", string(xmlReq))

	// Send request
	resp, err := s.sendRequest(s.config.EKYCAuthURL, xmlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send eKYC request: %w", err)
	}

	// Parse response
	var ekycResp models.UIDAIEKYCResponse
	if err := xml.Unmarshal(resp, &ekycResp); err != nil {
		return nil, fmt.Errorf("failed to parse eKYC response: %w", err)
	}

	// Log response if enabled
	logger.Debug("UIDAI eKYC Response: %+v", ekycResp)

	return &ekycResp, nil
}

// buildAuthXML builds the authentication XML request
func (s *UIDAIService) buildAuthXML(authRequest *models.UIDAIAuthRequest) ([]byte, error) {
	// Create Auth element
	auth := &authXML{
		UID:  authRequest.UID,
		Txn:  authRequest.TxnID,
		Ac:   s.config.SubAUA,
		Sa:   s.config.SubAUA,
		Ver:  s.config.AuthVersion,
		Tid:  "registered",
		Lk:   s.config.LicenseKey,
		Ts:   authRequest.Timestamp.Format("2006-01-02T15:04:05"),
		Uses: &usesXML{},
	}

	// Set authentication factors
	switch authRequest.AuthType {
	case models.AuthModeOTP:
		auth.Uses.Otp = "y"
		auth.Pids = &pidsXML{
			Otp: &otpXML{Value: authRequest.OTP},
		}
	case models.AuthModeBiometric:
		auth.Uses.Bio = "y"
		auth.Uses.Bt = "FMR"
		// Add biometric data
		auth.Bios = &biosXML{
			Bio: []bioXML{
				{
					Type: "FMR",
					Data: authRequest.BiometricData,
				},
			},
		}
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(auth, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth XML: %w", err)
	}

	return xmlData, nil
}

// buildOTPXML builds the OTP request XML
func (s *UIDAIService) buildOTPXML(otpRequest *models.UIDAIOTPRequest) ([]byte, error) {
	// Create OTP request element
	otp := &otpReqXML{
		UID:  otpRequest.UID,
		Txn:  otpRequest.TxnID,
		Ac:   s.config.SubAUA,
		Sa:   s.config.SubAUA,
		Ver:  s.config.AuthVersion,
		Lk:   s.config.LicenseKey,
		Ts:   otpRequest.Timestamp.Format("2006-01-02T15:04:05"),
		Type: "A",
		Otpv: &otpvXML{
			Av: s.config.AuthVersion,
		},
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(otp, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OTP XML: %w", err)
	}

	return xmlData, nil
}

// buildEKYCXML builds the eKYC request XML
func (s *UIDAIService) buildEKYCXML(ekycRequest *models.UIDAIEKYCRequest) ([]byte, error) {
	// Create eKYC request element
	ekyc := &ekycReqXML{
		UID:  ekycRequest.UID,
		Txn:  ekycRequest.TxnID,
		Ac:   s.config.SubAUA,
		Sa:   s.config.SubAUA,
		Ver:  s.config.AuthVersion,
		Lk:   s.config.LicenseKey,
		Ts:   ekycRequest.Timestamp.Format("2006-01-02T15:04:05"),
		Code: ekycRequest.AuthCode,
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(ekyc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal eKYC XML: %w", err)
	}

	return xmlData, nil
}

// sendRequest sends an HTTP request to UIDAI
func (s *UIDAIService) sendRequest(url string, xmlData []byte) ([]byte, error) {
	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(xmlData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml")

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// XML structures for UIDAI communication

type authXML struct {
	XMLName xml.Name `xml:"Auth"`
	UID     string   `xml:"uid,attr"`
	Txn     string   `xml:"txn,attr"`
	Ac      string   `xml:"ac,attr"`
	Sa      string   `xml:"sa,attr"`
	Ver     string   `xml:"ver,attr"`
	Tid     string   `xml:"tid,attr"`
	Lk      string   `xml:"lk,attr"`
	Ts      string   `xml:"ts,attr"`
	Uses    *usesXML `xml:"Uses"`
	Pids    *pidsXML `xml:"Pids,omitempty"`
	Bios    *biosXML `xml:"Bios,omitempty"`
}

type usesXML struct {
	XMLName xml.Name `xml:"Uses"`
	Otp     string   `xml:"otp,attr,omitempty"`
	Bio     string   `xml:"bio,attr,omitempty"`
	Bt      string   `xml:"bt,attr,omitempty"`
}

type pidsXML struct {
	XMLName xml.Name `xml:"Pids"`
	Otp     *otpXML  `xml:"Otp,omitempty"`
}

type otpXML struct {
	XMLName xml.Name `xml:"Otp"`
	Value   string   `xml:"value,attr"`
}

type biosXML struct {
	XMLName xml.Name `xml:"Bios"`
	Bio     []bioXML `xml:"Bio"`
}

type bioXML struct {
	XMLName xml.Name `xml:"Bio"`
	Type    string   `xml:"type,attr"`
	Data    string   `xml:",innerxml"`
}

type otpReqXML struct {
	XMLName xml.Name `xml:"OtpReq"`
	UID     string   `xml:"uid,attr"`
	Txn     string   `xml:"txn,attr"`
	Ac      string   `xml:"ac,attr"`
	Sa      string   `xml:"sa,attr"`
	Ver     string   `xml:"ver,attr"`
	Lk      string   `xml:"lk,attr"`
	Ts      string   `xml:"ts,attr"`
	Type    string   `xml:"type,attr"`
	Otpv    *otpvXML `xml:"Otpv"`
}

type otpvXML struct {
	XMLName xml.Name `xml:"Otpv"`
	Av      string   `xml:"av,attr"`
}

type ekycReqXML struct {
	XMLName xml.Name `xml:"EkycReq"`
	UID     string   `xml:"uid,attr"`
	Txn     string   `xml:"txn,attr"`
	Ac      string   `xml:"ac,attr"`
	Sa      string   `xml:"sa,attr"`
	Ver     string   `xml:"ver,attr"`
	Lk      string   `xml:"lk,attr"`
	Ts      string   `xml:"ts,attr"`
	Code    string   `xml:"code,attr"`
}
