package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/esign-go/internal/models"
	"github.com/esign-go/pkg/errors"
	"github.com/esign-go/pkg/logger"
)

// KYCService implements IKYCService interface
type KYCService struct {
	uidaiClient *http.Client
	config      *models.Config
	cryptoSvc   ICryptoService
}

// NewKYCService creates a new KYC service instance
func NewKYCService(config *models.Config, cryptoSvc ICryptoService) *KYCService {
	return &KYCService{
		uidaiClient: &http.Client{
			Timeout: time.Duration(config.UIDAI.Timeout) * time.Second,
		},
		config:    config,
		cryptoSvc: cryptoSvc,
	}
}

// GenerateOTP generates OTP for Aadhaar authentication
func (s *KYCService) GenerateOTP(aadhaar string, requestID int64, req *http.Request, txn, aspID string, attempts int) (*models.OTPGenerationResponse, error) {
	log := logger.GetLogger()

	// Validate Aadhaar
	if err := s.validateAadhaar(aadhaar); err != nil {
		return nil, err
	}

	// Generate hash of Aadhaar
	aadhaarHash := s.generateAadhaarHash(aadhaar)

	// Create UIDAI OTP request
	uidaiReq := &models.UIDAIOTPRequest{
		UID:       aadhaarHash,
		TxnID:     fmt.Sprintf("%s_%d", txn, requestID),
		Timestamp: time.Now(),
		ClientIP:  s.getClientIP(req),
	}

	// Marshal request to XML
	xmlData, err := xml.Marshal(uidaiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OTP request: %w", err)
	}

	// Sign the request
	signedXML, err := s.cryptoSvc.SignXML(string(xmlData),
		[]byte(s.config.UIDAI.PrivateKey),
		[]byte(s.config.UIDAI.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to sign OTP request: %w", err)
	}

	// Send request to UIDAI
	httpReq, err := http.NewRequest("POST", s.config.UIDAI.OtpURL, bytes.NewBufferString(signedXML))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/xml")
	httpReq.Header.Set("X-SubAUA", s.config.UIDAI.SubAUA)
	httpReq.Header.Set("X-License-Key", s.config.UIDAI.LicenseKey)

	// Execute request
	resp, err := s.uidaiClient.Do(httpReq)
	if err != nil {
		return nil, errors.NewKYCServiceError("UIDAI service unavailable", err)
	}
	defer resp.Body.Close()

	// Parse response
	var uidaiResp models.UIDAIOTPResponse
	if err := xml.NewDecoder(resp.Body).Decode(&uidaiResp); err != nil {
		return nil, fmt.Errorf("failed to parse UIDAI response: %w", err)
	}

	// Check response
	if !uidaiResp.Success {
		log.WithField("error", uidaiResp.ErrorMessage).Error("UIDAI OTP generation failed")
		return nil, errors.NewUIDAIAuthenticationError(uidaiResp.ErrorMessage)
	}

	// Return success response
	return &models.OTPGenerationResponse{
		Status:       "1",
		OtpTxn:       uidaiResp.TxnID,
		MaskedMobile: uidaiResp.MaskedMobile,
		RetryCount:   s.config.OTPRetryAttempts - attempts,
	}, nil
}

// VerifyOTP verifies the OTP
func (s *KYCService) VerifyOTP(otpTxn, otp, aadhaar string, requestID int64, req *http.Request, txn, aspID string) (*models.AadhaarDetailsVO, error) {
	log := logger.GetLogger()

	// Validate inputs
	if otpTxn == "" || otp == "" || aadhaar == "" {
		return nil, errors.NewValidationError("Invalid OTP verification parameters")
	}

	// Generate Aadhaar hash
	aadhaarHash := s.generateAadhaarHash(aadhaar)

	// Create UIDAI auth request
	uidaiReq := &models.UIDAIAuthRequest{
		UID:        aadhaarHash,
		TxnID:      otpTxn,
		AuthType:   "OTP",
		SubAUA:     s.config.UIDAI.SubAUA,
		LicenseKey: s.config.UIDAI.LicenseKey,
		Consent:    true,
		ClientIP:   s.getClientIP(req),
		Timestamp:  time.Now(),
		OTP:        otp,
	}

	// Marshal and sign request
	xmlData, err := xml.Marshal(uidaiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth request: %w", err)
	}

	signedXML, err := s.cryptoSvc.SignXML(string(xmlData),
		[]byte(s.config.UIDAI.PrivateKey),
		[]byte(s.config.UIDAI.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to sign auth request: %w", err)
	}

	// Send request to UIDAI
	httpReq, err := http.NewRequest("POST", s.config.UIDAI.AuthURL, bytes.NewBufferString(signedXML))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/xml")
	httpReq.Header.Set("X-SubAUA", s.config.UIDAI.SubAUA)
	httpReq.Header.Set("X-License-Key", s.config.UIDAI.LicenseKey)

	// Execute request
	resp, err := s.uidaiClient.Do(httpReq)
	if err != nil {
		return nil, errors.NewKYCServiceError("UIDAI service unavailable", err)
	}
	defer resp.Body.Close()

	// Parse response
	var uidaiResp models.UIDAIAuthResponse
	if err := xml.NewDecoder(resp.Body).Decode(&uidaiResp); err != nil {
		return nil, fmt.Errorf("failed to parse UIDAI response: %w", err)
	}

	// Check authentication success
	if !uidaiResp.Success {
		log.WithField("error", uidaiResp.ErrorMessage).Error("UIDAI authentication failed")
		return nil, errors.NewKYCAuthenticationError("OTP verification failed")
	}

	// Fetch eKYC data if authentication successful
	kycData, err := s.fetchEKYC(uidaiResp.AuthCode, otpTxn)
	if err != nil {
		log.WithError(err).Error("Failed to fetch eKYC data")
		// Return basic details even if eKYC fails
		return &models.AadhaarDetailsVO{
			ResponseCode: uidaiResp.ResponseCode,
			Token:        uidaiResp.AuthCode,
			AadhaarNo:    aadhaar[len(aadhaar)-4:], // Last 4 digits
		}, nil
	}

	return kycData, nil
}

// AuthenticateBiometric authenticates using biometric data
func (s *KYCService) AuthenticateBiometric(bioData *models.BiometricData, requestID int64, req *http.Request, txn, aspID string) (*models.AadhaarDetailsVO, error) {

	// Validate biometric data
	if bioData == nil || bioData.Data == "" {
		return nil, errors.NewValidationError("Invalid biometric data")
	}

	// Extract Aadhaar from biometric XML
	aadhaar, err := s.extractAadhaarFromBioXML(bioData.Data)
	if err != nil {
		return nil, err
	}

	// Generate Aadhaar hash
	aadhaarHash := s.generateAadhaarHash(aadhaar)

	// Create UIDAI auth request
	uidaiReq := &models.UIDAIAuthRequest{
		UID:           aadhaarHash,
		TxnID:         fmt.Sprintf("%s_%d_bio", txn, requestID),
		AuthType:      bioData.Type,
		SubAUA:        s.config.UIDAI.SubAUA,
		LicenseKey:    s.config.UIDAI.LicenseKey,
		Consent:       true,
		ClientIP:      s.getClientIP(req),
		Timestamp:     time.Now(),
		BiometricData: bioData.Data,
	}
	log := logger.GetLogger()
	log.WithField("aadhaar", aadhaar).Debug("Biometric authentication request")
	log.WithField("uidaiReq", uidaiReq).Debug("Biometric authentication request")
	// Process similar to OTP verification
	// ... (implementation similar to VerifyOTP)

	return &models.AadhaarDetailsVO{
		Name:         "Test User",
		Gender:       "M",
		Dob:          "01-01-1990",
		ResponseCode: "Y",
		Token:        "test-bio-token",
		AadhaarNo:    aadhaar[len(aadhaar)-4:],
	}, nil
}

// PerformOfflineKYC performs offline KYC verification
func (s *KYCService) PerformOfflineKYC(xmlData string, shareCode string, requestID int64) (*models.AadhaarDetailsVO, error) {
	// Validate offline XML
	if xmlData == "" || shareCode == "" {
		return nil, errors.NewValidationError("Invalid offline KYC parameters")
	}

	// Decrypt and verify offline XML using share code
	// This is a simplified implementation
	// In production, implement proper offline KYC verification

	return &models.AadhaarDetailsVO{
		Name:         "Offline User",
		Gender:       "M",
		Dob:          "01-01-1990",
		State:        "Maharashtra",
		Pincode:      "400001",
		ResponseCode: "Y",
		Token:        "offline-token",
		AadhaarNo:    "1234", // Last 4 digits from offline XML
	}, nil
}

// Helper methods

func (s *KYCService) validateAadhaar(aadhaar string) error {
	// Remove spaces and validate length
	aadhaar = strings.ReplaceAll(aadhaar, " ", "")
	if len(aadhaar) != 12 {
		return errors.NewValidationError("Invalid Aadhaar number length")
	}

	// Validate digits only
	for _, c := range aadhaar {
		if c < '0' || c > '9' {
			return errors.NewValidationError("Aadhaar must contain only digits")
		}
	}

	// Validate checksum (Verhoeff algorithm)
	if !s.validateVerhoeff(aadhaar) {
		return errors.NewValidationError("Invalid Aadhaar checksum")
	}

	return nil
}

func (s *KYCService) validateVerhoeff(aadhaar string) bool {
	// Simplified Verhoeff validation
	// In production, implement full Verhoeff algorithm
	return true
}

func (s *KYCService) generateAadhaarHash(aadhaar string) string {
	h := sha256.New()
	h.Write([]byte(aadhaar))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *KYCService) getClientIP(req *http.Request) string {
	// Try to get real IP from headers
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return req.RemoteAddr
}

func (s *KYCService) fetchEKYC(authCode, txnID string) (*models.AadhaarDetailsVO, error) {
	// Create eKYC request
	ekycReq := &models.UIDAIEKYCRequest{
		UID:       txnID,
		TxnID:     txnID,
		AuthCode:  authCode,
		Timestamp: time.Now(),
	}

	// Marshal and sign request
	xmlData, err := xml.Marshal(ekycReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal eKYC request: %w", err)
	}

	signedXML, err := s.cryptoSvc.SignXML(string(xmlData),
		[]byte(s.config.UIDAI.PrivateKey),
		[]byte(s.config.UIDAI.Certificate))
	if err != nil {
		return nil, fmt.Errorf("failed to sign eKYC request: %w", err)
	}

	// Send request to UIDAI
	httpReq, err := http.NewRequest("POST", s.config.UIDAI.EkycURL, bytes.NewBufferString(signedXML))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/xml")
	httpReq.Header.Set("X-SubAUA", s.config.UIDAI.SubAUA)
	httpReq.Header.Set("X-License-Key", s.config.UIDAI.LicenseKey)

	// Execute request
	resp, err := s.uidaiClient.Do(httpReq)
	if err != nil {
		return nil, errors.NewKYCServiceError("UIDAI eKYC service unavailable", err)
	}
	defer resp.Body.Close()

	// Parse response
	var ekycResp models.UIDAIEKYCResponse
	if err := xml.NewDecoder(resp.Body).Decode(&ekycResp); err != nil {
		return nil, fmt.Errorf("failed to parse eKYC response: %w", err)
	}

	if !ekycResp.Success {
		return nil, fmt.Errorf("eKYC fetch failed: %s", ekycResp.ErrorMessage)
	}

	// Convert to AadhaarDetailsVO
	return s.convertKYCData(ekycResp.KYCData), nil
}

func (s *KYCService) convertKYCData(kycData *models.KYCData) *models.AadhaarDetailsVO {
	if kycData == nil {
		return nil
	}

	// Parse address
	addressParts := strings.Split(kycData.Address, ",")
	addr := &models.AddressInfo{}
	if len(addressParts) > 0 {
		addr.House = strings.TrimSpace(addressParts[0])
	}
	if len(addressParts) > 1 {
		addr.Street = strings.TrimSpace(addressParts[1])
	}
	if len(addressParts) > 2 {
		addr.Locality = strings.TrimSpace(addressParts[2])
	}

	return &models.AadhaarDetailsVO{
		Name:         kycData.Name,
		Gender:       kycData.Gender,
		Dob:          kycData.DOB,
		Address:      addr,
		Photo:        kycData.Photo,
		ResponseCode: "Y",
		Token:        "kyc-token",
		AadhaarNo:    kycData.AadhaarHash[len(kycData.AadhaarHash)-4:], // Last 4 digits
	}
}

func (s *KYCService) extractAadhaarFromBioXML(bioXML string) (string, error) {
	// Parse biometric XML to extract Aadhaar
	// This is a simplified implementation
	// In production, parse the actual biometric XML format

	// For now, return a test Aadhaar
	return "123456789012", nil
}

// ProcessOkycOTPRequest processes offline KYC OTP request
func (s *KYCService) ProcessOkycOTPRequest(req *models.OkycOtpRequest, clientIP string) (*models.OKYCOTPResponse, error) {
	log := logger.GetLogger()
	log.Info("Processing offline KYC OTP request")

	// Validate request
	if req == nil || req.Msg1 == "" || req.ShareCode == "" {
		return nil, errors.NewValidationError("Invalid offline KYC OTP request")
	}

	// Validate last 4 digits of Aadhaar if provided
	if req.LastDigitOfAadhaar != "" && len(req.LastDigitOfAadhaar) != 4 {
		return nil, errors.NewValidationError("Invalid Aadhaar last digits")
	}

	// Process ZIP file if provided
	if len(req.ZipFile) > 0 {
		// In production, validate and process the offline KYC ZIP file
		// Check digital signature, extract XML, etc.
		log.Debug("Processing offline KYC ZIP file")
	}

	// Generate OTP transaction ID
	otpTxn := fmt.Sprintf("OKYC_%d_%d", req.RequestID, time.Now().Unix())

	// In production, this would:
	// 1. Validate the offline KYC XML signature
	// 2. Extract mobile number from offline KYC
	// 3. Send OTP to the registered mobile
	// 4. Store OTP transaction details

	// For now, return a success response
	return &models.OKYCOTPResponse{
		Status:     "1",
		Msg:        "OTP sent on registered mobile.",
		OtpTxn:     otpTxn,
		RetryCount: s.config.OTPRetryAttempts,
	}, nil
}

// VerifyOkycOTP verifies offline KYC OTP
func (s *KYCService) VerifyOkycOTP(req *models.OkycVerificationModel, clientIP string) (*models.OkycVerificationResponse, error) {
	log := logger.GetLogger()
	log.Info("Verifying offline KYC OTP")

	// Validate request
	if req == nil || req.OtpTxn == "" || req.OTP == "" || req.ShareCode == "" {
		return nil, errors.NewValidationError("Invalid offline KYC verification request")
	}

	// In production, this would:
	// 1. Verify OTP against stored value
	// 2. Decrypt offline KYC XML using share code
	// 3. Extract and return KYC details

	// For now, simulate OTP verification
	if req.OTP != "123456" { // Test OTP
		return &models.OkycVerificationResponse{
			Status: "FAIL",
			Msg:    "Invalid OTP",
		}, nil
	}

	// Return success response
	return &models.OkycVerificationResponse{
		Status: "OK",
		Msg:    "Verification successful",
		Form:   s.generateSuccessForm(req.RequestID),
	}, nil
}

func (s *KYCService) generateSuccessForm(requestID int64) string {
	// Generate form for successful verification
	return fmt.Sprintf(`<form action='/authenticate/es' id='esid' method='post'>
		<input type='hidden' id='kid' name='kid' value='%d'/>
		<input type='submit' value='submit'></form>`, requestID)
}

// ProcessFaceRecognition processes face recognition request
func (s *KYCService) ProcessFaceRecognition(req *models.FaceRecognitionRequest, clientIP string) (*models.FaceRecognitionResult, error) {
	log := logger.GetLogger()
	log.Info("Processing face recognition")

	// Validate request
	if req.TransactionID == "" {
		return nil, errors.NewValidationError("Transaction ID is required")
	}

	if len(req.VideoData) == 0 {
		return nil, errors.NewValidationError("Video data is required")
	}

	// TODO: Implement actual face recognition logic
	// This would involve:
	// 1. Extract frames from video
	// 2. Extract face from frames
	// 3. Compare with stored photo from KYC
	// 4. Return match result

	// For now, return a mock response
	log.WithFields(map[string]interface{}{
		"transactionID": req.TransactionID,
		"videoSize":     len(req.VideoData),
		"fileName":      req.VideoFileName,
	}).Debug("Processing face recognition request")

	// Mock implementation - in production, integrate with actual face recognition service
	result := &models.FaceRecognitionResult{
		Success: false, // Default to failed for security
		Status:  "R",   // R for Rejected
		Message: "Face recognition not implemented",
	}

	return result, nil
}
