package service

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/esign-go/internal/models"
	"github.com/esign-go/internal/repository"
	"github.com/esign-go/pkg/errors"
	"github.com/esign-go/pkg/logger"
	"github.com/esign-go/pkg/xmlparser"
)

// IEsignService defines the interface for esign service
type IEsignService interface {
	PreValidateAndPrepare(xml string, req *http.Request, version, userAgent string) (*models.EsignRequestDTO, error)
	TestEsignRequestEligibility(requestID string) (*models.EsignRequestDTO, error)
	SaveAspReqXML(xml string, requestID int64, clientIP string) error
	SaveEsignResponse(msg string, requestID int64, clientIP string) error
	UpdateRetryAttempt(requestID int64) error
	UpdateAuthAttempt(requestID int64) error
	UpdateTransition(requestID int64, status string) error
	UpdateKYCDetails(requestID int64, kyc *models.EsignKycDetailDTO, status string) error
	GetRequestDetailWithKYC(requestID int64) (*models.EsignRequestDTO, error)
	ProcessEsignRequest(req *models.EsignRequestDTO, kyc *models.AadhaarDetailsVO, isAborted bool, clientIP string) (string, error)
	TestESPLink() error
	GenerateSignedXMLResponse(requestID int64, errCode, errMsg, status, txn, resCode, clientIP string) (string, error)
}

// EsignService implements the esign service
type EsignService struct {
	repo          repository.IEsignRepository
	aspRepo       repository.IASPRepository
	xmlValidator  *xmlparser.XMLValidator
	cryptoService ICryptoService
	remoteService IRemoteSigningService
	config        *models.Config
	errorCodes    map[string]*models.ErrorCode
}

// NewEsignService creates a new esign service
func NewEsignService(
	repo repository.IEsignRepository,
	aspRepo repository.IASPRepository,
	xmlValidator *xmlparser.XMLValidator,
	cryptoService ICryptoService,
	remoteService IRemoteSigningService,
	config *models.Config,
) *EsignService {
	return &EsignService{
		repo:          repo,
		aspRepo:       aspRepo,
		xmlValidator:  xmlValidator,
		cryptoService: cryptoService,
		remoteService: remoteService,
		config:        config,
		errorCodes:    loadErrorCodes(),
	}
}

// PreValidateAndPrepare validates and prepares the esign request
func (s *EsignService) PreValidateAndPrepare(xmlData string, req *http.Request, version, userAgent string) (*models.EsignRequestDTO, error) {
	log := logger.GetLogger()
	log.Debug("Inside PreValidateAndPrepare")

	dto := &models.EsignRequestDTO{}

	// Test ESP services availability
	if err := s.TestESPLink(); err != nil {
		return nil, err
	}

	// Validate XML size (max 100KB)
	if len(xmlData) > s.config.MaxXMLSize {
		return s.createErrorResponse(dto, "ESP-101", "XML size exceeds limit", "")
	}

	// Validate against XSD schema
	if err := s.xmlValidator.ValidateXSD(xmlData, version); err != nil {
		log.WithError(err).Error("XSD validation failed")
		return s.createErrorResponse(dto, "ESP-102", "XSD validation failed", "")
	}

	// Parse XML request
	esignReq, err := s.xmlValidator.ParseEsignRequest(xmlData)
	if err != nil {
		log.WithError(err).Error("Failed to parse XML")
		return s.createErrorResponse(dto, "ESP-103", "Invalid XML structure", "")
	}

	dto.EsignRequest = esignReq

	// Security checks
	if strings.Contains(esignReq.ResponseURL, "javascript") || strings.Contains(esignReq.ResponseURL, "alert") {
		return s.createErrorResponse(dto, "ESP-000", "Invalid response URL", esignReq.ResponseURL)
	}

	// Verify XML signature
	sigInfo, err := s.xmlValidator.VerifySignature(xmlData)
	if err != nil {
		log.WithError(err).Error("Signature verification failed")
		return s.createErrorResponse(dto, "ESP-103", "XML signature verification failed", esignReq.ResponseURL)
	}

	dto.Subject = sigInfo.Subject
	dto.CertificateSerial = sigInfo.SerialNumber

	// Extract CN from subject
	signerCN := s.extractCN(sigInfo.Subject)
	aspTxn := esignReq.Txn
	aspID := esignReq.AspID
	dto.AspID = aspID
	dto.ResponseURL = esignReq.ResponseURL

	log.WithFields(map[string]interface{}{
		"txn_id": aspTxn,
		"asp_id": aspID,
	}).Debug("Processing request")

	// Validate ASP
	asp, err := s.aspRepo.GetASPDetails(aspID)
	if err != nil {
		if err == sql.ErrNoRows {
			return s.createErrorResponse(dto, "ESP-001", "Invalid ASP ID", esignReq.ResponseURL)
		}
		return nil, err
	}

	if asp.Status != 1 {
		return s.createErrorResponse(dto, "ESP-002", "ASP ID is inactive", esignReq.ResponseURL)
	}

	dto.AumID = asp.AumID
	dto.LegalName = asp.OrgName

	// Check for duplicate/resubmit request
	resubmit, err := s.checkResubmit(aspID, aspTxn)
	if err != nil {
		return nil, err
	}

	if resubmit.IsResubmit {
		log.Info("===RESUBMIT_OCCURRED===")
		dto.RequestID = resubmit.RequestID
		dto.IsReSubmit = true
		s.populateConsent(dto, asp.ConsentVariables)
		return dto, nil
	}

	// For new requests
	if resubmit.IsDuplicate && resubmit.Status >= 0 {
		return s.createErrorResponse(dto, "ESP-006", "Duplicate transaction ID", esignReq.ResponseURL)
	}

	// Validate ASP certificate
	if err := s.validateASPCertificate(signerCN, sigInfo.SerialNumber, asp, esignReq); err != nil {
		return s.createErrorResponse(dto, err.Error(), s.getErrorMessage(err.Error()), esignReq.ResponseURL)
	}

	// Check quota if enabled
	if asp.QuotaMode == 1 {
		if err := s.checkQuota(asp); err != nil {
			return s.createErrorResponse(dto, "ESP-010", "ASP quota limit reached", esignReq.ResponseURL)
		}
	}

	// Create request detail
	reqDetail := s.createRequestDetail(esignReq, req, userAgent, asp.AcmID)
	
	// Extract last 4 digits of Aadhaar if provided
	if adr := req.FormValue("adr"); adr != "" {
		reqDetail.Adr = adr
		dto.Adr = adr
	}

	// Insert request
	requestID, err := s.repo.InsertEsignRequest(reqDetail)
	if err != nil {
		return nil, err
	}

	dto.RequestID = requestID
	s.populateConsent(dto, asp.ConsentVariables)

	return dto, nil
}

// TestEsignRequestEligibility checks if request is eligible for processing
func (s *EsignService) TestEsignRequestEligibility(requestID string) (*models.EsignRequestDTO, error) {
	req, err := s.repo.GetRequestByID(requestID)
	if err != nil {
		return nil, err
	}

	// Check if request is valid
	if req.Status != -1 {
		return nil, errors.NewAuthenticationError("ESP-999", "Invalid request status")
	}

	// Check request timeout
	elapsed := time.Since(req.CreatedOn)
	if elapsed > time.Duration(s.config.RequestTimeout)*time.Minute {
		return nil, errors.NewAuthenticationError("ESP-205", "Request expired")
	}

	return req, nil
}

// SaveAspReqXML saves the ASP request XML
func (s *EsignService) SaveAspReqXML(xmlData string, requestID int64, clientIP string) error {
	return s.repo.SaveRawLog(&models.EsignRawLog{
		RequestID: requestID,
		Data:      xmlData,
		Type:      models.RawLogTypeASPRequest,
		ClientIP:  clientIP,
		CreatedOn: time.Now(),
	})
}

// SaveEsignResponse saves the esign response
func (s *EsignService) SaveEsignResponse(msg string, requestID int64, clientIP string) error {
	return s.repo.SaveRawLog(&models.EsignRawLog{
		RequestID: requestID,
		Data:      msg,
		Type:      models.RawLogTypeESPResponse,
		ClientIP:  clientIP,
		CreatedOn: time.Now(),
	})
}

// UpdateRetryAttempt updates OTP retry attempts
func (s *EsignService) UpdateRetryAttempt(requestID int64) error {
	return s.repo.UpdateOTPRetryAttempt(requestID)
}

// UpdateAuthAttempt updates authentication attempts
func (s *EsignService) UpdateAuthAttempt(requestID int64) error {
	return s.repo.UpdateAuthAttempt(requestID)
}

// UpdateTransition updates request transition status
func (s *EsignService) UpdateTransition(requestID int64, status string) error {
	return s.repo.UpdateTransition(requestID, status)
}

// UpdateKYCDetails updates KYC details and transition
func (s *EsignService) UpdateKYCDetails(requestID int64, kyc *models.EsignKycDetailDTO, status string) error {
	// Start transaction
	tx, err := s.repo.BeginTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Update KYC details
	if err := s.repo.UpdateKYCDetailsTx(tx, requestID, kyc); err != nil {
		return err
	}

	// Update transition
	if err := s.repo.UpdateTransitionTx(tx, requestID, status); err != nil {
		return err
	}

	return tx.Commit()
}

// GetRequestDetailWithKYC gets request details with KYC
func (s *EsignService) GetRequestDetailWithKYC(requestID int64) (*models.EsignRequestDTO, error) {
	return s.repo.GetRequestWithKYC(requestID)
}

// ProcessEsignRequest processes the esign request
func (s *EsignService) ProcessEsignRequest(req *models.EsignRequestDTO, kyc *models.AadhaarDetailsVO, isAborted bool, clientIP string) (string, error) {
	log := logger.GetLogger()
	
	// Prepare documents for signing
	docs := s.prepareDocuments(req.EsignRequest.Docs)
	
	// Create signing request
	signingReq := &models.SigningRequest{
		RequestID:    req.RequestID,
		AspID:        req.AspID,
		Txn:          req.EsignRequest.Txn,
		Documents:    docs,
		KYC:          kyc,
		ResponseType: req.EsignRequest.ResponseSigType,
		IsAborted:    isAborted,
	}

	// Call remote signing service
	response, err := s.remoteService.SignDocuments(signingReq)
	if err != nil {
		log.WithError(err).Error("Failed to sign documents")
		return s.GenerateSignedXMLResponse(
			req.RequestID,
			"ESP-901",
			"Signing service error",
			"0",
			req.EsignRequest.Txn,
			"",
			clientIP,
		)
	}

	// Update request status
	if err := s.repo.UpdateRequestStatus(req.RequestID, models.StatusSignCompleted); err != nil {
		log.WithError(err).Error("Failed to update request status")
	}

	return response, nil
}

// TestESPLink tests ESP service connectivity
func (s *EsignService) TestESPLink() error {
	// Test database connection
	if err := s.repo.Ping(); err != nil {
		return errors.NewSystemError("ESP-902", "Database connection failed")
	}

	// Test remote service
	if err := s.remoteService.HealthCheck(); err != nil {
		return errors.NewSystemError("ESP-903", "Remote service unavailable")
	}

	return nil
}

// GenerateSignedXMLResponse generates signed XML response
func (s *EsignService) GenerateSignedXMLResponse(requestID int64, errCode, errMsg, status, txn, resCode, clientIP string) (string, error) {
	// Create response structure
	resp := &models.EsignResponse{
		ErrCode:  errCode,
		ErrMsg:   errMsg,
		Status:   status,
		Ts:       time.Now().Format(time.RFC3339),
		Txn:      txn,
		ResCode:  resCode,
	}

	// Marshal to XML
	xmlData, err := xml.Marshal(resp)
	if err != nil {
		return "", err
	}

	// Sign the response
	signedXML, err := s.cryptoService.SignXML(string(xmlData))
	if err != nil {
		return "", err
	}

	// Save response
	if requestID > 0 {
		if err := s.SaveEsignResponse(signedXML, requestID, clientIP); err != nil {
			logger.GetLogger().WithError(err).Error("Failed to save response")
		}
	}

	return signedXML, nil
}

// Helper methods

func (s *EsignService) createErrorResponse(dto *models.EsignRequestDTO, intErrCode, errMsg, responseURL string) (*models.EsignRequestDTO, error) {
	log := logger.GetLogger()
	
	dto.IsError = true
	dto.ResponseURL = responseURL

	// Get external error code and message
	extCode := intErrCode
	extMsg := errMsg
	
	if errInfo, ok := s.errorCodes[intErrCode]; ok {
		if errInfo.ExternalCode != "" {
			extCode = errInfo.ExternalCode
		}
		if errInfo.ExternalMessage != "" {
			extMsg = errInfo.ExternalMessage
		}
	}

	log.WithFields(map[string]interface{}{
		"int_code": intErrCode,
		"ext_code": extCode,
		"message":  extMsg,
	}).Debug("Creating error response")

	// Generate signed error response
	msg, err := s.remoteService.GenerateErrorResponse(dto.RequestID, extCode, extMsg, "0", dto.EsignRequest.Txn, "", "")
	if err != nil {
		log.WithError(err).Error("Failed to generate error response")
		msg = "Error generating response"
	}

	dto.ErrorMsg = msg
	return dto, nil
}

func (s *EsignService) extractCN(subject string) string {
	parts := strings.Split(subject, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "CN=") {
			return strings.TrimPrefix(trimmed, "CN=")
		}
	}
	return ""
}

func (s *EsignService) checkResubmit(aspID, txn string) (*models.ResubmitInfo, error) {
	// Check if transaction exists
	existing, err := s.repo.GetRequestByASPAndTxn(aspID, txn)
	if err != nil {
		if err == sql.ErrNoRows {
			return &models.ResubmitInfo{}, nil
		}
		return nil, err
	}

	info := &models.ResubmitInfo{
		RequestID:   existing.RequestID,
		Status:      existing.Status,
		IsDuplicate: true,
	}

	// Check if it's a resubmit (within timeout window)
	elapsed := time.Since(existing.CreatedOn)
	if elapsed < time.Duration(s.config.RequestTimeout)*time.Minute && existing.Status == -1 {
		info.IsResubmit = true
	}

	return info, nil
}

func (s *EsignService) validateASPCertificate(signerCN, certSerial string, asp *models.ASPDetails, req *models.EsignRequest) error {
	// Validate CN
	if signerCN != asp.CertUserCN {
		return fmt.Errorf("ESP-003")
	}

	// Validate serial number
	if certSerial != asp.CertSerialNo {
		return fmt.Errorf("ESP-004")
	}

	// Validate certificate time
	now := time.Now()
	if now.Before(asp.CertValidFrom) || now.After(asp.CertValidTo) {
		return fmt.Errorf("ESP-007")
	}

	// Validate request timestamp
	if err := s.validateRequestTimestamp(req.Ts); err != nil {
		return fmt.Errorf("ESP-005")
	}

	// Validate document hashes
	if err := s.validateDocumentHashes(req.Docs, req.Ver); err != nil {
		return err
	}

	// Validate eKYC ID if provided
	if req.EkycID != "" && len(req.EkycID) != 72 {
		return fmt.Errorf("ESP-009")
	}

	return nil
}

func (s *EsignService) validateRequestTimestamp(ts string) error {
	reqTime, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return err
	}

	diff := time.Since(reqTime)
	if diff < -time.Duration(s.config.RequestTimeout)*time.Minute || 
	   diff > time.Duration(s.config.RequestTimeout)*time.Minute {
		return fmt.Errorf("timestamp out of range")
	}

	return nil
}

func (s *EsignService) validateDocumentHashes(docs *models.Docs, version string) error {
	if docs == nil || len(docs.InputHash) == 0 {
		return fmt.Errorf("ESP-008")
	}

	// Version 2.x allows only 1 document
	if version == "2.1" && len(docs.InputHash) > 1 {
		return fmt.Errorf("ESP-008")
	}

	// Version 3.x allows up to 5 documents
	if len(docs.InputHash) > 5 {
		return fmt.Errorf("ESP-008")
	}

	// Validate each hash
	for _, hash := range docs.InputHash {
		if hash.Value == "" {
			return fmt.Errorf("ESP-008")
		}
	}

	return nil
}

func (s *EsignService) checkQuota(asp *models.ASPDetails) error {
	if asp.Overdraft == 0 && asp.AvailableQuota <= 0 {
		return fmt.Errorf("quota exceeded")
	}
	return nil
}

func (s *EsignService) populateConsent(dto *models.EsignRequestDTO, consentVars string) {
	// Parse consent variables JSON
	vars := make(map[string]string)
	if err := xml.Unmarshal([]byte(consentVars), &vars); err == nil {
		dto.V1 = vars["variable1"]
		dto.V2 = vars["variable2"]
		dto.V3 = vars["variable3"]
	}
}

func (s *EsignService) createRequestDetail(req *models.EsignRequest, httpReq *http.Request, userAgent string, acmID *string) *models.EsignRequestDetail {
	clientIP := s.getClientIP(httpReq)
	
	detail := &models.EsignRequestDetail{
		AspID:           req.AspID,
		Txn:             req.Txn,
		Version:         req.Ver,
		Timestamp:       req.Ts,
		AuthMode:        req.AuthMode,
		ResponseSigType: req.ResponseSigType,
		ResponseURL:     req.ResponseURL,
		Status:          -1, // Initial status
		RequestIP:       clientIP,
		UserAgent:       userAgent,
		CreatedOn:       time.Now(),
	}

	if acmID != nil {
		detail.AcmID = acmID
	}

	// Process documents
	for _, hash := range req.Docs.InputHash {
		doc := models.EsignDocument{
			DocID:         hash.ID,
			DocInfo:       hash.DocInfo,
			HashAlgorithm: hash.HashAlgorithm,
			HashValue:     hash.Value,
		}
		detail.Documents = append(detail.Documents, doc)
	}

	return detail
}

func (s *EsignService) getClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return req.RemoteAddr
}

func (s *EsignService) prepareDocuments(docs *models.Docs) []models.Document {
	var documents []models.Document
	for _, hash := range docs.InputHash {
		doc := models.Document{
			ID:       hash.ID,
			Info:     hash.DocInfo,
			Hash:     hash.Value,
			HashAlgo: hash.HashAlgorithm,
		}
		documents = append(documents, doc)
	}
	return documents
}

func (s *EsignService) getErrorMessage(code string) string {
	if err, ok := s.errorCodes[code]; ok {
		return err.InternalMessage
	}
	return "Unknown error"
}

func (s *EsignService) generatePhotoHash(photo string) string {
	hash := sha256.Sum256([]byte(photo))
	return hex.EncodeToString(hash[:])
}

// loadErrorCodes loads error code mappings
func loadErrorCodes() map[string]*models.ErrorCode {
	// In production, load from database or config file
	return map[string]*models.ErrorCode{
		"ESP-001": {Code: "ESP-001", InternalMessage: "Invalid ASP ID", ExternalCode: "ESP-001", ExternalMessage: "Invalid ASP ID"},
		"ESP-002": {Code: "ESP-002", InternalMessage: "ASP ID is inactive", ExternalCode: "ESP-002", ExternalMessage: "ASP ID is inactive"},
		"ESP-003": {Code: "ESP-003", InternalMessage: "Certificate CN not matched", ExternalCode: "ESP-003", ExternalMessage: "Certificate validation failed"},
		"ESP-004": {Code: "ESP-004", InternalMessage: "Certificate serial not matched", ExternalCode: "ESP-004", ExternalMessage: "Certificate validation failed"},
		"ESP-005": {Code: "ESP-005", InternalMessage: "Invalid request timestamp", ExternalCode: "ESP-005", ExternalMessage: "Request timestamp invalid"},
		"ESP-006": {Code: "ESP-006", InternalMessage: "Duplicate transaction ID", ExternalCode: "ESP-006", ExternalMessage: "Duplicate transaction ID"},
		"ESP-007": {Code: "ESP-007", InternalMessage: "Certificate time not valid", ExternalCode: "ESP-007", ExternalMessage: "Certificate expired"},
		"ESP-008": {Code: "ESP-008", InternalMessage: "Invalid document hash", ExternalCode: "ESP-008", ExternalMessage: "Invalid document information"},
		"ESP-009": {Code: "ESP-009", InternalMessage: "Invalid eKYC token", ExternalCode: "ESP-009", ExternalMessage: "Invalid eKYC token"},
		"ESP-010": {Code: "ESP-010", InternalMessage: "ASP quota limit reached", ExternalCode: "ESP-010", ExternalMessage: "Service limit reached"},
		"ESP-101": {Code: "ESP-101", InternalMessage: "XML size exceeds limit", ExternalCode: "ESP-101", ExternalMessage: "Request too large"},
		"ESP-102": {Code: "ESP-102", InternalMessage: "XSD validation failed", ExternalCode: "ESP-102", ExternalMessage: "Invalid request format"},
		"ESP-103": {Code: "ESP-103", InternalMessage: "XML signature verification failed", ExternalCode: "ESP-103", ExternalMessage: "Signature verification failed"},
		"ESP-999": {Code: "ESP-999", InternalMessage: "Unknown error", ExternalCode: "ESP-999", ExternalMessage: "Unknown error"},
	}
}