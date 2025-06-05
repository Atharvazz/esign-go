package controller

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ESIGN_FINAL/esign-go/internal/service"
	"esign-go/internal/service"

	"github.com/esign-go/internal/middleware"
	"github.com/esign-go/internal/models"
	"github.com/esign-go/pkg/errors"
	"github.com/esign-go/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthenticateController handles authentication endpoints
type AuthenticateController struct {
	esignService    service.IEsignService
	kycService      service.IKYCService
	templateService service.ITemplateService
	config          *models.Config
}

// NewAuthenticateController creates a new authenticate controller
func NewAuthenticateController(
	esignService service.IEsignService,
	kycService service.IKYCService,
	templateService service.ITemplateService,
	config *models.Config,
) *AuthenticateController {
	return &AuthenticateController{
		esignService:    esignService,
		kycService:      kycService,
		templateService: templateService,
		config:          config,
	}
}

// RegisterRoutes registers all authentication routes
func (ac *AuthenticateController) RegisterRoutes(router *gin.RouterGroup) {
	auth := router.Group("/authenticate")
	{
		// Apply rate limiting middleware
		auth.POST("/esign-doc",
			middleware.RateLimiter("esign-doc", ac.config.RateLimit.EsignDoc),
			ac.EsignDoc)
		auth.GET("/auth-ra", ac.AuthRA)
		auth.POST("/otp", ac.GenerateOTP)
		auth.POST("/otpAction", ac.VerifyOTP)
		auth.POST("/es", ac.ProcessEsign)
		auth.GET("/es-ra", ac.EsignRedirect)
		auth.POST("/postRequestdata", ac.BiometricAuth)
		auth.POST("/esignCancel", ac.CancelEsign)
		auth.GET("/sigError", ac.SignatureError)
	}
}

// EsignDoc handles the main esign document request
func (ac *AuthenticateController) EsignDoc(c *gin.Context) {
	log := logger.GetLogger()

	// Track request
	uniqueReqID := ac.trackRequest(c)
	log.WithField("request_id", uniqueReqID).Info("req_start_authAndEkyc")

	// Extract parameters
	msg := c.PostForm("msg")
	cvDocID := c.PostForm("cv_docId")
	adr := c.PostForm("adr") // Last 4 digits of Aadhaar

	// Log request if enabled
	if ac.config.Debug.LogRequests {
		log.WithField("msg_length", len(msg)).Debug("Received esign request")
	}

	// Pre-validate and prepare request
	esignReq, err := ac.esignService.PreValidateAndPrepare(msg, c.Request, "2.1", c.Request.UserAgent())

	if err != nil {
		log.WithError(err).Error("Validation failed")

		// Handle specific error types
		switch e := err.(type) {
		case *errors.ValidationError:
			ac.handleValidationError(c, e, esignReq)
			return
		case *errors.AuthenticationError:
			ac.handleAuthError(c, e, esignReq)
			return
		default:
			ac.handleGenericError(c, err, esignReq)
			return
		}
	}

	// Request is valid, prepare for authentication
	if !esignReq.IsError {
		// Set flash attributes for redirect
		session := ac.getSession(c)
		session.Values["msg1"] = esignReq.LegalName
		session.Values["sid"] = esignReq.EsignRequest.SignerID
		session.Values["msg3"] = esignReq.EsignRequest.Txn
		session.Values["msg4"] = esignReq.EsignRequest.Ts
		session.Values["ln"] = esignReq.LegalName
		session.Values["v1"] = esignReq.V1
		session.Values["v2"] = esignReq.V2
		session.Values["v3"] = esignReq.V3
		session.Values["rid"] = esignReq.RequestID
		session.Values["authMod"] = esignReq.EsignRequest.AuthMode
		session.Values["build"] = ac.config.Build
		session.Values["adr"] = adr

		// Generate custom view if template ID provided
		if cvDocID != "" {
			cvOutput, err := ac.generateCustomView(esignReq, cvDocID, c)
			if err != nil {
				log.WithError(err).Error("Failed to generate custom view")
			} else {
				session.Values["cv_output"] = cvOutput
			}
		}

		// Save session
		if err := session.Save(c.Request, c.Writer); err != nil {
			log.WithError(err).Error("Failed to save session")
		}

		// Save request XML if not a resubmit
		if msg != "" && esignReq.RequestID > 0 && !esignReq.IsReSubmit {
			clientIP := ac.getClientIP(c)
			if err := ac.esignService.SaveAspReqXML(msg, esignReq.RequestID, clientIP); err != nil {
				log.WithError(err).Error("Failed to save ASP request XML")
			}
		}

		// Redirect to authentication page
		tid := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", esignReq.RequestID)))
		c.Redirect(http.StatusFound, fmt.Sprintf("/authenticate/auth-ra?tid=%s", tid))

	} else {
		// Error response
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": esignReq.ErrorMsg,
			"u":   esignReq.ResponseURL,
		})
	}

	log.WithField("request_id", uniqueReqID).Info("req_end_authAndEkyc")
}

// AuthRA handles the authentication redirect
func (ac *AuthenticateController) AuthRA(c *gin.Context) {
	log := logger.GetLogger()

	// Decode transaction ID
	tid := c.Query("tid")
	if tid == "" {
		c.HTML(http.StatusBadRequest, "authFail.html", gin.H{
			"msg": "Invalid request",
		})
		return
	}

	decodedTID, err := base64.StdEncoding.DecodeString(tid)
	if err != nil {
		c.HTML(http.StatusBadRequest, "authFail.html", gin.H{
			"msg": "Invalid request ID",
		})
		return
	}

	log.WithField("tid", string(decodedTID)).Info("req_start_authRa")

	// Get session data
	session := ac.getSession(c)
	authMode := session.Values["authMod"].(string)

	// Determine view based on auth mode
	var view string
	templateData := gin.H{
		"bioEnv": ac.config.BiometricEnv,
	}

	// Copy session values to template data
	for k, v := range session.Values {
		templateData[k] = v
	}

	switch authMode {
	case "1":
		view = "auth.html"
	case "2":
		view = "auth_biometric.html"
	case "3":
		view = "auth_biometric_iris.html"
	default:
		view = "authFail.html"
		templateData["msg"] = "Invalid authentication mode"
	}

	c.HTML(http.StatusOK, view, templateData)
	log.WithField("tid", string(decodedTID)).Info("req_end_authRa")
}

// GenerateOTP handles OTP generation requests
func (ac *AuthenticateController) GenerateOTP(c *gin.Context) {
	log := logger.GetLogger()

	var otpReq models.OTPRequest
	if err := c.ShouldBindJSON(&otpReq); err != nil {
		c.JSON(http.StatusBadRequest, models.OTPResponse{
			Status: "0",
			Msg:    "Invalid request format",
		})
		return
	}

	log.WithField("request_id", otpReq.RequestID).Info("req_otpRequest_start")

	// Validate request eligibility
	esignReq, err := ac.esignService.TestEsignRequestEligibility(otpReq.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status:     "0",
			Form:       ac.getForm("", otpReq.RequestID),
			Msg:        "Invalid esign request!",
			RetryCount: -1,
		})
		return
	}

	// Check retry attempts
	retryCount := ac.config.AuthAttempts - esignReq.OtpRetryAttempts
	if retryCount <= 0 {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status:     "2",
			Form:       ac.getForm("", otpReq.RequestID),
			Msg:        "You have exceeded Send/Resend OTP Limit. Please try again!",
			RetryCount: 0,
		})
		return
	}

	// Validate last 4 digits if provided
	if esignReq.Adr != "" {
		if err := ac.validateLast4Digits(esignReq.Adr, otpReq.Aadhaar); err != nil {
			c.JSON(http.StatusOK, models.OTPResponse{
				Status:     "0",
				Form:       ac.getForm("", otpReq.RequestID),
				Msg:        "Invalid Aadhaar entered!",
				RetryCount: retryCount,
			})
			return
		}
	}

	// Update retry attempt
	if err := ac.esignService.UpdateRetryAttempt(esignReq.RequestID); err != nil {
		log.WithError(err).Error("Failed to update retry attempt")
	}

	// Generate OTP
	otpRes, err := ac.kycService.GenerateOTP(
		otpReq.Aadhaar,
		esignReq.RequestID,
		c.Request,
		esignReq.Txn,
		esignReq.AspID,
		esignReq.OtpRetryAttempts,
	)

	if err != nil {
		log.WithError(err).Error("Failed to generate OTP")

		// Handle specific error types
		var msg string
		switch err.(type) {
		case *errors.KYCAuthenticationError:
			msg = "Unable to send OTP. Please try again!"
		case *errors.KYCServiceError:
			msg = "Error in generating OTP request!"
		case *errors.UIDAIAuthenticationError:
			msg = err.Error()
		default:
			msg = "Unknown error. Please try after sometime!"
		}

		c.JSON(http.StatusOK, models.OTPResponse{
			Status:     "0",
			Form:       ac.getForm("", otpReq.RequestID),
			Msg:        msg + fmt.Sprintf(" %d attempt(s) remaining.", retryCount),
			RetryCount: retryCount,
		})
		return
	}

	// Update transition status
	if err := ac.esignService.UpdateTransition(esignReq.RequestID, models.StatusOTPSent); err != nil {
		log.WithError(err).Error("Failed to update transition")
	}

	// Success response
	c.JSON(http.StatusOK, models.OTPResponse{
		Status:     "1",
		Msg:        "OTP sent successfully",
		OtpTxn:     otpRes.OtpTxn,
		RetryCount: retryCount,
	})

	log.WithField("request_id", otpReq.RequestID).Info("req_otpRequest_end")
}

// VerifyOTP handles OTP verification
func (ac *AuthenticateController) VerifyOTP(c *gin.Context) {
	log := logger.GetLogger()

	var otpReq models.OTPVerifyRequest
	if err := c.ShouldBindJSON(&otpReq); err != nil {
		c.JSON(http.StatusBadRequest, models.OTPResponse{
			Status: "FAIL",
			Msg:    "Invalid request format",
		})
		return
	}

	log.WithField("request_id", otpReq.RequestID).Info("req_start_otpAction")

	// Test ESP link
	if err := ac.esignService.TestESPLink(); err != nil {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getForm("", otpReq.RequestID),
			Msg:    "eSign service down. Please try after sometime",
		})
		return
	}

	// Validate request eligibility
	esignReq, err := ac.esignService.TestEsignRequestEligibility(otpReq.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getForm("", otpReq.RequestID),
			Msg:    "Invalid esign request or request expired!",
		})
		return
	}

	// Update authentication attempts
	if err := ac.esignService.UpdateAuthAttempt(esignReq.RequestID); err != nil {
		log.WithError(err).Error("Failed to update auth attempt")
	}

	retryCount := ac.config.AuthAttempts - (esignReq.AuthAttempts + 1)

	// Verify OTP
	kyc, err := ac.kycService.VerifyOTP(
		otpReq.OtpTxn,
		otpReq.OTP,
		otpReq.Aadhaar,
		esignReq.RequestID,
		c.Request,
		esignReq.Txn,
		esignReq.AspID,
	)

	if err != nil {
		log.WithError(err).Error("OTP verification failed")

		var msg string
		if retryCount <= 0 {
			msg = "Maximum attempts exceeded"
		} else {
			msg = fmt.Sprintf("Invalid OTP! %d attempt(s) remaining.", retryCount)
		}

		c.JSON(http.StatusOK, models.OTPResponse{
			Status:     "FAIL",
			Form:       ac.getForm("", otpReq.RequestID),
			Msg:        msg,
			RetryCount: retryCount,
		})
		return
	}

	// Update KYC details
	kycDetails := ac.populateKYC(kyc)
	if err := ac.esignService.UpdateKYCDetails(esignReq.RequestID, kycDetails, models.StatusOTPVerified); err != nil {
		log.WithError(err).Error("Failed to update KYC details")
	}

	// Process esign request
	msg, err := ac.processEsignInternal(esignReq.RequestID, c.Request, kycDetails)
	if err != nil {
		log.WithError(err).Error("Failed to process esign")
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getForm("", otpReq.RequestID),
			Msg:    "Failed to process esign request",
		})
		return
	}

	// Generate form for auto-submission
	form := ac.getEsignForm(esignReq.ResponseURL, msg)

	c.JSON(http.StatusOK, models.OTPResponse{
		Status:     "OK",
		Form:       form,
		RetryCount: retryCount - 1,
	})

	log.WithField("request_id", otpReq.RequestID).Info("req_end_otpAction")
}

// BiometricAuth handles biometric authentication
func (ac *AuthenticateController) BiometricAuth(c *gin.Context) {
	log := logger.GetLogger()

	var bioReq models.BiometricRequest
	if err := c.ShouldBindJSON(&bioReq); err != nil {
		c.JSON(http.StatusBadRequest, models.BiometricResponse{
			Success: false,
			Msg:     "Invalid request format",
		})
		return
	}

	switch bioReq.Request {
	case "getRequestData":
		ac.getBiometricRequestData(c, false)
	case "getRequestDataForIris":
		ac.getBiometricRequestData(c, true)
	case "sendBiometric":
		ac.processBiometric(c, &bioReq)
	case "abortRequest":
		ac.abortBiometricRequest(c, &bioReq)
	default:
		c.JSON(http.StatusBadRequest, models.BiometricResponse{
			Success: false,
			Msg:     "Invalid request type",
		})
	}
}

// Helper methods

func (ac *AuthenticateController) trackRequest(c *gin.Context) string {
	reqID := uuid.New().String()
	c.Set("RequestID", reqID)
	return reqID
}

func (ac *AuthenticateController) getClientIP(c *gin.Context) string {
	// Try to get real IP from headers
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return c.ClientIP()
}

func (ac *AuthenticateController) getSession(c *gin.Context) *models.Session {
	// In production, use a proper session store
	// This is a simplified version
	return &models.Session{
		Values: make(map[string]interface{}),
	}
}

func (ac *AuthenticateController) validateLast4Digits(stored, input string) error {
	if len(input) < 12 {
		return fmt.Errorf("invalid aadhaar length")
	}
	last4 := input[len(input)-4:]
	if last4 != stored {
		return fmt.Errorf("aadhaar mismatch")
	}
	return nil
}

func (ac *AuthenticateController) getForm(rid, kid string) string {
	var sb strings.Builder
	sb.WriteString(`<form action='/authenticate/es' id='esid' method='post'>`)
	if rid != "" {
		sb.WriteString(fmt.Sprintf(`<input type='hidden' id='rid' name='rid' value='%s'/>`, rid))
	}
	sb.WriteString(fmt.Sprintf(`<input type='hidden' id='kid' name='kid' value='%s'/>`, kid))
	sb.WriteString(`<input type='submit' value='submit'></form>`)
	return sb.String()
}

func (ac *AuthenticateController) getEsignForm(resURL, msg string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<form action='%s' id='esid' method='post' enctype='multipart/form-data'>`, resURL))
	sb.WriteString(fmt.Sprintf(`<input type='hidden' id='msg' name='msg' value='%s'/>`, msg))
	sb.WriteString(`<input type='submit' value='submit'></form>`)
	return sb.String()
}

func (ac *AuthenticateController) handleValidationError(c *gin.Context, err *errors.ValidationError, req *models.EsignRequestDTO) {
	log := logger.GetLogger()
	log.WithError(err).Error("Validation error")

	if req != nil && req.ResponseURL != "" {
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": err.Message,
			"u":   req.ResponseURL,
		})
	} else {
		c.HTML(http.StatusBadRequest, "authFail.html", gin.H{
			"msg": err.Message,
		})
	}
}

func (ac *AuthenticateController) handleAuthError(c *gin.Context, err *errors.AuthenticationError, req *models.EsignRequestDTO) {
	log := logger.GetLogger()
	log.WithError(err).Error("Authentication error")

	if req != nil && req.ResponseURL != "" {
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": err.Message,
			"u":   req.ResponseURL,
		})
	} else {
		c.HTML(http.StatusUnauthorized, "authFail.html", gin.H{
			"msg": err.Message,
		})
	}
}

func (ac *AuthenticateController) handleGenericError(c *gin.Context, err error, req *models.EsignRequestDTO) {
	log := logger.GetLogger()
	log.WithError(err).Error("Generic error")

	msg := "An error occurred processing your request"
	if req != nil && req.ResponseURL != "" {
		c.HTML(http.StatusOK, "rd.html", gin.H{
			"msg": msg,
			"u":   req.ResponseURL,
		})
	} else {
		c.HTML(http.StatusInternalServerError, "authFail.html", gin.H{
			"msg": msg,
		})
	}
}

func (ac *AuthenticateController) generateCustomView(req *models.EsignRequestDTO, cvDocID string, c *gin.Context) (string, error) {
	params := map[string]string{
		"rid":         fmt.Sprintf("%d", req.RequestID),
		"contextPath": c.Request.URL.Path,
		"msg1":        req.LegalName,
		"msg3":        req.EsignRequest.Txn,
		"msg4":        req.EsignRequest.Ts,
		"v1":          req.V1,
		"v2":          req.V2,
		"v3":          req.V3,
		"ln":          req.LegalName,
		"bioEnv":      ac.config.BiometricEnv,
		"adr":         req.Adr,
	}

	return ac.templateService.RenderCustomView(req.AspID, cvDocID, params, req.EsignRequest.AuthMode)
}

func (ac *AuthenticateController) populateKYC(kyc *models.AadhaarDetailsVO) *models.EsignKycDetailDTO {
	kycDetail := &models.EsignKycDetailDTO{
		ResidentName: kyc.Name,
		State:        kyc.State,
		Gender:       kyc.Gender,
		Dob:          kyc.Dob,
		ResponseCode: kyc.ResponseCode,
		RequestTime:  time.Now(),
		ResponseTime: time.Now(),
	}

	if kyc.Pincode != "" {
		kycDetail.PostalCode = kyc.Pincode
	}

	if kyc.Address != nil {
		kycDetail.Address1 = kyc.Address.House
		kycDetail.Address2 = kyc.Address.Street
		kycDetail.Address3 = kyc.Address.Landmark
		kycDetail.Address4 = kyc.Address.Locality
		kycDetail.Locality = kyc.Address.VTC
	}

	if kyc.Photo != "" {
		// Generate photo hash
		kycDetail.PhotoHash = ac.generatePhotoHash(kyc.Photo)
	}

	// Set token
	if kyc.Token != "" {
		kycDetail.Token = kyc.Token
	}

	// Set last 4 digits of Aadhaar
	if kyc.AadhaarNo != "" && len(kyc.AadhaarNo) >= 4 {
		kycDetail.Uid = kyc.AadhaarNo[len(kyc.AadhaarNo)-4:]
	}

	return kycDetail
}

func (ac *AuthenticateController) generatePhotoHash(photo string) string {
	// Implementation for photo hash generation
	// This is a placeholder - implement actual hash logic
	return "photo_hash_placeholder"
}

func (ac *AuthenticateController) processEsignInternal(requestID int64, req *http.Request, kyc *models.EsignKycDetailDTO) (string, error) {
	// Get request details
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(requestID)
	if err != nil {
		return "", err
	}

	// Convert KYC DTO to VO for processing
	kycVO := ac.convertKYCDTOToVO(kyc)

	// Process esign request
	clientIP := ac.getClientIP(&gin.Context{Request: req})
	msg, err := ac.esignService.ProcessEsignRequest(esignReq, kycVO, false, clientIP)
	if err != nil {
		return "", err
	}

	// Save response
	if err := ac.esignService.SaveEsignResponse(msg, requestID, clientIP); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to save esign response")
	}

	return msg, nil
}

func (ac *AuthenticateController) convertKYCDTOToVO(dto *models.EsignKycDetailDTO) *models.AadhaarDetailsVO {
	// Convert DTO back to VO for processing
	// This is a simplified version
	return &models.AadhaarDetailsVO{
		Name:         dto.ResidentName,
		Gender:       dto.Gender,
		Dob:          dto.Dob,
		State:        dto.State,
		Pincode:      dto.PostalCode,
		ResponseCode: dto.ResponseCode,
		Token:        dto.Token,
		AadhaarNo:    dto.Uid, // Last 4 digits only
	}
}

// Additional endpoint implementations...

func (ac *AuthenticateController) ProcessEsign(c *gin.Context) {
	// Implementation for /es endpoint
	rid := c.PostForm("rid")
	kid := c.PostForm("kid")

	if kid == "" {
		c.HTML(http.StatusBadRequest, "esignFailed.html", gin.H{
			"msg": "Invalid request",
		})
		return
	}

	// Process the esign request
	// Implementation details...
}

func (ac *AuthenticateController) EsignRedirect(c *gin.Context) {
	// Implementation for /es-ra endpoint
	view := c.Query("view")
	if view == "" {
		view = "rd"
	}
	c.HTML(http.StatusOK, view+".html", gin.H{})
}

func (ac *AuthenticateController) CancelEsign(c *gin.Context) {
	// Implementation for esign cancellation
	kid := c.PostForm("kid")
	cancelReason := c.PostForm("cr")

	// Process cancellation
	// Implementation details...
}

func (ac *AuthenticateController) SignatureError(c *gin.Context) {
	c.HTML(http.StatusOK, "authFail.html", gin.H{
		"msg": "Digital signature error!",
	})
}

func (ac *AuthenticateController) getBiometricRequestData(c *gin.Context, isIris bool) {
	authMode := "bio"
	wadh := ac.generateWADH(isIris)

	response := models.BiometricResponse{
		Success:     true,
		AuthMode:    authMode,
		Wadh:        wadh,
		ConsentText: ac.config.ConsentText,
		ResponseURL: ac.config.BiometricResponseURL,
	}

	c.JSON(http.StatusOK, response)
}

func (ac *AuthenticateController) processBiometric(c *gin.Context, req *models.BiometricRequest) {
	// Implementation for biometric processing
	// Similar to OTP flow but with biometric data
}

func (ac *AuthenticateController) abortBiometricRequest(c *gin.Context, req *models.BiometricRequest) {
	// Implementation for aborting biometric request
}

func (ac *AuthenticateController) generateWADH(isIris bool) string {
	// Generate WADH based on biometric type
	// Implementation details...
	return "wadh_placeholder"
}
