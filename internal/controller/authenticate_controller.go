package controller

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/esign-go/internal/service"

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
	sessionService  service.ISessionService
	config          *models.Config
}

// NewAuthenticateController creates a new authenticate controller
func NewAuthenticateController(
	esignService service.IEsignService,
	kycService service.IKYCService,
	templateService service.ITemplateService,
	sessionService service.ISessionService,
	config *models.Config,
) *AuthenticateController {
	return &AuthenticateController{
		esignService:    esignService,
		kycService:      kycService,
		templateService: templateService,
		sessionService:  sessionService,
		config:          config,
	}
}

// RegisterRoutes registers all authentication routes
func (ac *AuthenticateController) RegisterRoutes(router *gin.RouterGroup) {
	auth := router.Group("/authenticate")
	{
		// Apply rate limiting middleware with fallback
		auth.POST("/esign-doc",
			middleware.RateLimiterWithFallback("esign-doc", ac.config.RateLimit.EsignDoc, ac.RateLimiterFallbackForEsignDoc),
			ac.EsignDoc)
		auth.GET("/esign-doc", ac.EsignDocGet)
		auth.GET("/auth-ra", ac.AuthRA)
		auth.POST("/otp", ac.GenerateOTP)
		auth.POST("/otpAction", ac.VerifyOTP)
		auth.POST("/es", ac.ProcessEsign)
		auth.GET("/es-ra", ac.EsignRedirect)
		auth.POST("/postRequestdata", ac.BiometricAuth)
		auth.POST("/esignCancel", ac.CancelEsign)
		auth.GET("/sigError", ac.SignatureError)
		// Check status endpoints with rate limiting
		auth.POST("/check-status",
			middleware.RateLimiterWithFallback("check-status", ac.config.RateLimit.CheckStatus, ac.RateLimiterFallbackForCheckStatus),
			ac.CheckStatus)
		auth.POST("/check-status-api",
			middleware.RateLimiterWithFallback("check-status", ac.config.RateLimit.CheckStatus, ac.RateLimiterFallbackForCheckStatus),
			ac.CheckStatusAPI)
		// Offline KYC endpoints
		auth.POST("/okycOtp", ac.OkycOtp)
		auth.POST("/okycOtpVerifyAction", ac.OkycOtpVerifyAction)
		auth.GET("/okycOtpView", ac.OkycOtpView)
		auth.POST("/esignCancelRedirect", ac.CancelEsignRedirect)
		// Cancel redirect endpoints
		auth.GET("/es-can-ra", ac.EsignCancelRedirectView)
		// Version 3 endpoints
		auth.POST("/esignCancelVer3", ac.CancelEsignVer3)
		// Face recognition endpoint
		auth.POST("/fcr", ac.FaceRecognition)
	}
}

// EsignRedirect handles the redirect after esign processing
func (ac *AuthenticateController) EsignRedirect(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("Inside EsignRedirect")

	// Get view from query parameters
	view := c.Query("view")
	if view == "" {
		view = "esign-success.html"
	}

	// Render the view
	c.HTML(http.StatusOK, view, gin.H{
		"title": "eSign Redirect",
	})
}

// CancelEsign handles esign cancellation
func (ac *AuthenticateController) CancelEsign(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("Inside CancelEsign")

	kid := c.PostForm("kid")
	cancelReason := c.PostForm("cr")

	if kid == "" {
		c.HTML(http.StatusBadRequest, "authExpired.html", gin.H{
			"error": "Invalid request ID",
		})
		return
	}

	requestID, err := strconv.ParseInt(kid, 10, 64)
	if err != nil {
		c.HTML(http.StatusBadRequest, "authExpired.html", gin.H{
			"error": "Invalid request ID format",
		})
		return
	}

	// Get request details
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(requestID)
	if err != nil || esignReq == nil {
		c.HTML(http.StatusBadRequest, "authExpired.html", gin.H{
			"error": "Request not found",
		})
		return
	}

	// Check if request can be cancelled
	if esignReq.Status != models.StatusNumInitiated {
		c.HTML(http.StatusBadRequest, "authExpired.html", gin.H{
			"error": "Request cannot be cancelled",
		})
		return
	}

	// Update request with cancel reason
	esignReq.CancelReason = cancelReason
	ipAddress := ac.getClientIP(c)

	// Generate cancel response
	responseXML, err := ac.esignService.GenerateSignedXMLResponse(
		requestID,
		"ESP-201",
		"Request cancelled by user",
		models.StatusCancelled,
		esignReq.Txn,
		"201",
		ipAddress,
	)

	if err != nil {
		log.WithError(err).Error("Failed to generate cancel response")
		c.HTML(http.StatusInternalServerError, "authFail.html", gin.H{
			"error": "Failed to process cancellation",
		})
		return
	}

	// Send response to ASP
	if esignReq.ResponseURL != "" {
		go ac.esignService.SendResponseToASP(esignReq.ResponseURL, responseXML)
	}

	c.HTML(http.StatusOK, "esign-cancelled.html", gin.H{
		"message": "eSign request cancelled successfully",
	})
}

// EsignDocGet handles GET requests to esign-doc (illegal operation)
func (ac *AuthenticateController) EsignDocGet(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("Inside EsignDocGet - illegal operation")

	// Return auth fail view with error message
	c.HTML(http.StatusBadRequest, "authFail.html", gin.H{
		"msg": "Illegal operation performed!",
	})
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
		// Prepare session data
		sessionData := &service.SessionData{
			RequestID:     esignReq.RequestID,
			AspID:         esignReq.AspID,
			LegalName:     esignReq.LegalName,
			SignerID:      esignReq.EsignRequest.SignerID,
			TransactionID: esignReq.EsignRequest.Txn,
			Timestamp:     esignReq.EsignRequest.Ts,
			AuthMode:      esignReq.EsignRequest.AuthMode,
			V1:            esignReq.V1,
			V2:            esignReq.V2,
			V3:            esignReq.V3,
			Build:         ac.config.Build,
			Adr:           adr,
			CreatedAt:     time.Now(),
		}

		// Generate custom view if template ID provided
		if cvDocID != "" {
			cvOutput, err := ac.generateCustomView(esignReq, cvDocID, c)
			if err != nil {
				log.WithError(err).Error("Failed to generate custom view")
			} else {
				sessionData.CustomViewOutput = cvOutput
			}
		}

		// Store session data
		if err := ac.sessionService.StoreSessionData(c, sessionData); err != nil {
			log.WithError(err).Error("Failed to save session data")
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
	sessionData, err := ac.sessionService.GetSessionData(c)
	if err != nil || sessionData == nil {
		c.HTML(http.StatusBadRequest, "authFail.html", gin.H{
			"msg": "Session expired or invalid",
		})
		return
	}

	authMode := sessionData.AuthMode

	// Determine view based on auth mode
	var view string
	templateData := gin.H{
		"bioEnv":   ac.config.BiometricEnv,
		"msg1":     sessionData.LegalName,
		"sid":      sessionData.SignerID,
		"msg3":     sessionData.TransactionID,
		"msg4":     sessionData.Timestamp,
		"ln":       sessionData.LegalName,
		"v1":       sessionData.V1,
		"v2":       sessionData.V2,
		"v3":       sessionData.V3,
		"rid":      sessionData.RequestID,
		"authMod":  sessionData.AuthMode,
		"build":    sessionData.Build,
		"adr":      sessionData.Adr,
		"cv_output": sessionData.CustomViewOutput,
		"filler1":  sessionData.Filler1,
		"filler2":  sessionData.Filler2,
		"filler3":  sessionData.Filler3,
		"filler4":  sessionData.Filler4,
		"filler5":  sessionData.Filler5,
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
	// Extract ASP ID and Transaction ID from XML request
	msg := c.PostForm("msg")
	if msg == "" {
		reqID := uuid.New().String()
		c.Set("RequestID", reqID)
		return reqID
	}
	
	// Parse ASP ID from XML
	aspStart := strings.Index(msg, "aspId=")
	if aspStart == -1 {
		return uuid.New().String()
	}
	aspStart += 7
	aspEnd := strings.Index(msg[aspStart:], "\"")
	if aspEnd == -1 {
		return uuid.New().String()
	}
	aspID := msg[aspStart : aspStart+aspEnd]
	
	// Parse Transaction ID from XML
	txnStart := strings.Index(msg, "txn=")
	if txnStart == -1 {
		return aspID + ":" + fmt.Sprintf("%d", time.Now().Unix())
	}
	txnStart += 5
	txnEnd := strings.Index(msg[txnStart:], "\"")
	if txnEnd == -1 {
		return aspID + ":" + fmt.Sprintf("%d", time.Now().Unix())
	}
	txnID := msg[txnStart : txnStart+txnEnd]
	
	// Return format: {ASP_ID}_{TXN_ID}:{timestamp}
	reqID := fmt.Sprintf("%s_%s:%d", aspID, txnID, time.Now().UnixMilli())
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

func (ac *AuthenticateController) getForm(rid string, kid int64) string {
	var sb strings.Builder
	sb.WriteString(`<form action='/authenticate/es' id='esid' method='post'>`)
	if rid != "" {
		sb.WriteString(fmt.Sprintf(`<input type='hidden' id='rid' name='rid' value='%s'/>`, rid))
	}
	sb.WriteString(fmt.Sprintf(`<input type='hidden' id='kid' name='kid' value='%d'/>`, kid))
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
	log := logger.GetLogger()
	
	if photo == "" {
		return ""
	}

	// Decode base64 photo
	photoData, err := base64.StdEncoding.DecodeString(photo)
	if err != nil {
		log.WithError(err).Error("Failed to decode photo base64")
		return ""
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(photoData)
	
	// Convert to uppercase hex string
	return strings.ToUpper(hex.EncodeToString(hash[:]))
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

// esignRest is an internal method for REST-based esign processing
func (ac *AuthenticateController) esignRest(kid string, req *http.Request, kyc *models.EsignKycDetailDTO) (string, error) {
	log := logger.GetLogger()
	log.WithField("kid", kid).Debug("Inside esignRest")
	log.Info("req_start_esignRest_" + kid)

	requestID, err := strconv.ParseInt(kid, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid request ID: %w", err)
	}

	// Get request details from database
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(requestID)
	if err != nil {
		return "", fmt.Errorf("failed to get request details: %w", err)
	}

	// Validate request status and transition
	if esignReq == nil || esignReq.Status != models.StatusNumInitiated {
		return "", fmt.Errorf("invalid request state")
	}

	// Check if request is in valid transition state
	validTransitions := []string{
		models.StatusOTPVerified,
		models.StatusBiometricFingerprintVerified,
		models.StatusBiometricIrisVerified,
		models.StatusOTPSent,
		models.StatusRequestAuthorized,
	}

	isValidTransition := false
	for _, transition := range validTransitions {
		if esignReq.RequestTransition == transition {
			isValidTransition = true
			break
		}
	}

	if !isValidTransition {
		return "", fmt.Errorf("invalid request transition state")
	}

	// Set error code to kid (as done in Java)
	esignReq.ErrorCode = kid

	// Get client IP
	// Get client IP from request
	ipAddress := req.Header.Get("X-Real-IP")
	if ipAddress == "" {
		ipAddress = req.Header.Get("X-Forwarded-For")
	}
	if ipAddress == "" {
		ipAddress = req.RemoteAddr
	}

	// Process esign with KYC
	responseXML, err := ac.processEsignInternal(requestID, req, kyc)
	if err != nil {
		log.WithError(err).Error("Failed to process esign")
		
		// Generate error response
		errorResp, _ := ac.esignService.GenerateSignedXMLResponse(
			requestID,
			"ESP-999",
			err.Error(),
			models.StatusFailed,
			esignReq.Txn,
			"999",
			ipAddress,
		)
		return errorResp, err
	}

	log.Info("req_end_esignRest_" + kid)
	return responseXML, nil
}

func (ac *AuthenticateController) ProcessEsign(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside esign")

	rid := c.PostForm("rid")
	kid := c.PostForm("kid")

	// Default values
	u := "esignFailed"
	view := "rd.html"
	var requestID int64
	var kyc *models.AadhaarDetailsVO
	var msg string
	err := "Internal Error or Illegal Operation Performed!!"

	// Validate input
	if kid == "" {
		msg = err
		c.HTML(http.StatusBadRequest, u, gin.H{
			"msg": msg,
		})
		return
	}

	// Parse request ID
	requestID, parseErr := strconv.ParseInt(kid, 10, 64)
	if parseErr != nil {
		log.WithError(parseErr).Error("Failed to parse request ID")
		msg = err
		c.HTML(http.StatusBadRequest, u, gin.H{
			"msg": msg,
		})
		return
	}

	log.WithFields(map[string]interface{}{
		"es_rid": rid,
		"es_kid": kid,
	}).Debug("Processing esign")

	// Get request details from database
	esignReq, dbErr := ac.esignService.GetRequestDetailWithKYC(requestID)
	if dbErr != nil {
		log.WithError(dbErr).Error("Failed to get request details")
		msg = err
		c.HTML(http.StatusInternalServerError, u, gin.H{
			"msg": msg,
		})
		return
	}

	// Validate request status and transition
	if esignReq != nil && esignReq.Status == models.StatusNumInitiated &&
		(esignReq.RequestTransition == models.StatusOTPVerified ||
			esignReq.RequestTransition == models.StatusBioVerified ||
			esignReq.RequestTransition == "BIOMETRIC_IRIS_VERIFIED" ||
			esignReq.RequestTransition == models.StatusOTPSent ||
			esignReq.RequestTransition == models.StatusAuthorized) {

		// Get KYC details
		if esignReq.KYC != nil {
			kyc = &models.AadhaarDetailsVO{
				Name:         esignReq.KYC.ResidentName,
				Gender:       esignReq.KYC.Gender,
				Dob:          esignReq.KYC.Dob,
				State:        esignReq.KYC.State,
				Pincode:      esignReq.KYC.PostalCode,
				ResponseCode: esignReq.KYC.ResponseCode,
				Token:        esignReq.KYC.Token,
				AadhaarNo:    esignReq.KYC.Uid, // Last 4 digits
			}
		}

		// Update error code and auth attempts
		retryCount := esignReq.AuthAttempts
		esignReq.ErrorCode = rid
		esignReq.AuthAttempts = retryCount

		// Get client IP
		clientIP := ac.getClientIP(c)

		// Process esign request
		msg, processErr := ac.esignService.ProcessEsignRequest(esignReq, kyc, false, clientIP)
		if processErr != nil {
			log.WithError(processErr).Error("Failed to process esign request")
			c.HTML(http.StatusInternalServerError, u, gin.H{
				"msg": "Failed to process request",
			})
			return
		}

		// Get response URL
		u = esignReq.ResponseURL
		log.WithField("responseURL", u).Debug("Response URL")

		// Save esign response
		if esignReq.RequestID > 0 {
			if saveErr := ac.esignService.SaveEsignResponse(msg, esignReq.RequestID, clientIP); saveErr != nil {
				log.WithError(saveErr).Error("Failed to save esign response")
			}
		}

		// Redirect with response
		if msg == "" {
			msg = "Success"
		}
		c.HTML(http.StatusOK, view, gin.H{
			"msg": msg,
			"u":   u,
		})

	} else {
		// Invalid request status
		if esignReq != nil {
			log.WithFields(map[string]interface{}{
				"ES_STATUS":            esignReq.Status,
				"ES_TRANSITION_STATUS": esignReq.RequestTransition,
			}).Debug("Invalid esign status")
		}
		c.HTML(http.StatusBadRequest, u, gin.H{
			"msg": err,
		})
	}
}

// Duplicate methods and broken code removed - see earlier implementations

// Duplicate CancelEsign method removed - see line 106

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
	log := logger.GetLogger()
	log.Info("Processing biometric authentication")

	// Test ESP link
	if err := ac.esignService.TestESPLink(); err != nil {
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     "eSign service down. Please try after sometime",
		})
		return
	}

	// Validate request eligibility
	esignReq, err := ac.esignService.TestEsignRequestEligibility(req.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     "Invalid esign request or request expired!",
		})
		return
	}

	// Check retry attempts
	retryCount := ac.config.AuthAttempts - (esignReq.AuthAttempts + 1)
	if retryCount <= 0 {
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     "Maximum attempts exceeded",
		})
		return
	}

	// Update authentication attempts
	if err := ac.esignService.UpdateAuthAttempt(esignReq.RequestID); err != nil {
		log.WithError(err).Error("Failed to update auth attempt")
	}

	// Parse biometric data
	bioData := &models.BiometricData{
		Type:   ac.determineBiometricType(esignReq.EsignRequest.AuthMode),
		Data:   req.BiometricXML,
		Device: "Biometric Device",
		Wadh:   ac.generateWADH(esignReq.EsignRequest.AuthMode == "3"),
	}

	// Authenticate using biometric
	kyc, err := ac.kycService.AuthenticateBiometric(
		bioData,
		esignReq.RequestID,
		c.Request,
		esignReq.Txn,
		esignReq.AspID,
	)

	if err != nil {
		log.WithError(err).Error("Biometric authentication failed")
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     fmt.Sprintf("Invalid biometric! %d attempt(s) remaining.", retryCount),
		})
		return
	}

	// Update transition status
	bioStatus := models.StatusBioVerified
	if esignReq.EsignRequest.AuthMode == "3" {
		bioStatus = "BIOMETRIC_IRIS_VERIFIED"
	}
	
	if err := ac.esignService.UpdateTransition(esignReq.RequestID, bioStatus); err != nil {
		log.WithError(err).Error("Failed to update transition")
	}

	// Update KYC details
	kycDetails := ac.populateKYC(kyc)
	if err := ac.esignService.UpdateKYCDetails(esignReq.RequestID, kycDetails, bioStatus); err != nil {
		log.WithError(err).Error("Failed to update KYC details")
	}

	// Process esign request
	msg, err := ac.processEsignInternal(esignReq.RequestID, c.Request, kycDetails)
	if err != nil {
		log.WithError(err).Error("Failed to process esign")
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     "Failed to process esign request",
		})
		return
	}

	// Generate form for auto-submission
	form := ac.getEsignForm(esignReq.ResponseURL, msg)

	c.JSON(http.StatusOK, models.BiometricResponse{
		Success: true,
		Msg:     form,
	})
}

func (ac *AuthenticateController) abortBiometricRequest(c *gin.Context, req *models.BiometricRequest) {
	log := logger.GetLogger()
	log.Info("Aborting biometric request")

	// Get request details
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(req.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.BiometricResponse{
			Success: false,
			Msg:     "Invalid request",
		})
		return
	}

	// Update status to cancelled
	esignReq.CancelReason = "User aborted biometric authentication"

	// Process cancellation
	clientIP := ac.getClientIP(c)
	kyc := ac.convertKYCDTOToVO(&models.EsignKycDetailDTO{}) // Empty KYC for cancellation

	msg, err := ac.esignService.ProcessEsignRequest(esignReq, kyc, true, clientIP)
	if err != nil {
		log.WithError(err).Error("Failed to process cancellation")
	}

	if msg == "" {
		// Generate error response
		msg, _ = ac.esignService.GenerateSignedXMLResponse(
			req.RequestID,
			"ESP-999",
			"Authentication cancelled by user",
			"0",
			esignReq.Txn,
			uuid.New().String(),
			clientIP,
		)
	}

	// Save response
	if err := ac.esignService.SaveEsignResponse(msg, req.RequestID, clientIP); err != nil {
		log.WithError(err).Error("Failed to save esign response")
	}

	form := ac.getEsignForm(esignReq.ResponseURL, msg)
	c.JSON(http.StatusOK, models.BiometricResponse{
		Success: true,
		Msg:     form,
	})
}

func (ac *AuthenticateController) determineBiometricType(authMode string) string {
	switch authMode {
	case "2":
		return "FMR" // Fingerprint
	case "3":
		return "IIR" // Iris
	default:
		return "FMR"
	}
}

func (ac *AuthenticateController) generateWADH(isIris bool) string {
	// Generate WADH (Witness Aadhaar Data Hash)
	// Format: SHA256(ver+ra+rc+lr+de+pfr)
	var rawWADH string
	if isIris {
		// For IRIS: version + "I" + flags
		rawWADH = "2.5" + "I" + "Y" + "N" + "N" + "N"
	} else {
		// For Fingerprint: version + "F" + flags  
		rawWADH = "2.5" + "F" + "Y" + "N" + "N" + "N"
	}
	
	// Calculate SHA256 hash
	hash := sha256.Sum256([]byte(rawWADH))
	return hex.EncodeToString(hash[:])
}

// CheckStatus handles check-status request with XML response
func (ac *AuthenticateController) CheckStatus(c *gin.Context) {
	log := logger.GetLogger()
	log.Debug("inside checkStatus")

	msg := c.PostForm("msg")
	
	// Check if ASP is authorized for check status
	aspID := ac.extractAspIDFromXML(msg)
	if !ac.isAuthorizedForCheckStatus(aspID) {
		c.String(http.StatusUnauthorized, "Unauthorized For Check Status")
		return
	}

	// Validate and process check status
	response, err := ac.esignService.ValidateAndProcessCheckStatus(msg, c.Request)
	if err != nil {
		log.WithError(err).Error("Check status processing failed")
		c.String(http.StatusInternalServerError, "Internal Server Error")
		return
	}

	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, response)
}

// CheckStatusAPI handles check-status-api request with JSON response
func (ac *AuthenticateController) CheckStatusAPI(c *gin.Context) {
	log := logger.GetLogger()
	
	var model models.EsignStatusModel
	if err := c.ShouldBindJSON(&model); err != nil {
		c.JSON(http.StatusBadRequest, models.EsignStatusVO{
			Msg: "Invalid request format",
			Sts: models.StatusNumFailed,
		})
		return
	}

	log.WithFields(map[string]interface{}{
		"aspId": model.AspID,
		"txn":   model.Txn,
	}).Debug("Check status API request")

	// Check if ASP is authorized
	if !ac.isAuthorizedForCheckStatus(model.AspID) {
		c.JSON(http.StatusUnauthorized, models.EsignStatusVO{
			Msg: "UNAUTHORIZED",
			Sts: models.StatusNumFailed,
		})
		return
	}

	// Get transaction status
	status, err := ac.esignService.CheckTransactionStatus(model.AspID, model.Txn)
	if err != nil {
		c.JSON(http.StatusOK, models.EsignStatusVO{
			Msg: "transaction not found!",
			Sts: models.StatusNumFailed,
		})
		return
	}

	c.JSON(http.StatusOK, status)
}

// OkycOtp handles offline KYC OTP generation
func (ac *AuthenticateController) OkycOtp(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside okycOtp")

	var okycReq models.OkycOtpRequest
	if err := c.ShouldBind(&okycReq); err != nil {
		c.JSON(http.StatusBadRequest, models.OKYCOTPResponse{
			Status: "0",
			Msg:    "Invalid request format",
		})
		return
	}

	// Test request eligibility
	esignReq, err := ac.esignService.TestEsignRequestEligibility(okycReq.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status: "0",
			Form:   ac.getForm("", okycReq.RequestID),
			Msg:    "Invalid esign request!",
		})
		return
	}

	// Update retry attempt
	if err := ac.esignService.UpdateRetryAttempt(esignReq.RequestID); err != nil {
		log.WithError(err).Error("Failed to update retry attempt")
	}

	retryCount := ac.config.AuthAttempts - esignReq.OtpRetryAttempts

	if retryCount <= 0 {
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status:     "1",
			Form:       ac.getForm("", okycReq.RequestID),
			Msg:        "You have exceeded OTP Limit. Please try again!",
			RetryCount: 0,
		})
		return
	}

	// Process offline KYC OTP request
	clientIP := ac.getClientIP(c)
	otpRes, err := ac.kycService.ProcessOkycOTPRequest(&okycReq, clientIP)
	if err != nil {
		log.WithError(err).Error("Failed to process OKYC OTP request")
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status:     "0",
			Form:       ac.getForm("", okycReq.RequestID),
			Msg:        "Error in generating OTP request!",
			RetryCount: retryCount,
		})
		return
	}

	// Update transition
	if err := ac.esignService.UpdateTransition(esignReq.RequestID, models.StatusOTPSent); err != nil {
		log.WithError(err).Error("Failed to update transition")
	}

	c.JSON(http.StatusOK, models.OKYCOTPResponse{
		Status:     "1",
		Msg:        "OTP sent on registered mobile.",
		OtpTxn:     otpRes.OtpTxn,
		RetryCount: retryCount,
	})
}

// OkycOtpVerifyAction handles offline KYC OTP verification
func (ac *AuthenticateController) OkycOtpVerifyAction(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside okycOtpVerifyAction")

	var verifyReq models.OkycVerificationModel
	if err := c.ShouldBindJSON(&verifyReq); err != nil {
		c.JSON(http.StatusBadRequest, models.OkycVerificationResponse{
			Status: "FAIL",
			Msg:    "Invalid request format",
		})
		return
	}

	// Test ESP link
	if err := ac.esignService.TestESPLink(); err != nil {
		c.JSON(http.StatusOK, models.OkycVerificationResponse{
			Status: "FAIL",
			Form:   ac.getForm("", verifyReq.RequestID),
			Msg:    "eSign service down. Please try after sometime",
		})
		return
	}

	// Test request eligibility
	esignReq, err := ac.esignService.TestEsignRequestEligibility(verifyReq.RequestID)
	if err != nil {
		c.JSON(http.StatusOK, models.OkycVerificationResponse{
			Status: "FAIL",
			Form:   ac.getForm("", verifyReq.RequestID),
			Msg:    "Invalid esign request or request expired!",
		})
		return
	}

	// Update authentication attempts
	if err := ac.esignService.UpdateAuthAttempt(esignReq.RequestID); err != nil {
		log.WithError(err).Error("Failed to update auth attempt")
	}

	retryCount := ac.config.AuthAttempts - (esignReq.AuthAttempts + 1)
	if retryCount <= 0 {
		c.JSON(http.StatusOK, models.OkycVerificationResponse{
			Status: "FAIL",
			Form:   ac.getForm("", verifyReq.RequestID),
			Msg:    "Maximum attempts exceeded",
		})
		return
	}

	// Verify offline KYC OTP
	clientIP := ac.getClientIP(c)
	resp, err := ac.kycService.VerifyOkycOTP(&verifyReq, clientIP)
	if err != nil {
		log.WithError(err).Error("Failed to verify offline KYC OTP")
		c.JSON(http.StatusOK, models.OkycVerificationResponse{
			Status: "FAIL",
			Form:   ac.getForm("", verifyReq.RequestID),
			Msg:    fmt.Sprintf("Verification failed. %d attempt(s) remaining.", retryCount),
		})
		return
	}

	if resp.Status == "OK" {
		// Update transition status
		if err := ac.esignService.UpdateTransition(esignReq.RequestID, models.StatusOTPVerified); err != nil {
			log.WithError(err).Error("Failed to update transition")
		}

		// Perform offline KYC extraction
		kyc, err := ac.kycService.PerformOfflineKYC("", verifyReq.ShareCode, verifyReq.RequestID)
		if err != nil {
			log.WithError(err).Error("Failed to perform offline KYC")
			c.JSON(http.StatusOK, models.OkycVerificationResponse{
				Status: "FAIL",
				Form:   ac.getForm("", verifyReq.RequestID),
				Msg:    "Failed to extract KYC details",
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
			c.JSON(http.StatusOK, models.OkycVerificationResponse{
				Status: "FAIL",
				Form:   ac.getForm("", verifyReq.RequestID),
				Msg:    "Failed to process esign request",
			})
			return
		}

		// Generate form for auto-submission
		form := ac.getEsignForm(esignReq.ResponseURL, msg)
		c.JSON(http.StatusOK, models.OkycVerificationResponse{
			Status: "OK",
			Msg:    "Verification successful",
			Form:   form,
		})
	} else {
		c.JSON(http.StatusOK, resp)
	}
}

// EsignCancelRedirectView handles the cancel redirect view
func (ac *AuthenticateController) EsignCancelRedirectView(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("Inside EsignCancelRedirectView")

	// Get view from model attribute
	view := c.Query("view")
	if view == "" {
		view = "esign-cancel.html"
	}

	// Render the view
	c.HTML(http.StatusOK, view, gin.H{
		"title": "eSign Cancel",
	})
}

// CancelEsignRedirect handles esign cancellation with redirect
func (ac *AuthenticateController) CancelEsignRedirect(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside esignCancelAndRedirect")

	kid := c.PostForm("kid")
	cancelReason := c.PostForm("cr")

	if kid == "" {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getFailForm("/authenticate/esign-doc"),
		})
		return
	}

	requestID, err := strconv.ParseInt(kid, 10, 64)
	if err != nil {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getFailForm("/authenticate/esign-doc"),
		})
		return
	}

	// Get request details
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(requestID)
	if err != nil {
		c.JSON(http.StatusOK, models.OTPResponse{
			Status: "FAIL",
			Form:   ac.getFailForm("/authenticate/esign-doc"),
		})
		return
	}

	// Set cancel reason
	esignReq.CancelReason = cancelReason

	// Process cancellation
	clientIP := ac.getClientIP(c)
	kyc := ac.convertKYCDTOToVO(&models.EsignKycDetailDTO{}) // Empty KYC for cancellation
	
	msg, err := ac.esignService.ProcessEsignRequest(esignReq, kyc, true, clientIP)
	if err != nil {
		log.WithError(err).Error("Failed to process esign cancellation")
	}

	if msg == "" {
		// Generate error response
		resCode := uuid.New().String()
		msg, _ = ac.esignService.GenerateSignedXMLResponse(
			requestID,
			"ESP-999",
			"Unknown Error.",
			"0",
			esignReq.Txn,
			resCode,
			clientIP,
		)
	}

	// Save response
	if err := ac.esignService.SaveEsignResponse(msg, requestID, clientIP); err != nil {
		log.WithError(err).Error("Failed to save esign response")
	}

	form := ac.getEsignForm(esignReq.ResponseURL, msg)
	c.JSON(http.StatusOK, models.OTPResponse{
		Status: "OK",
		Form:   form,
	})
}

// Helper methods for check status

func (ac *AuthenticateController) extractAspIDFromXML(xml string) string {
	start := strings.Index(xml, "aspId=")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(xml[start:], "\"")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

func (ac *AuthenticateController) isAuthorizedForCheckStatus(aspID string) bool {
	// Check against configured ASP list
	for _, authorizedASP := range ac.config.CheckStatusASPs {
		if authorizedASP == aspID {
			return true
		}
	}
	return false
}

func (ac *AuthenticateController) getFailForm(url string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<form action='%s' id='esid' method='get' enctype='multipart/form-data'>`, url))
	sb.WriteString(`<input type='submit' value='submit'></form>`)
	return sb.String()
}

// Rate limiter fallback methods

// RateLimiterFallbackForEsignDoc handles rate limit exceeded for esign-doc endpoint
func (ac *AuthenticateController) RateLimiterFallbackForEsignDoc(c *gin.Context) {
	log := logger.GetLogger()
	log.WithField("endpoint", "esign-doc").Warn("Rate limit exceeded")

	// Get message from request
	msg := c.PostForm("msg")
	
	// Try to extract response URL from XML
	responseURL := ac.extractResponseURLFromXML(msg)
	if responseURL == "" {
		responseURL = "/authenticate/esign-doc"
	}

	// Generate error response
	errorMsg, err := ac.esignService.GenerateSignedXMLResponse(
		0, // No request ID yet
		"ESP-429",
		"Too many requests. Please try again later.",
		"0",
		"",
		"",
		ac.getClientIP(c),
	)

	if err != nil {
		log.WithError(err).Error("Failed to generate rate limit error response")
		c.HTML(http.StatusTooManyRequests, "authFail.html", gin.H{
			"msg": "Too many requests. Please try again later.",
		})
		return
	}

	// Return rate limit error response
	c.HTML(http.StatusOK, "rd.html", gin.H{
		"msg": errorMsg,
		"u":   responseURL,
	})
}

// RateLimiterFallbackForCheckStatus handles rate limit exceeded for check-status endpoint
func (ac *AuthenticateController) RateLimiterFallbackForCheckStatus(c *gin.Context) {
	log := logger.GetLogger()
	log.WithField("endpoint", "check-status").Warn("Rate limit exceeded")

	// Generate error response for check status
	errorResp, err := ac.esignService.GenerateSignedXMLResponse(
		0,
		"ESP-429",
		"Too many requests. Please try again later.",
		"0",
		"",
		"",
		ac.getClientIP(c),
	)

	if err != nil {
		log.WithError(err).Error("Failed to generate rate limit error response")
		c.String(http.StatusTooManyRequests, "Too many requests")
		return
	}

	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusTooManyRequests, errorResp)
}

// Helper method to extract response URL from XML
func (ac *AuthenticateController) extractResponseURLFromXML(xml string) string {
	start := strings.Index(xml, "responseUrl=")
	if start == -1 {
		return ""
	}
	start += 13 // length of 'responseUrl="'
	end := strings.Index(xml[start:], "\"")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}

// OkycOtpView handles GET request for offline KYC OTP view
func (ac *AuthenticateController) OkycOtpView(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside okycOtpView")
	
	c.HTML(http.StatusOK, "auth_okyc.html", gin.H{})
}

// CancelEsignVer3 handles esign cancellation version 3
func (ac *AuthenticateController) CancelEsignVer3(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside esignCancelVer3")

	kid := c.PostForm("kid")
	cancelReason := c.PostForm("cr")

	// Default view
	view := "authExpired.html"
	u := "esign-failed.html"
	var kyc *models.AadhaarDetailsVO

	log.WithFields(map[string]interface{}{
		"KID": kid,
		"CR":  cancelReason,
	}).Info("Cancel request")

	// Parse request ID
	requestID, err := strconv.ParseInt(kid, 10, 64)
	if err != nil {
		log.WithError(err).Error("Failed to parse request ID")
		c.HTML(http.StatusBadRequest, view, gin.H{
			"msg": "Internal Error !!",
		})
		return
	}

	// Get request details
	esignReq, err := ac.esignService.GetRequestDetailWithKYC(requestID)
	if err != nil {
		log.WithError(err).Error("Failed to get request details")
		c.HTML(http.StatusInternalServerError, view, gin.H{
			"msg": "Internal Error !!",
		})
		return
	}

	if esignReq != nil && kid != "" {
		// Set cancel reason
		esignReq.CancelReason = cancelReason

		// Get KYC if available
		if esignReq.KYC != nil {
			kyc = ac.convertKYCDTOToVO(esignReq.KYC)
		}

		// Get client IP
		clientIP := ac.getClientIP(c)

		// Process cancellation
		msg, err := ac.esignService.ProcessEsignRequest(esignReq, kyc, true, clientIP)
		if err != nil {
			log.WithError(err).Error("Failed to process esign cancellation")
		}

		// Save response
		if esignReq.RequestID > 0 {
			if saveErr := ac.esignService.SaveEsignResponse(msg, esignReq.RequestID, clientIP); saveErr != nil {
				log.WithError(saveErr).Error("Failed to save esign response")
			}
		}

		resURL := esignReq.ResponseURL
		log.WithField("responseURL", resURL).Debug("Response URL")

		// Return response
		view = "rd.html"
		c.HTML(http.StatusOK, view, gin.H{
			"obj": esignReq.KycID,
			"msg": msg,
			"u":   resURL,
		})
	} else {
		c.HTML(http.StatusBadRequest, u, gin.H{
			"msg": "Internal Error !!",
		})
	}
}

// FaceRecognition handles face recognition requests
func (ac *AuthenticateController) FaceRecognition(c *gin.Context) {
	log := logger.GetLogger()
	log.Info("inside fcr")

	// Parse multipart form
	err := c.Request.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		c.JSON(http.StatusBadRequest, models.OKYCOTPResponse{
			Status: "0",
			Msg:    "Failed to parse form",
		})
		return
	}

	// Get video file
	videoFile, videoHeader, err := c.Request.FormFile("vf")
	if err != nil {
		c.JSON(http.StatusBadRequest, models.OKYCOTPResponse{
			Status: "0",
			Msg:    "Video file is required",
		})
		return
	}
	defer videoFile.Close()

	// Read video file
	videoData, err := io.ReadAll(videoFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.OKYCOTPResponse{
			Status: "0",
			Msg:    "Failed to read video file",
		})
		return
	}

	// Get transaction ID
	transactionID := c.PostForm("transactionId")
	rid := transactionID

	log.WithField("rid", rid).Debug("Processing face recognition")

	// Prepare face recognition request
	fcrReq := &models.FaceRecognitionRequest{
		TransactionID:    transactionID,
		VideoFileName:    videoHeader.Filename,
		VideoData:        videoData,
		VideoContentType: videoHeader.Header.Get("Content-Type"),
	}

	// Get client IP
	clientIP := ac.getClientIP(c)

	// Process face recognition
	result, err := ac.kycService.ProcessFaceRecognition(fcrReq, clientIP)
	if err != nil {
		log.WithError(err).Error("Face recognition processing failed")
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status: "0",
			Msg:    "Face Match Failed",
		})
		return
	}

	// Generate form
	requestID, _ := strconv.ParseInt(rid, 10, 64)
	frm := ac.getForm(rid, requestID)

	// Return response based on result
	if result.Success {
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status: "1",
			Form:   frm,
			Msg:    "Photo Match Successful",
		})
	} else {
		c.JSON(http.StatusOK, models.OKYCOTPResponse{
			Status: "0",
			Form:   frm,
			Msg:    "Face Match Failed",
		})
	}
}
