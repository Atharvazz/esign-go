package errors

import (
	"fmt"
)

// Error types
type (
	// ValidationError represents a validation error
	ValidationError struct {
		Message string
		Field   string
		Value   interface{}
	}

	// AuthenticationError represents an authentication error
	AuthenticationError struct {
		Message string
		Code    string
	}

	// AuthorizationError represents an authorization error
	AuthorizationError struct {
		Message string
		Code    string
	}

	// NotFoundError represents a not found error
	NotFoundError struct {
		Message string
		Entity  string
		ID      string
	}

	// ConflictError represents a conflict error
	ConflictError struct {
		Message string
		Entity  string
		Field   string
	}

	// RateLimitError represents a rate limit error
	RateLimitError struct {
		Message string
		Limit   int
		Reset   int64
	}

	// ServiceError represents a service error
	ServiceError struct {
		Message string
		Service string
		Code    string
	}

	// DatabaseError represents a database error
	DatabaseError struct {
		Message   string
		Operation string
		Err       error
	}

	// UIDAIError represents a UIDAI service error
	UIDAIError struct {
		Message      string
		ResponseCode string
		ErrorCode    string
	}

	// UIDAIAuthenticationError represents a UIDAI authentication failure
	UIDAIAuthenticationError struct {
		Message      string
		ResponseCode string
		ErrorCode    string
	}

	// MaxAttemptsError represents maximum attempts exceeded error
	MaxAttemptsError struct {
		Message  string
		Attempts int
		MaxLimit int
	}

	// SignatureError represents a signature error
	SignatureError struct {
		Message string
		Type    string
	}

	// XMLError represents an XML parsing/validation error
	XMLError struct {
		Message string
		Line    int
		Column  int
	}

	// KYCAuthenticationError represents a KYC authentication failure
	KYCAuthenticationError struct {
		Message      string
		ResponseCode string
	}

	// KYCServiceError represents a KYC service error
	KYCServiceError struct {
		Message string
		Err     error
	}

	// ProcessingError represents a processing error
	ProcessingError struct {
		Message string
		Code    string
	}

	// SystemError represents a system error
	SystemError struct {
		Message string
		Code    string
	}
)

// Error implementations

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
	}
	return e.Message
}

func (e *AuthenticationError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("authentication error [%s]: %s", e.Code, e.Message)
	}
	return e.Message
}

func (e *AuthorizationError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("authorization error [%s]: %s", e.Code, e.Message)
	}
	return e.Message
}

func (e *NotFoundError) Error() string {
	if e.Entity != "" && e.ID != "" {
		return fmt.Sprintf("%s with ID '%s' not found", e.Entity, e.ID)
	}
	return e.Message
}

func (e *ConflictError) Error() string {
	if e.Entity != "" && e.Field != "" {
		return fmt.Sprintf("conflict on %s.%s: %s", e.Entity, e.Field, e.Message)
	}
	return e.Message
}

func (e *RateLimitError) Error() string {
	return e.Message
}

func (e *ServiceError) Error() string {
	if e.Service != "" {
		return fmt.Sprintf("%s service error: %s", e.Service, e.Message)
	}
	return e.Message
}

func (e *DatabaseError) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("database error during %s: %s", e.Operation, e.Message)
	}
	return e.Message
}

func (e *UIDAIError) Error() string {
	if e.ResponseCode != "" {
		return fmt.Sprintf("UIDAI error [%s]: %s", e.ResponseCode, e.Message)
	}
	return e.Message
}

func (e *UIDAIAuthenticationError) Error() string {
	if e.ResponseCode != "" {
		return fmt.Sprintf("UIDAI authentication failed [%s]: %s", e.ResponseCode, e.Message)
	}
	return e.Message
}

func (e *MaxAttemptsError) Error() string {
	if e.MaxLimit > 0 {
		return fmt.Sprintf("%s (attempts: %d/%d)", e.Message, e.Attempts, e.MaxLimit)
	}
	return e.Message
}

func (e *SignatureError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("signature error [%s]: %s", e.Type, e.Message)
	}
	return e.Message
}

func (e *XMLError) Error() string {
	if e.Line > 0 && e.Column > 0 {
		return fmt.Sprintf("XML error at line %d, column %d: %s", e.Line, e.Column, e.Message)
	}
	return e.Message
}

func (e *KYCAuthenticationError) Error() string {
	if e.ResponseCode != "" {
		return fmt.Sprintf("KYC authentication failed [%s]: %s", e.ResponseCode, e.Message)
	}
	return e.Message
}

func (e *KYCServiceError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("KYC service error: %s (cause: %v)", e.Message, e.Err)
	}
	return e.Message
}

func (e *ProcessingError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("processing error [%s]: %s", e.Code, e.Message)
	}
	return e.Message
}

func (e *SystemError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("system error [%s]: %s", e.Code, e.Message)
	}
	return e.Message
}

// Constructor functions

// NewValidationError creates a new validation error
func NewValidationError(format string, args ...interface{}) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewValidationFieldError creates a new validation error for a specific field
func NewValidationFieldError(field string, format string, args ...interface{}) *ValidationError {
	return &ValidationError{
		Message: fmt.Sprintf(format, args...),
		Field:   field,
	}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(format string, args ...interface{}) *AuthenticationError {
	return &AuthenticationError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewAuthorizationError creates a new authorization error
func NewAuthorizationError(format string, args ...interface{}) *AuthorizationError {
	return &AuthorizationError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(format string, args ...interface{}) *NotFoundError {
	return &NotFoundError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewConflictError creates a new conflict error
func NewConflictError(format string, args ...interface{}) *ConflictError {
	return &ConflictError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(format string, args ...interface{}) *RateLimitError {
	return &RateLimitError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewServiceError creates a new service error
func NewServiceError(service string, format string, args ...interface{}) *ServiceError {
	return &ServiceError{
		Service: service,
		Message: fmt.Sprintf(format, args...),
	}
}

// NewDatabaseError creates a new database error
func NewDatabaseError(operation string, err error) *DatabaseError {
	return &DatabaseError{
		Operation: operation,
		Message:   err.Error(),
		Err:       err,
	}
}

// NewUIDAIError creates a new UIDAI error
func NewUIDAIError(format string, args ...interface{}) *UIDAIError {
	return &UIDAIError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewUIDAIAuthenticationError creates a new UIDAI authentication error
func NewUIDAIAuthenticationError(message string) *UIDAIAuthenticationError {
	return &UIDAIAuthenticationError{
		Message: message,
	}
}

// NewMaxAttemptsError creates a new max attempts error
func NewMaxAttemptsError(format string, args ...interface{}) *MaxAttemptsError {
	return &MaxAttemptsError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewSignatureError creates a new signature error
func NewSignatureError(format string, args ...interface{}) *SignatureError {
	return &SignatureError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewXMLError creates a new XML error
func NewXMLError(format string, args ...interface{}) *XMLError {
	return &XMLError{
		Message: fmt.Sprintf(format, args...),
	}
}

// NewKYCAuthenticationError creates a new KYC authentication error
func NewKYCAuthenticationError(message string) *KYCAuthenticationError {
	return &KYCAuthenticationError{
		Message: message,
	}
}

// NewKYCServiceError creates a new KYC service error
func NewKYCServiceError(message string, err error) *KYCServiceError {
	return &KYCServiceError{
		Message: message,
		Err:     err,
	}
}

// NewProcessingError creates a new processing error
func NewProcessingError(code, message string) *ProcessingError {
	return &ProcessingError{
		Code:    code,
		Message: message,
	}
}

// NewSystemError creates a new system error
func NewSystemError(code, message string) *SystemError {
	return &SystemError{
		Code:    code,
		Message: message,
	}
}

// Helper functions

// IsValidationError checks if error is a validation error
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}

// IsAuthenticationError checks if error is an authentication error
func IsAuthenticationError(err error) bool {
	_, ok := err.(*AuthenticationError)
	return ok
}

// IsAuthorizationError checks if error is an authorization error
func IsAuthorizationError(err error) bool {
	_, ok := err.(*AuthorizationError)
	return ok
}

// IsNotFoundError checks if error is a not found error
func IsNotFoundError(err error) bool {
	_, ok := err.(*NotFoundError)
	return ok
}

// IsConflictError checks if error is a conflict error
func IsConflictError(err error) bool {
	_, ok := err.(*ConflictError)
	return ok
}

// IsRateLimitError checks if error is a rate limit error
func IsRateLimitError(err error) bool {
	_, ok := err.(*RateLimitError)
	return ok
}

// IsServiceError checks if error is a service error
func IsServiceError(err error) bool {
	_, ok := err.(*ServiceError)
	return ok
}

// IsDatabaseError checks if error is a database error
func IsDatabaseError(err error) bool {
	_, ok := err.(*DatabaseError)
	return ok
}

// IsUIDAIError checks if error is a UIDAI error
func IsUIDAIError(err error) bool {
	_, ok := err.(*UIDAIError)
	return ok
}

// IsMaxAttemptsError checks if error is a max attempts error
func IsMaxAttemptsError(err error) bool {
	_, ok := err.(*MaxAttemptsError)
	return ok
}

// Additional error types to match Java implementation

// ASPAuthenticationException represents ASP authentication errors
type ASPAuthenticationException struct {
	Code    string
	Message string
	Cause   error
}

func (e *ASPAuthenticationException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ASP authentication error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("ASP authentication error %s: %s", e.Code, e.Message)
}

// NewASPAuthenticationException creates a new ASP authentication exception
func NewASPAuthenticationException(code, message string) *ASPAuthenticationException {
	return &ASPAuthenticationException{
		Code:    code,
		Message: message,
	}
}

// ASPSignatureVerificationException represents ASP signature verification errors
type ASPSignatureVerificationException struct {
	Code    string
	Message string
	Cause   error
}

func (e *ASPSignatureVerificationException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("ASP signature verification error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("ASP signature verification error %s: %s", e.Code, e.Message)
}

// NewASPSignatureVerificationException creates a new ASP signature verification exception
func NewASPSignatureVerificationException(code, message string, cause error) *ASPSignatureVerificationException {
	return &ASPSignatureVerificationException{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// ESPDatabaseException represents database errors
type ESPDatabaseException struct {
	Code    string
	Message string
	Cause   error
}

func (e *ESPDatabaseException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Database error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("Database error %s: %s", e.Code, e.Message)
}

// NewESPDatabaseException creates a new database exception
func NewESPDatabaseException(message string, cause error) *ESPDatabaseException {
	return &ESPDatabaseException{
		Code:    "ESP_DB_ERROR",
		Message: message,
		Cause:   cause,
	}
}

// ESignXmlResponseException represents XML response errors
type ESignXmlResponseException struct {
	Code    string
	Message string
	Cause   error
}

func (e *ESignXmlResponseException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("XML response error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("XML response error %s: %s", e.Code, e.Message)
}

// NewESignXmlResponseException creates a new XML response exception
func NewESignXmlResponseException(message string, cause error) *ESignXmlResponseException {
	return &ESignXmlResponseException{
		Code:    "ESP_XML_ERROR",
		Message: message,
		Cause:   cause,
	}
}

// XMLValidationException represents XML validation errors
type XMLValidationException struct {
	Code    string
	Message string
	Cause   error
}

func (e *XMLValidationException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("XML validation error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("XML validation error %s: %s", e.Code, e.Message)
}

// NewXMLValidationException creates a new XML validation exception
func NewXMLValidationException(message string, cause error) *XMLValidationException {
	return &XMLValidationException{
		Code:    "ESP_XML_VALIDATION",
		Message: message,
		Cause:   cause,
	}
}

// NSDLESPServiceException represents NSDL ESP service errors
type NSDLESPServiceException struct {
	Code    string
	Message string
	Cause   error
}

func (e *NSDLESPServiceException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("NSDL ESP service error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("NSDL ESP service error %s: %s", e.Code, e.Message)
}

// NewNSDLESPServiceException creates a new NSDL ESP service exception
func NewNSDLESPServiceException(message string, cause error) *NSDLESPServiceException {
	return &NSDLESPServiceException{
		Code:    "ESP_SERVICE_ERROR",
		Message: message,
		Cause:   cause,
	}
}

// EnvelopAuthValidationException represents envelope authentication validation errors
type EnvelopAuthValidationException struct {
	Code    string
	Message string
	Cause   error
}

func (e *EnvelopAuthValidationException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Envelope auth validation error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("Envelope auth validation error %s: %s", e.Code, e.Message)
}

// NewEnvelopAuthValidationException creates a new envelope auth validation exception
func NewEnvelopAuthValidationException(message string) *EnvelopAuthValidationException {
	return &EnvelopAuthValidationException{
		Code:    "ENV_AUTH_ERROR",
		Message: message,
	}
}

// AuditFailureException represents audit failure errors
type AuditFailureException struct {
	Code    string
	Message string
	Cause   error
}

func (e *AuditFailureException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("Audit failure %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("Audit failure %s: %s", e.Code, e.Message)
}

// NewAuditFailureException creates a new audit failure exception
func NewAuditFailureException(message string, cause error) *AuditFailureException {
	return &AuditFailureException{
		Code:    "AUDIT_FAILURE",
		Message: message,
		Cause:   cause,
	}
}

// KUAServiceException represents KUA service errors
type KUAServiceException struct {
	Code    string
	Message string
	Cause   error
}

func (e *KUAServiceException) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("KUA service error %s: %s - %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("KUA service error %s: %s", e.Code, e.Message)
}

// NewKUAServiceException creates a new KUA service exception
func NewKUAServiceException(message string, cause error) *KUAServiceException {
	return &KUAServiceException{
		Code:    "KUA_SERVICE_ERROR",
		Message: message,
		Cause:   cause,
	}
}

// UIDAINonSkipableAuthenticationException represents non-skippable UIDAI errors
type UIDAINonSkipableAuthenticationException struct {
	Code    string
	Message string
}

func (e *UIDAINonSkipableAuthenticationException) Error() string {
	return fmt.Sprintf("UIDAI non-skippable error %s: %s", e.Code, e.Message)
}

// NewUIDAINonSkipableAuthenticationException creates a new non-skippable UIDAI error
func NewUIDAINonSkipableAuthenticationException(code, message string) *UIDAINonSkipableAuthenticationException {
	return &UIDAINonSkipableAuthenticationException{
		Code:    code,
		Message: message,
	}
}