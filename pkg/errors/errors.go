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