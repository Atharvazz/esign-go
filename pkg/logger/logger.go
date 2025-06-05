package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	log  *logrus.Logger
	once sync.Once
)

// Init initializes the logger
func Init() {
	once.Do(func() {
		log = logrus.New()
		
		// Set log level from environment
		level := os.Getenv("LOG_LEVEL")
		if level == "" {
			level = "info"
		}
		
		logLevel, err := logrus.ParseLevel(level)
		if err != nil {
			logLevel = logrus.InfoLevel
		}
		log.SetLevel(logLevel)
		
		// Set formatter based on environment
		env := os.Getenv("ENVIRONMENT")
		if env == "production" {
			log.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: "2006-01-02T15:04:05.000Z",
				FieldMap: logrus.FieldMap{
					logrus.FieldKeyTime:  "timestamp",
					logrus.FieldKeyLevel: "level",
					logrus.FieldKeyMsg:   "message",
				},
			})
		} else {
			log.SetFormatter(&logrus.TextFormatter{
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05.000",
				ForceColors:     true,
			})
		}
		
		// Set output
		log.SetOutput(os.Stdout)
		
		// Add hooks if needed
		// log.AddHook(...)
	})
}

// GetLogger returns the logger instance
func GetLogger() *logrus.Logger {
	if log == nil {
		Init()
	}
	return log
}

// WithField adds a field to the log entry
func WithField(key string, value interface{}) *logrus.Entry {
	return getEntry().WithField(key, value)
}

// WithFields adds multiple fields to the log entry
func WithFields(fields map[string]interface{}) *logrus.Entry {
	return getEntry().WithFields(fields)
}

// WithError adds an error to the log entry
func WithError(err error) *logrus.Entry {
	return getEntry().WithError(err)
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	getEntry().Debugf(format, args...)
}

// Info logs an info message
func Info(format string, args ...interface{}) {
	getEntry().Infof(format, args...)
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	getEntry().Warnf(format, args...)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	getEntry().Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func Fatal(format string, args ...interface{}) {
	getEntry().Fatalf(format, args...)
}

// Panic logs a panic message and panics
func Panic(format string, args ...interface{}) {
	getEntry().Panicf(format, args...)
}

// getEntry returns a log entry with caller information
func getEntry() *logrus.Entry {
	if log == nil {
		Init()
	}
	
	// Get caller information
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}
	
	// Extract just the filename
	parts := strings.Split(file, "/")
	if len(parts) > 0 {
		file = parts[len(parts)-1]
	}
	
	return log.WithFields(logrus.Fields{
		"caller": fmt.Sprintf("%s:%d", file, line),
	})
}

// Structured logging helpers

// LogRequest logs an HTTP request
func LogRequest(method, path string, statusCode int, duration int64, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"method":      method,
		"path":        path,
		"status_code": statusCode,
		"duration_ms": duration,
		"type":        "http_request",
	})
	
	if statusCode >= 500 {
		entry.Error("HTTP request failed")
	} else if statusCode >= 400 {
		entry.Warn("HTTP request client error")
	} else {
		entry.Info("HTTP request completed")
	}
}

// LogTransaction logs a transaction
func LogTransaction(txnID, aspID, status string, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"transaction_id": txnID,
		"asp_id":        aspID,
		"status":        status,
		"type":          "transaction",
	})
	
	if status == "FAILED" {
		entry.Error("Transaction failed")
	} else {
		entry.Info("Transaction processed")
	}
}

// LogAuthentication logs an authentication attempt
func LogAuthentication(txnID, authMode, status string, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"transaction_id": txnID,
		"auth_mode":     authMode,
		"status":        status,
		"type":          "authentication",
	})
	
	if status == "FAILED" {
		entry.Warn("Authentication failed")
	} else {
		entry.Info("Authentication successful")
	}
}

// LogUIDAI logs UIDAI communication
func LogUIDAI(operation, status string, responseTime int64, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"operation":     operation,
		"status":        status,
		"response_time": responseTime,
		"type":          "uidai",
	})
	
	if status == "ERROR" {
		entry.Error("UIDAI operation failed")
	} else {
		entry.Debug("UIDAI operation completed")
	}
}

// LogDatabase logs database operations
func LogDatabase(operation, table string, duration int64, err error) {
	entry := WithFields(logrus.Fields{
		"operation":   operation,
		"table":       table,
		"duration_ms": duration,
		"type":        "database",
	})
	
	if err != nil {
		entry.WithError(err).Error("Database operation failed")
	} else {
		entry.Debug("Database operation completed")
	}
}

// LogSecurity logs security-related events
func LogSecurity(event, severity string, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"event":    event,
		"severity": severity,
		"type":     "security",
	})
	
	switch severity {
	case "critical":
		entry.Error("Security event")
	case "high":
		entry.Warn("Security event")
	default:
		entry.Info("Security event")
	}
}

// Audit logs audit events
func Audit(action, entity, entityID string, userID string, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"action":    action,
		"entity":    entity,
		"entity_id": entityID,
		"user_id":   userID,
		"type":      "audit",
	})
	
	entry.Info("Audit event")
}

// Performance logs performance metrics
func Performance(operation string, duration int64, fields map[string]interface{}) {
	entry := WithFields(fields)
	entry = entry.WithFields(logrus.Fields{
		"operation":   operation,
		"duration_ms": duration,
		"type":        "performance",
	})
	
	if duration > 5000 { // More than 5 seconds
		entry.Warn("Slow operation detected")
	} else {
		entry.Debug("Performance metric")
	}
}

// SetLevel sets the log level
func SetLevel(level string) error {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	
	if log == nil {
		Init()
	}
	
	log.SetLevel(logLevel)
	return nil
}

// AddHook adds a hook to the logger
func AddHook(hook logrus.Hook) {
	if log == nil {
		Init()
	}
	log.AddHook(hook)
}