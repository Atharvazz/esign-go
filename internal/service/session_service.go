package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/esign-go/pkg/logger"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// ISessionService defines the interface for session management
type ISessionService interface {
	// Get retrieves a value from session
	Get(c *gin.Context, key string) interface{}

	// Set stores a value in session
	Set(c *gin.Context, key string, value interface{}) error

	// Delete removes a value from session
	Delete(c *gin.Context, key string) error

	// Clear removes all values from session
	Clear(c *gin.Context) error

	// Save persists the session
	Save(c *gin.Context) error

	// GetFlash retrieves and removes a flash value
	GetFlash(c *gin.Context, key string) interface{}

	// SetFlash stores a flash value
	SetFlash(c *gin.Context, key string, value interface{}) error

	// GetSession returns the underlying session
	GetSession(c *gin.Context) sessions.Session

	// StoreSessionData stores structured session data
	StoreSessionData(c *gin.Context, data *SessionData) error

	// GetSessionData retrieves structured session data
	GetSessionData(c *gin.Context) (*SessionData, error)
}

// SessionService implements session management
type SessionService struct {
	redisClient *redis.Client
	prefix      string
	maxAge      int
}

// NewSessionService creates a new session service
func NewSessionService(redisClient *redis.Client, prefix string, maxAge int) *SessionService {
	return &SessionService{
		redisClient: redisClient,
		prefix:      prefix,
		maxAge:      maxAge,
	}
}

// Get retrieves a value from session
func (s *SessionService) Get(c *gin.Context, key string) interface{} {
	session := sessions.Default(c)
	return session.Get(key)
}

// Set stores a value in session
func (s *SessionService) Set(c *gin.Context, key string, value interface{}) error {
	session := sessions.Default(c)

	// Handle complex types by converting to JSON
	if needsSerialization(value) {
		jsonData, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to serialize value: %w", err)
		}
		session.Set(key, string(jsonData))
	} else {
		session.Set(key, value)
	}

	return nil
}

// Delete removes a value from session
func (s *SessionService) Delete(c *gin.Context, key string) error {
	session := sessions.Default(c)
	session.Delete(key)
	return nil
}

// Clear removes all values from session
func (s *SessionService) Clear(c *gin.Context) error {
	session := sessions.Default(c)
	session.Clear()
	return session.Save()
}

// Save persists the session
func (s *SessionService) Save(c *gin.Context) error {
	session := sessions.Default(c)
	return session.Save()
}

// GetFlash retrieves and removes a flash value
func (s *SessionService) GetFlash(c *gin.Context, key string) interface{} {
	session := sessions.Default(c)
	value := session.Get(key)
	if value != nil {
		session.Delete(key)
		session.Save()
	}
	return value
}

// SetFlash stores a flash value
func (s *SessionService) SetFlash(c *gin.Context, key string, value interface{}) error {
	return s.Set(c, key, value)
}

// GetSession returns the underlying session
func (s *SessionService) GetSession(c *gin.Context) sessions.Session {
	return sessions.Default(c)
}

// Helper functions

func needsSerialization(value interface{}) bool {
	switch value.(type) {
	case string, int, int64, float64, bool:
		return false
	default:
		return true
	}
}

// SessionData represents session data structure
type SessionData struct {
	RequestID        int64                  `json:"requestId"`
	AspID            string                 `json:"aspId"`
	LegalName        string                 `json:"legalName"`
	SignerID         string                 `json:"signerId"`
	TransactionID    string                 `json:"txn"`
	Timestamp        string                 `json:"ts"`
	AuthMode         string                 `json:"authMode"`
	V1               string                 `json:"v1"`
	V2               string                 `json:"v2"`
	V3               string                 `json:"v3"`
	Build            string                 `json:"build"`
	Adr              string                 `json:"adr"`
	CustomViewOutput string                 `json:"cvOutput"`
	Filler1          string                 `json:"filler1"`
	Filler2          string                 `json:"filler2"`
	Filler3          string                 `json:"filler3"`
	Filler4          string                 `json:"filler4"`
	Filler5          string                 `json:"filler5"`
	OtpTxn           string                 `json:"otpTxn"`
	RetryCount       int                    `json:"retryCount"`
	CreatedAt        time.Time              `json:"createdAt"`
	BiometricEnv     string                 `json:"bioEnv"`
	Extra            map[string]interface{} `json:"extra"`
}

// StoreSessionData stores structured session data
func (s *SessionService) StoreSessionData(c *gin.Context, data *SessionData) error {
	log := logger.GetLogger()

	// Store individual fields for compatibility
	fields := map[string]interface{}{
		"rid":       data.RequestID,
		"aspId":     data.AspID,
		"ln":        data.LegalName,
		"sid":       data.SignerID,
		"msg3":      data.TransactionID,
		"msg4":      data.Timestamp,
		"authMod":   data.AuthMode,
		"v1":        data.V1,
		"v2":        data.V2,
		"v3":        data.V3,
		"build":     data.Build,
		"adr":       data.Adr,
		"cv_output": data.CustomViewOutput,
		"filler1":   data.Filler1,
		"filler2":   data.Filler2,
		"filler3":   data.Filler3,
		"filler4":   data.Filler4,
		"filler5":   data.Filler5,
		"bioEnv":    data.BiometricEnv,
	}

	// Store each field
	for key, value := range fields {
		if err := s.Set(c, key, value); err != nil {
			log.WithError(err).WithField("key", key).Error("Failed to store session field")
			return err
		}
	}

	// Store complete data as JSON
	if err := s.Set(c, "sessionData", data); err != nil {
		log.WithError(err).Error("Failed to store complete session data")
		return err
	}

	// Save session
	return s.Save(c)
}

// GetSessionData retrieves structured session data
func (s *SessionService) GetSessionData(c *gin.Context) (*SessionData, error) {
	// Try to get complete session data first
	if dataStr := s.Get(c, "sessionData"); dataStr != nil {
		if jsonStr, ok := dataStr.(string); ok {
			var data SessionData
			if err := json.Unmarshal([]byte(jsonStr), &data); err == nil {
				return &data, nil
			}
		}
	}

	// Fall back to individual fields
	data := &SessionData{
		Extra: make(map[string]interface{}),
	}

	// Get individual fields
	if rid := s.Get(c, "rid"); rid != nil {
		switch v := rid.(type) {
		case int64:
			data.RequestID = v
		case float64:
			data.RequestID = int64(v)
		}
	}

	if aspId := s.Get(c, "aspId"); aspId != nil {
		data.AspID, _ = aspId.(string)
	}

	if ln := s.Get(c, "ln"); ln != nil {
		data.LegalName, _ = ln.(string)
	}

	if sid := s.Get(c, "sid"); sid != nil {
		data.SignerID, _ = sid.(string)
	}

	if msg3 := s.Get(c, "msg3"); msg3 != nil {
		data.TransactionID, _ = msg3.(string)
	}

	if msg4 := s.Get(c, "msg4"); msg4 != nil {
		data.Timestamp, _ = msg4.(string)
	}

	if authMod := s.Get(c, "authMod"); authMod != nil {
		data.AuthMode, _ = authMod.(string)
	}

	if v1 := s.Get(c, "v1"); v1 != nil {
		data.V1, _ = v1.(string)
	}

	if v2 := s.Get(c, "v2"); v2 != nil {
		data.V2, _ = v2.(string)
	}

	if v3 := s.Get(c, "v3"); v3 != nil {
		data.V3, _ = v3.(string)
	}

	if build := s.Get(c, "build"); build != nil {
		data.Build, _ = build.(string)
	}

	if adr := s.Get(c, "adr"); adr != nil {
		data.Adr, _ = adr.(string)
	}

	if bioEnv := s.Get(c, "bioEnv"); bioEnv != nil {
		data.BiometricEnv, _ = bioEnv.(string)
	}

	return data, nil
}
