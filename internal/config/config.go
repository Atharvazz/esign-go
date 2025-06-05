package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for our application
type Config struct {
	App      AppConfig
	Server   ServerConfig
	Database DatabaseConfig
	Security SecurityConfig
	UIDAI    UIDAIConfig
	Templates TemplateConfig
	RateLimit RateLimitConfig
	CORS     CORSConfig
	Logging  LoggingConfig
}

type AppConfig struct {
	Name        string
	Environment string
	Build       string
	Debug       bool
}

type ServerConfig struct {
	Address      string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type DatabaseConfig struct {
	Host         string
	Port         int
	User         string
	Password     string
	DBName       string
	SSLMode      string
	MaxOpenConns int
	MaxIdleConns int
	MaxLifetime  time.Duration
}

type SecurityConfig struct {
	JWTSecret            string
	SigningCertPath      string
	SigningKeyPath       string
	EncryptionCertPath   string
	EncryptionKeyPath    string
	TrustedCertsPath     string
	PasswordSalt         string
	SessionTimeout       time.Duration
	MaxAuthAttempts      int
}

type UIDAIConfig struct {
	AuthURL          string
	OTPAuthURL       string
	EKYCAuthURL      string
	BiometricEnv     string
	LicenseKey       string
	SubAUA           string
	AuthVersion      string
	Timeout          time.Duration
}

type TemplateConfig struct {
	Path           string
	CacheTemplates bool
}

type RateLimitConfig struct {
	Enabled  bool
	EsignDoc RateLimitRule
	OTP      RateLimitRule
	Default  RateLimitRule
}

type RateLimitRule struct {
	Rate     int
	Burst    int
	Duration time.Duration
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

type LoggingConfig struct {
	Level           string
	Format          string
	OutputPath      string
	ErrorOutputPath string
	RequestLogging  bool
	XMLLogging      bool
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/app/esign/")
	
	// Set defaults
	setDefaults()
	
	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Enable environment variable override
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ESIGN")
	
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return &config, nil
}

func setDefaults() {
	// App defaults
	viper.SetDefault("app.name", "eSign Service")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.build", "1.0.0")
	viper.SetDefault("app.debug", false)
	
	// Server defaults
	viper.SetDefault("server.address", ":8080")
	viper.SetDefault("server.readTimeout", "30s")
	viper.SetDefault("server.writeTimeout", "30s")
	viper.SetDefault("server.idleTimeout", "120s")
	
	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslMode", "disable")
	viper.SetDefault("database.maxOpenConns", 25)
	viper.SetDefault("database.maxIdleConns", 25)
	viper.SetDefault("database.maxLifetime", "15m")
	
	// Security defaults
	viper.SetDefault("security.sessionTimeout", "30m")
	viper.SetDefault("security.maxAuthAttempts", 3)
	
	// Rate limit defaults
	viper.SetDefault("rateLimit.enabled", true)
	viper.SetDefault("rateLimit.esignDoc.rate", 10)
	viper.SetDefault("rateLimit.esignDoc.burst", 20)
	viper.SetDefault("rateLimit.esignDoc.duration", "1m")
	viper.SetDefault("rateLimit.otp.rate", 5)
	viper.SetDefault("rateLimit.otp.burst", 10)
	viper.SetDefault("rateLimit.otp.duration", "1m")
	viper.SetDefault("rateLimit.default.rate", 100)
	viper.SetDefault("rateLimit.default.burst", 200)
	viper.SetDefault("rateLimit.default.duration", "1m")
	
	// CORS defaults
	viper.SetDefault("cors.allowedOrigins", []string{"*"})
	viper.SetDefault("cors.allowedMethods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("cors.allowedHeaders", []string{"*"})
	viper.SetDefault("cors.allowCredentials", true)
	viper.SetDefault("cors.maxAge", "12h")
	
	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.outputPath", "stdout")
	viper.SetDefault("logging.errorOutputPath", "stderr")
	viper.SetDefault("logging.requestLogging", true)
	viper.SetDefault("logging.xmlLogging", false)
}

func validate(cfg *Config) error {
	// Validate required fields
	if cfg.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if cfg.Database.User == "" {
		return fmt.Errorf("database user is required")
	}
	if cfg.Database.DBName == "" {
		return fmt.Errorf("database name is required")
	}
	if cfg.Security.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}
	if cfg.UIDAI.AuthURL == "" {
		return fmt.Errorf("UIDAI auth URL is required")
	}
	
	return nil
}