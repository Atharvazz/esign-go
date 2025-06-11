package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for our application
type Config struct {
	App                  AppConfig         `mapstructure:"app"`
	Server               ServerConfig      `mapstructure:"server"`
	Database             DatabaseConfig    `mapstructure:"database"`
	Security             SecurityConfig    `mapstructure:"security"`
	UIDAI                UIDAIConfig       `mapstructure:"uidai"`
	Templates            TemplateConfig    `mapstructure:"templates"`
	RateLimit            RateLimitConfig   `mapstructure:"rateLimit"`
	CORS                 CORSConfig        `mapstructure:"cors"`
	Logging              LoggingConfig     `mapstructure:"logging"`
	Debug                DebugConfig       `mapstructure:"debug"`
	Biometric            BiometricConfig   `mapstructure:"biometric"`
	Auth                 AuthConfig        `mapstructure:"auth"`
	CheckStatus          CheckStatusConfig `mapstructure:"checkStatus"`
	RequestTimeout       int               `mapstructure:"requestTimeout"`
	Build                string            `mapstructure:"build"`
	BiometricEnv         string            `mapstructure:"biometricEnv"`
	BiometricResponseURL string            `mapstructure:"biometricResponseUrl"`
	ConsentText          string            `mapstructure:"consentText"`
	AuthAttempts         int               `mapstructure:"authAttempts"`
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Environment string `mapstructure:"environment"`
	Build       string `mapstructure:"build"`
	Debug       bool   `mapstructure:"debug"`
}

type ServerConfig struct {
	Address        string        `mapstructure:"address"`
	ReadTimeout    time.Duration `mapstructure:"readTimeout"`
	WriteTimeout   time.Duration `mapstructure:"writeTimeout"`
	IdleTimeout    time.Duration `mapstructure:"idleTimeout"`
	Version        string        `mapstructure:"version"`
	Environment    string        `mapstructure:"environment"`
	RequestTimeout int           `mapstructure:"requestTimeout"`
}

type DatabaseConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	User         string        `mapstructure:"user"`
	Password     string        `mapstructure:"password"`
	DBName       string        `mapstructure:"dbname"`
	SSLMode      string        `mapstructure:"sslmode"`
	MaxOpenConns int           `mapstructure:"maxopenconns"`
	MaxIdleConns int           `mapstructure:"maxidleconns"`
	MaxLifetime  time.Duration `mapstructure:"maxlifetime"`
}

type SecurityConfig struct {
	JWTSecret            string        `mapstructure:"jwtSecret"`
	SigningCertPath      string        `mapstructure:"signingCertPath"`
	SigningKeyPath       string        `mapstructure:"signingKeyPath"`
	EncryptionCertPath   string        `mapstructure:"encryptionCertPath"`
	EncryptionKeyPath    string        `mapstructure:"encryptionKeyPath"`
	TrustedCertsPath     string        `mapstructure:"trustedCertsPath"`
	PasswordSalt         string        `mapstructure:"passwordSalt"`
	SessionTimeout       time.Duration `mapstructure:"sessionTimeout"`
	MaxAuthAttempts      int           `mapstructure:"maxAuthAttempts"`
	MaxXMLSize           int64         `mapstructure:"maxXMLSize"`
}

type UIDAIConfig struct {
	AuthURL          string        `mapstructure:"authURL"`
	OTPAuthURL       string        `mapstructure:"otpAuthURL"`
	EKYCAuthURL      string        `mapstructure:"ekycAuthURL"`
	BiometricEnv     string        `mapstructure:"biometricEnv"`
	LicenseKey       string        `mapstructure:"licenseKey"`
	SubAUA           string        `mapstructure:"subAUA"`
	AuthVersion      string        `mapstructure:"authVersion"`
	Timeout          time.Duration `mapstructure:"timeout"`
	PrivateKey       string        `mapstructure:"privateKey"`
	Certificate      string        `mapstructure:"certificate"`
	PublicKey        string        `mapstructure:"publicKey"`
}

type TemplateConfig struct {
	Path           string `mapstructure:"path"`
	CacheTemplates bool   `mapstructure:"cacheTemplates"`
}

type RateLimitConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	EsignDoc    RateLimitRule `mapstructure:"esignDoc"`
	OTP         RateLimitRule `mapstructure:"otp"`
	Default     RateLimitRule `mapstructure:"default"`
	CheckStatus RateLimitRule `mapstructure:"checkStatus"`
}

type RateLimitRule struct {
	Rate     int           `mapstructure:"rate"`
	Burst    int           `mapstructure:"burst"`
	Duration time.Duration `mapstructure:"duration"`
	Period   time.Duration `mapstructure:"period"`
}

type CORSConfig struct {
	AllowedOrigins   []string      `mapstructure:"allowedOrigins"`
	AllowedMethods   []string      `mapstructure:"allowedMethods"`
	AllowedHeaders   []string      `mapstructure:"allowedHeaders"`
	ExposedHeaders   []string      `mapstructure:"exposedHeaders"`
	AllowCredentials bool          `mapstructure:"allowCredentials"`
	MaxAge           time.Duration `mapstructure:"maxAge"`
}

type LoggingConfig struct {
	Level           string `mapstructure:"level"`
	Format          string `mapstructure:"format"`
	OutputPath      string `mapstructure:"outputPath"`
	ErrorOutputPath string `mapstructure:"errorOutputPath"`
	RequestLogging  bool   `mapstructure:"requestLogging"`
	XMLLogging      bool   `mapstructure:"xmlLogging"`
}

type DebugConfig struct {
	LogRequests   bool `mapstructure:"logRequests"`
	LogResponses  bool `mapstructure:"logResponses"`
	PrettyPrint   bool `mapstructure:"prettyPrint"`
	SkipXMLVerify bool `mapstructure:"skipXMLVerify"`
}

type BiometricConfig struct {
	Environment  string `mapstructure:"environment"`
	ResponseURL  string `mapstructure:"responseURL"`
	ConsentText  string `mapstructure:"consentText"`
}

type AuthConfig struct {
	MaxAttempts      int `mapstructure:"maxAttempts"`
	OTPRetryAttempts int `mapstructure:"otpRetryAttempts"`
	SessionTimeout   int `mapstructure:"sessionTimeout"`
}

type CheckStatusConfig struct {
	AllowedASPs []string `mapstructure:"allowedASPs"`
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
	
	// Request timeout default
	viper.SetDefault("requestTimeout", 30)
	
	// Server defaults
	viper.SetDefault("server.address", ":8080")
	viper.SetDefault("server.readTimeout", "30s")
	viper.SetDefault("server.writeTimeout", "30s")
	viper.SetDefault("server.idleTimeout", "120s")
	viper.SetDefault("server.requestTimeout", 30) // 30 minutes
	
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
	viper.SetDefault("security.maxXMLSize", 10485760) // 10MB
	
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
	
	// Template defaults
	viper.SetDefault("templates.path", "./templates")
	viper.SetDefault("templates.cacheTemplates", true)
	
	// Auth defaults
	viper.SetDefault("auth.maxAttempts", 3)
	viper.SetDefault("auth.otpRetryAttempts", 3)
	viper.SetDefault("auth.sessionTimeout", 30)
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