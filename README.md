# eSign Service - Go Implementation

A complete Golang implementation of the eSign service with Aadhaar-based authentication and digital signature capabilities.

## Features

- ✅ Complete `/authenticate/esign-doc` endpoint implementation
- ✅ XML request parsing and validation
- ✅ Aadhaar OTP and Biometric authentication
- ✅ Digital certificate generation
- ✅ Document signing with PKCS#7 signatures
- ✅ Rate limiting and security middleware
- ✅ Custom view template support
- ✅ Comprehensive error handling
- ✅ Database persistence with PostgreSQL
- ✅ Structured logging
- ✅ Configuration management
- ✅ CORS support
- ✅ Request tracking and auditing

## Project Structure

```
esign-go/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go           # Configuration management
│   ├── controller/
│   │   └── authenticate_controller.go  # HTTP handlers
│   ├── service/
│   │   ├── interfaces.go       # Service interfaces
│   │   ├── esign_service.go    # Core business logic
│   │   ├── xml_validator.go    # XML validation
│   │   ├── crypto_service.go   # Cryptographic operations
│   │   ├── template_service.go # Template rendering
│   │   └── uidai_service.go    # UIDAI integration
│   ├── repository/
│   │   ├── interfaces.go       # Repository interfaces
│   │   ├── database.go         # Database initialization
│   │   ├── esign_repository.go # eSign data access
│   │   ├── audit_repository.go # Audit logging
│   │   └── asp_repository.go   # ASP management
│   ├── models/
│   │   └── models.go           # Data models
│   ├── middleware/
│   │   ├── rate_limiter.go    # Rate limiting
│   │   ├── logger.go          # Request logging
│   │   ├── request_id.go      # Request ID tracking
│   │   └── cors.go            # CORS handling
│   └── utils/
├── pkg/
│   ├── errors/
│   │   └── errors.go          # Custom error types
│   ├── logger/
│   │   └── logger.go          # Logging utilities
│   └── xmlparser/
│       └── parser.go          # XML parsing utilities
├── configs/
│   └── config.yaml            # Configuration file
├── templates/                  # HTML templates
├── static/                    # Static assets
├── migrations/               # Database migrations
├── go.mod                    # Go module file
└── README.md                # This file
```

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 12 or higher
- Redis (optional, for distributed rate limiting)

## Installation

1. Clone the repository:
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
```

2. Install dependencies:
```bash
go mod download
```

3. Set up the database:
```bash
# Create database
createdb esign_db

# Run migrations (handled automatically on startup)
```

4. Configure the application:
```bash
# Copy and edit the configuration file
cp configs/config.yaml configs/config.local.yaml
# Edit configs/config.local.yaml with your settings
```

## Configuration

The application uses a YAML configuration file with the following sections:

- **app**: Application settings (name, environment, debug mode)
- **server**: HTTP server configuration
- **database**: PostgreSQL connection settings
- **security**: Certificate paths and security settings
- **uidai**: UIDAI integration configuration
- **rateLimit**: Rate limiting rules
- **cors**: CORS policy settings
- **logging**: Logging configuration

## Running the Application

### Development Mode

```bash
go run cmd/server/main.go
```

### Production Mode

```bash
# Build the binary
go build -o esign-server cmd/server/main.go

# Run with production config
ENVIRONMENT=production ./esign-server
```

### Using Docker

```bash
# Build Docker image
docker build -t esign-service .

# Run container
docker run -p 8080:8080 -v /app/esign/config:/app/config esign-service
```

## API Endpoints

### 1. POST /authenticate/esign-doc
Main endpoint for document signing requests.

**Request Parameters:**
- `msg`: Base64 encoded XML request
- `cv_docId`: Optional custom view template ID

**Response:**
- HTML page for authentication or
- JSON response for API clients

### 2. POST /authenticate/es
Handles authentication submission.

**Form Data:**
- `aadhaar`: 12-digit Aadhaar number
- `authMode`: Authentication mode (OTP/BIO)
- `consent`: User consent (Y/N)

### 3. POST /authenticate/otp-request
Generates OTP for Aadhaar authentication.

**Request Body:**
```json
{
  "aadhaar": "123456789012"
}
```

### 4. POST /authenticate/validate-otp
Validates OTP and proceeds with signing.

**Request Body:**
```json
{
  "txnId": "transaction-id",
  "otp": "123456",
  "aadhaar": "123456789012"
}
```

### 5. GET /authenticate/status/:txnId
Checks the status of a signing transaction.

### 6. POST /authenticate/callback
Receives callbacks from UIDAI or ASP.

## Security Features

1. **Rate Limiting**
   - Per-endpoint rate limits
   - IP-based throttling
   - Configurable burst rates

2. **Input Validation**
   - XML schema validation
   - Aadhaar number validation
   - Request signature verification

3. **Authentication**
   - UIDAI integration for Aadhaar auth
   - Session management
   - Maximum attempt limits

4. **Cryptography**
   - RSA key pair generation
   - X.509 certificate creation
   - PKCS#7 digital signatures

## Database Schema

The application uses PostgreSQL with the following main tables:

- `asps`: Application Service Providers
- `transactions`: Signing transactions
- `auth_attempts`: Authentication attempts
- `certificates`: Generated certificates
- `signing_records`: Document signing records

## Logging

Structured logging with different levels:
- **DEBUG**: Detailed debugging information
- **INFO**: General information
- **WARN**: Warning messages
- **ERROR**: Error messages

Logs include:
- Request/response tracking
- Authentication attempts
- UIDAI communication
- Database operations
- Security events

## Error Handling

Custom error types for different scenarios:
- `ValidationError`: Input validation failures
- `AuthenticationError`: Authentication failures
- `UIDAIError`: UIDAI service errors
- `RateLimitError`: Rate limit exceeded
- `DatabaseError`: Database operation failures

## Testing

Run tests:
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/service
```

## Performance Optimization

1. **Connection Pooling**: Database connection pooling
2. **Template Caching**: HTML templates cached in memory
3. **Concurrent Processing**: Goroutines for async operations
4. **Response Compression**: Gzip compression for responses

## Monitoring

Health check endpoint:
```bash
curl http://localhost:8080/health
```

## Development

### Adding New Features

1. Define interfaces in `internal/service/interfaces.go`
2. Implement service logic in `internal/service/`
3. Add repository methods if needed
4. Update controllers in `internal/controller/`
5. Add tests

### Code Style

Follow Go best practices:
- Use `gofmt` for formatting
- Run `golint` for linting
- Use meaningful variable names
- Add comments for exported functions

## Deployment

### Environment Variables

- `ESIGN_DATABASE_PASSWORD`: Database password
- `ESIGN_SECURITY_JWTSECRET`: JWT secret key
- `ESIGN_UIDAI_LICENSEKEY`: UIDAI license key
- `LOG_LEVEL`: Logging level
- `ENVIRONMENT`: Runtime environment

### Production Checklist

- [ ] Set `app.debug` to `false`
- [ ] Configure proper database credentials
- [ ] Set up SSL certificates
- [ ] Configure rate limits
- [ ] Set up monitoring
- [ ] Configure log rotation
- [ ] Set up backup strategy

## License

This implementation follows the same license as the original Java implementation.

## Support

For issues or questions, please refer to the documentation or contact the development team.