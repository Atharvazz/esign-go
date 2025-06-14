# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o esign-server cmd/server/main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S esign && \
    adduser -u 1000 -S esign -G esign

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/esign-server .

# Copy configuration and templates
COPY --from=builder /build/configs ./configs
COPY --from=builder /build/templates ./templates
COPY --from=builder /build/static ./static

# Create necessary directories
RUN mkdir -p /app/logs /app/certs && \
    chown -R esign:esign /app

# Switch to non-root user
USER esign

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./esign-server"]