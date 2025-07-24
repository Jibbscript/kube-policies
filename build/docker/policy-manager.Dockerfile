# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -a -installsuffix cgo \
    -o policy-manager \
    ./cmd/policy-manager

# Final stage
FROM gcr.io/distroless/static:nonroot

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /workspace/policy-manager /usr/local/bin/policy-manager

# Use nonroot user
USER 65534:65534

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/policy-manager"]

# Labels
LABEL org.opencontainers.image.title="Kube-Policies Policy Manager"
LABEL org.opencontainers.image.description="Policy management service for Kube-Policies"
LABEL org.opencontainers.image.vendor="Enterprise"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/Jibbscript/kube-policies"
LABEL org.opencontainers.image.documentation="https://docs.kube-policies.io"
LABEL org.opencontainers.image.version="${VERSION}"

