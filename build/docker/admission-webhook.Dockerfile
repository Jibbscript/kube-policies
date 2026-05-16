# Build stage — use BUILDPLATFORM to build natively for the host arch,
# then cross-compile to TARGETARCH if invoked via `docker buildx --platform=...`.
# When the host == target (the common `make demo-up` path on arm64 Macs and
# amd64 CI), no emulation runs.
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25-alpine AS builder

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
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Build the binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -trimpath \
    -o admission-webhook \
    ./cmd/admission-webhook

# Final stage
FROM gcr.io/distroless/static:nonroot

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /workspace/admission-webhook /usr/local/bin/admission-webhook

# Use nonroot user
USER 65534:65534

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/admission-webhook"]

# Labels
LABEL org.opencontainers.image.title="Kube-Policies Admission Webhook"
LABEL org.opencontainers.image.description="Kubernetes admission webhook for policy enforcement"
LABEL org.opencontainers.image.vendor="Enterprise"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/Jibbscript/kube-policies"
LABEL org.opencontainers.image.documentation="https://docs.kube-policies.io"
LABEL org.opencontainers.image.version="${VERSION}"

