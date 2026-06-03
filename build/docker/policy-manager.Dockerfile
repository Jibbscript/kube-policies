# Build stage — uses TARGETARCH so the image is native to the kind cluster
# arch by default (arm64 on Apple Silicon, amd64 on x86_64 CI).
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata curl

# Set working directory
WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies with retry logic via shell
RUN set -e; \
    for attempt in 1 2 3; do \
      echo "Download attempt $attempt..."; \
      if go mod download -x 2>&1; then \
        echo "Download successful"; \
        break; \
      elif [ $attempt -lt 3 ]; then \
        echo "Download failed, retrying in 5s..."; \
        sleep 5; \
      else \
        echo "Download failed after 3 attempts"; \
        exit 1; \
      fi; \
    done

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# GOFIPS140 selects the Go native FIPS 140-3 cryptographic module (CRY-WU-01).
ARG GOFIPS140=v1.0.0

# Build the binary with the FIPS 140-3 module, then fail the build if the
# resulting binary does not record the GOFIPS140 marker.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFIPS140=${GOFIPS140} go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -trimpath \
    -o policy-manager \
    ./cmd/policy-manager && \
    go version -m policy-manager | grep -q "GOFIPS140=${GOFIPS140}" \
      || (echo "FATAL: policy-manager binary is missing the GOFIPS140 marker" >&2 && exit 1)

# Final stage
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

# Re-declare ARGs for final stage
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /workspace/policy-manager /usr/local/bin/policy-manager

# Use nonroot user
USER 65534:65534

# Run the cryptographic libraries in FIPS 140-3 mode (CRY-WU-01).
ENV GODEBUG=fips140=on

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/policy-manager"]

# Labels
LABEL org.opencontainers.image.title="Kube-Policies Policy Manager"
LABEL org.opencontainers.image.description="Policy management service for Kube-Policies"
LABEL org.opencontainers.image.vendor="Enterprise"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/Jibbscript/kube-policies"
LABEL org.opencontainers.image.documentation="https://docs.kube-policies.io"
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

