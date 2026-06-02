# Build stage — use BUILDPLATFORM to build natively for the host arch,
# then cross-compile to TARGETARCH if invoked via `docker buildx --platform=...`.
# When the host == target (the common `make demo-up` path on arm64 Macs and
# amd64 CI), no emulation runs.
FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.25.11-alpine@sha256:cd2fb3559df6e13bc93b7f0734a4eabe1d21e7b64eec211ed90784f00a17a56a AS builder

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
# GOFIPS140 selects the Go native FIPS 140-3 cryptographic module (CRY-WU-01).
# Building with it records a GOFIPS140 marker in the binary and bakes
# DefaultGODEBUG=fips140=on, so crypto runs through the validated module.
ARG GOFIPS140=v1.0.0

# Build the binary with the FIPS 140-3 module, then fail the build if the
# resulting binary does not record the GOFIPS140 marker (defense against a
# silent loss of FIPS mode).
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOFIPS140=${GOFIPS140} go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -trimpath \
    -o admission-webhook \
    ./cmd/admission-webhook && \
    go version -m admission-webhook | grep -q "GOFIPS140=${GOFIPS140}" \
      || (echo "FATAL: admission-webhook binary is missing the GOFIPS140 marker" >&2 && exit 1)

# Final stage
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /workspace/admission-webhook /usr/local/bin/admission-webhook

# Use nonroot user
USER 65534:65534

# Run the cryptographic libraries in FIPS 140-3 mode (CRY-WU-01). The binary
# already bakes DefaultGODEBUG=fips140=on via the GOFIPS140 build; setting it
# explicitly makes the runtime posture visible and overridable by operators.
ENV GODEBUG=fips140=on

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

