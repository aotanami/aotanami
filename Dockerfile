# Build the manager binary
FROM golang:1.26.1-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Cache deps and install ca-certificates for TLS
RUN go mod download && \
    apk add --no-cache ca-certificates

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build with version info injected via ldflags
# CGO_ENABLED=0 produces a fully static binary — no libc/OS dependencies
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X 'github.com/zelyo-ai/zelyo-operator/internal/version.Version=${VERSION}' -X 'github.com/zelyo-ai/zelyo-operator/internal/version.Commit=${COMMIT}' -X 'github.com/zelyo-ai/zelyo-operator/internal/version.Date=${BUILD_DATE}'" \
    -a -o manager ./cmd/main.go


# ── Final stage: scratch (zero OS packages = zero OS CVEs) ──────────────────
# Since the binary is statically compiled (CGO_ENABLED=0), we don't need any
# OS libraries. Using scratch instead of distroless eliminates ALL OS-level
# vulnerabilities from the image scan.
FROM scratch

# OCI Image Spec labels
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="Zelyo Operator"
LABEL org.opencontainers.image.description="Autonomous AI Security Agent for Kubernetes — Detect, Correlate, Fix"
LABEL org.opencontainers.image.url="https://github.com/zelyo-ai/zelyo-operator"
LABEL org.opencontainers.image.source="https://github.com/zelyo-ai/zelyo-operator"
LABEL org.opencontainers.image.vendor="Zelyo AI"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.documentation="https://github.com/zelyo-ai/zelyo-operator/tree/main/docs"

# Copy CA certificates for TLS (Zelyo Operator makes HTTPS calls to LLM APIs)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically-linked binary
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
