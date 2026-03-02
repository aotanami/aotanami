# Build the manager binary
FROM golang:1.25.3-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace

# Install ca-certificates for HTTPS calls in the final image
RUN apk add --no-cache ca-certificates

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Cache deps before building and copying source so that we don't need to re-download
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build with version info injected via ldflags
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w \
    -X github.com/aotanami/aotanami/internal/version.Version=${VERSION} \
    -X github.com/aotanami/aotanami/internal/version.Commit=${COMMIT} \
    -X github.com/aotanami/aotanami/internal/version.Date=${BUILD_DATE}" \
    -a -o manager cmd/main.go

# Use distroless as minimal base image
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static-debian12:nonroot

# OCI Image Spec labels
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="Aotanami"
LABEL org.opencontainers.image.description="Autonomous Kubernetes Protection — Powered by Agentic AI"
LABEL org.opencontainers.image.url="https://github.com/aotanami/aotanami"
LABEL org.opencontainers.image.source="https://github.com/aotanami/aotanami"
LABEL org.opencontainers.image.vendor="Zelyo AI"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.documentation="https://github.com/aotanami/aotanami/tree/main/docs"

WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
