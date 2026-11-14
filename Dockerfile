# syntax=docker/dockerfile:1

# The gateway image: the Dashboard is built and embedded in one static gateway
# binary, which runs as a non-root user and needs a writable filesystem only at
# /var/lib/apiward (database and audit log; mount a local volume there).
# Settings, keys and certificates are mounted read-only at /etc/apiward.
# Base images are pinned by digest; the tags show which release each is.

FROM node:26.13.0-trixie-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS dashboard
WORKDIR /src/dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY dashboard/index.html dashboard/tsconfig.json dashboard/vite.config.ts ./
COPY dashboard/src ./src
RUN npm run build

FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS gateway
# The toolchain is go.mod's toolchain line, so the build never downloads one.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY apiward.go ./
COPY cmd ./cmd
COPY internal ./internal
COPY module ./module
COPY policy ./policy
COPY --from=dashboard /src/dashboard/dist ./internal/adminui/dist
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -tags embedui -o /out/apiward ./cmd/apiward
# An empty data folder, so a new named volume mounted on it belongs to the
# image's user.
RUN mkdir -m 700 /out/data

# The source of the few system files the gateway reads; its nonroot user is
# UID and GID 65532 (its /etc/passwd).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS base

# The image holds the program and only what it reads: the certificate
# authorities that verify an upstream's certificate when a TLS profile names
# no ca_file, the user and group of UID 65532, and the name resolution order.
# It has no shell, no time zone data and no media type table; the gateway
# works in UTC and names its own content types.
FROM scratch
ARG REVISION=""
LABEL org.opencontainers.image.title="APIWard" \
      org.opencontainers.image.description="Security policy gateway for REST APIs" \
      org.opencontainers.image.source="https://github.com/Alex-Zechariah-02/apiward" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base /etc/passwd /etc/group /etc/nsswitch.conf /etc/
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
COPY --from=gateway /out/apiward /usr/local/bin/apiward
COPY --from=gateway --chown=65532:65532 /out/data /var/lib/apiward
USER 65532:65532
EXPOSE 9480
STOPSIGNAL SIGTERM
# apiward health asks the metrics listener's /readyz and waits up to 5 s.
HEALTHCHECK --interval=10s --timeout=8s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["/usr/local/bin/apiward", "health", "--config", "/etc/apiward/apiward.json"]
ENTRYPOINT ["/usr/local/bin/apiward"]
CMD ["run", "--config", "/etc/apiward/apiward.json"]
