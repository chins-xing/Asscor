# ASSCOR Kernel - Multi-stage Dockerfile
# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/ASSCOR-kernel ./cmd/kernel/ && \
    go build -trimpath -ldflags="-s -w" -o /out/ASSCOR-agent ./cmd/agent/

# Runtime stage
FROM alpine:3.20

RUN adduser -D -h /opt/asscor asscor && \
    mkdir -p /opt/asscor/data /opt/asscor/logs /opt/asscor/agent && \
    mkdir -p /etc/asscor/config && \
    mkdir -p /opt/asscor/certs && \
    mkdir -p /var/lib/asscor && \
    mkdir -p /var/log/asscor

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ASSCOR-kernel /opt/asscor/
COPY --from=builder /out/ASSCOR-agent /opt/asscor/agent/
COPY config.ini /etc/asscor/config.ini
COPY agent.ini /etc/asscor/agent.ini
COPY configs/ /etc/asscor/config/

RUN chown -R asscor:asscor /opt/asscor /etc/asscor /var/lib/asscor /var/log/asscor

EXPOSE 50051 50052

USER asscor
WORKDIR /opt/asscor

STOPSIGNAL SIGTERM

# Health is checked via the container init process (PID 1 = the kernel, the
# only foreground process): kill -0 1 probes its liveness without matching on
# command lines (audit L-3 — pgrep -f could false-match other processes) and
# needs no extra package (audit L-4 — wget was installed but never used).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD kill -0 1 || exit 1

ENTRYPOINT ["./ASSCOR-kernel", "--config=/etc/asscor/config.ini", "--listen=:50051", "--log-output=/var/log/asscor/kernel.log"]
