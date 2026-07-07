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
    mkdir -p /var/lib/asscor && \
    mkdir -p /var/log/asscor

RUN apk add --no-cache wget

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ASSCOR-kernel /opt/asscor/
COPY --from=builder /out/ASSCOR-agent /opt/asscor/agent/
COPY config.ini /etc/asscor/config.ini
COPY agent.ini /etc/asscor/agent.ini
COPY config/ /etc/asscor/config/

RUN chown -R asscor:asscor /opt/asscor /etc/asscor /var/lib/asscor /var/log/asscor

EXPOSE 50051 50052 8087

USER asscor
WORKDIR /opt/asscor

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8087/api/health || exit 1

ENTRYPOINT ["./ASSCOR-kernel", "--config=/etc/asscor/config.ini", "--listen=:50051", "--webui-port=8087", "--log-output=/var/log/asscor/kernel.log"]
