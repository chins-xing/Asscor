# ASSCOR Kernel - Multi-stage Dockerfile
# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /out/ASSCOR-kernel ./cmd/kernel/

# Runtime stage
FROM alpine:3.20

RUN adduser -D -h /opt/asscor asscor && \
    mkdir -p /opt/asscor/data /opt/asscor/logs /opt/asscor/certs /opt/asscor/build

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/ASSCOR-kernel /opt/asscor/
COPY config.ini /opt/asscor/
COPY agent.ini /opt/asscor/
COPY config/ /opt/asscor/config/

RUN chown -R asscor:asscor /opt/asscor

EXPOSE 50051 8087

USER asscor
WORKDIR /opt/asscor

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8087/api/health || exit 1

ENTRYPOINT ["./ASSCOR-kernel", "--config=config.ini", "--listen=:50051", "--webui-port=8087"]
