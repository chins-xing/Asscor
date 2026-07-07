.PHONY: build docker-build docker-up docker-down docker-logs clean test

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/asscor-kernel ./cmd/kernel/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/asscor-agent ./cmd/agent/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/asscor ./cmd/asscor/

test:
	go test -count=1 ./...

vet:
	go vet ./...

docker-build:
	docker build -t asscor/asscor-kernel .

docker-up:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker/docker-compose.yml logs -f --tail=100

docker-status:
	@docker compose -f deploy/docker/docker-compose.yml ps

docker-clean:
	docker compose -f deploy/docker/docker-compose.yml down -v

clean:
	rm -rf build/asscor-*

dev:
	go run ./cmd/kernel/ --config=config.ini --listen=:50051 --log-level=debug
