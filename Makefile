.PHONY: build test run

build:
	CGO_ENABLED=0 go build -trimpath -o bin/auth-service ./cmd/auth-service

test:
	go test ./...

run:
	go run ./cmd/auth-service
