.PHONY: build test vet run

build:
	CGO_ENABLED=0 go build -trimpath -o bin/auth-service ./cmd/auth-service

test:
	go test ./...

vet:
	go vet ./...

run:
	go run ./cmd/auth-service
