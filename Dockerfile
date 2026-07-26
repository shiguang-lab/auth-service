FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-service ./cmd/auth-service

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/auth-service /auth-service
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/auth-service"]
