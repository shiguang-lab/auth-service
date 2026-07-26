FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-service ./cmd/auth-service

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S auth \
    && adduser -S -G auth -H -s /sbin/nologin auth
COPY --from=build /out/auth-service /usr/local/bin/auth-service
USER auth:auth
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/auth-service"]
