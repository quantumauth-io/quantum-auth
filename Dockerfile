########################
# 1. Build stage
########################
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Go modules first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Then the rest of the source
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

# Build qa server (main at cmd/quantum-auth/main.go)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
    -ldflags="-s -w \
      -X 'main.Version=${VERSION}' \
      -X 'main.Commit=${COMMIT}' \
      -X 'main.BuildDate=${BUILD_DATE}'" \
    -o /app/qa-server ./cmd/quantum-auth

########################
# 2. Runtime stage
########################
FROM debian:bookworm-slim

RUN useradd -r -u 10001 qa && mkdir -p /app && chown qa:qa /app
WORKDIR /app

COPY --from=builder /app/qa-server /app/qa-server

# App listens on 1042 in the container; map 8080->1042 in your dev env if you like
EXPOSE 1042

USER qa
ENTRYPOINT ["/app/qa-server"]