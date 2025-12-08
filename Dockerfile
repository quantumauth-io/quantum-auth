
FROM golang:1.25-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath \
    -ldflags="-s -w \
      -X 'main.Version=${VERSION}' \
      -X 'main.Commit=${COMMIT}' \
      -X 'main.BuildDate=${BUILD_DATE}'" \
    -o /app/qa-server ./cmd/quantum-auth


FROM debian:bookworm-slim

RUN useradd -m -r -u 10001 qa && \
    mkdir -p /app && \
    chown -R qa:qa /app && \
    chown -R qa:qa /home/qa

WORKDIR /app

COPY --from=builder /app/qa-server /app/qa-server
COPY --from=builder /app/internal/quantum/database/migrations /app/migrations
COPY --from=builder /app/cmd/quantum-auth/config /app/cmd/quantum-auth/config

EXPOSE 1042

USER qa
ENV HOME=/home/qa
ENV GOMODCACHE=/tmp/go-mod

ENTRYPOINT ["/app/qa-server"]
