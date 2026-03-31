# ── Stage 1: Build ────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /tlsmask .

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /tlsmask /usr/local/bin/tlsmask

EXPOSE 8080

ENTRYPOINT ["tlsmask"]
CMD ["--port", "8080", "--verbose"]
