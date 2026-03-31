FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
COPY deps/ deps/
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tlsmask .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /tlsmask /usr/local/bin/tlsmask

EXPOSE 2255
ENTRYPOINT ["tlsmask"]
CMD ["--port", "2255", "--verbose"]
