FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
COPY deps/ deps/
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o /tlsmask .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /tlsmask /usr/local/bin/tlsmask

ENV TLSMASK_DATA_DIR=/data
VOLUME /data

EXPOSE 2255 2256

ENV TLSMASK_UI_ADDR=0.0.0.0:2256

ENTRYPOINT ["tlsmask"]
CMD []
