# --- Build stage ---
FROM golang:1.20-alpine AS builder
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o proxy .

# --- Final stage ---
FROM alpine:3.16
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /app/proxy .

EXPOSE 443

CMD ["./proxy"]
