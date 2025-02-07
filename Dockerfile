FROM golang:1.23-bullseye AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o proxy .

# --- Final stage ---
FROM alpine:3.16
RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=builder /app/proxy .

EXPOSE 443
CMD ["./proxy"]
