# 1. Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Install build tools for SQLite (CGO is required)
RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Enable CGO for SQLite and build the binary
#RUN ls -la /app && exit 1
RUN CGO_ENABLED=1 GOOS=linux go build -o main ./cmd/server

# 2. Run Stage (Tiny image)
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .

# Expose port 8080
EXPOSE 8080

# Run the binary
CMD ["./main"]