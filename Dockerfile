# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum (if it exists)
COPY go.mod go.sum* ./
# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o secret-detector cmd/secret-detector/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates in case the tool needs to make HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from the build stage
COPY --from=builder /app/secret-detector .

# Default command
ENTRYPOINT ["./secret-detector"]
