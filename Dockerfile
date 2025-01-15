# Use the latest Golang Alpine image for building the Go app
FROM golang:alpine3.21 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code from the current directory to the Working Directory inside the container
COPY . .

# List files in the container for debugging
RUN ls -R /app

# Build the Go app by specifying the correct path for main.go
RUN go build -o /app/main ./cmd/main.go

# Create a smaller image for running the app
FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/main .

# Expose port 80 to the outside world
EXPOSE 5001

# Command to run the executable
CMD ["./main"]
