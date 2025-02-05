# Base Image Golang 1.23
FROM golang:1.23.6

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Docker Local Development
# Set environment variables
# ENV DB_HOST=pgdb
# ENV DB_PORT=5432
# ENV DB_NAME=gosampledb
# ENV DB_USER=postgres
# ENV DB_PASSWORD=123456
# ENV DB_SSLMODE=disable
# ENV DB_TIMEZONE=UTC
# ENV DB_CONNECT_TIMEOUT=5
# ENV JWT_SECRET=verysecret
# ENV JWT_ISSUER=example.com
# ENV JWT_AUDIENCE=example.com
# ENV COOKIE_DOMAIN=localhost
# ENV DOMAIN=example.com
# ENV API_KEY=b41447e6319d1cd467306735632ba733

# Docker on Render
ENV DB_HOST=dpg-cuhln2d6l47c73dt3ns0-a
ENV DB_PORT=5432
ENV DB_NAME=gosampledb_ufiv
ENV DB_USER=gosampledb_user
ENV DB_PASSWORD=AEnD4JifW8ZKLE9G9aMq4AhVk5dLfFOb
ENV DB_SSLMODE=disable
ENV DB_TIMEZONE=UTC
ENV DB_CONNECT_TIMEOUT=5
ENV JWT_SECRET=verysecret
ENV JWT_ISSUER=example.com
ENV JWT_AUDIENCE=example.com
ENV COOKIE_DOMAIN=localhost
ENV DOMAIN=example.com
ENV API_KEY=b41447e6319d1cd467306735632ba733

# Build the Go app
RUN go build -o main ./cmd/api

# Make the executable file
RUN chmod +x main

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]