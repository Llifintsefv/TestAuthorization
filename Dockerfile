FROM golang:1.23-alpine AS builder 

WORKDIR /app  

COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify
   
COPY . .
    
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/auth-service ./cmd/main.go
    
FROM alpine:latest
    
WORKDIR /app   

COPY --from=builder /app/auth-service /app/auth-service
  
EXPOSE 8080
   
CMD ["/app/auth-service"]