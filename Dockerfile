#build stage
FROM golang:alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o sso ./cmd/sso

#final stage
FROM alpine:latest
WORKDIR /app

COPY --from=builder /app/sso .
COPY --from=builder /app/config ./config

ENV CONFIG_PATH=config/docker.yaml

LABEL Name=sso Version=0.0.1
EXPOSE 44044

CMD ["./sso"]