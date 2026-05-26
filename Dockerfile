FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ais-monitor .

FROM alpine:3.18
WORKDIR /root/
COPY --from=builder /app/ais-monitor .
COPY conf.ini .
RUN mkdir -p Archive
CMD ["./ais-monitor"]
