FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o odinforge-agent ./cmd/agent/

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY --from=builder /build/odinforge-agent /usr/local/bin/odinforge-agent

RUN chmod +x /usr/local/bin/odinforge-agent

ENV STATELESS=1

ENTRYPOINT ["/usr/local/bin/odinforge-agent"]
