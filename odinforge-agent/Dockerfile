# Build
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/odinforge-agent ./cmd/agent

# Run
FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/odinforge-agent /app/odinforge-agent
ENV ODINFORGE_SERVER_URL=""
ENV ODINFORGE_AUTH_MODE="api_key"
ENV ODINFORGE_API_KEY=""
ENV ODINFORGE_TENANT_ID="default"
ENV ODINFORGE_QUEUE_PATH="/app/agent.queue.db"
ENTRYPOINT ["/app/odinforge-agent"]
