# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM golang:1.26.5-bookworm@sha256:18aedc16aa19b3fd7ded7245fc14b109e054d65d22ed53c355c899582bbb2113 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/groupbridge ./cmd/groupbridge \
    && mkdir -p /out/state

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/enel1221/GroupBridge" \
      org.opencontainers.image.description="Keycloak identity groups to GitLab access controller" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/state /var/lib/groupbridge
COPY --from=build /out/groupbridge /groupbridge
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/groupbridge"]
