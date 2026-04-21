# RestoreRunner — upload an Unraid backup, boot the captured container,
# tail its logs, one click to stop.

# --- build stage -----------------------------------------------------------
FROM golang:1.26-bookworm AS build

ARG VERSION=dev
ARG COMMIT=none
ARG BUILDTIME=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" \
    -o /out/restorerunner \
    ./cmd/restorerunner

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/TehRobot-Assistant/restore-runner"
LABEL org.opencontainers.image.description="Upload an Unraid AppData backup and boot the captured container in a sandbox"
LABEL org.opencontainers.image.licenses="MIT"

# Unraid UI hints — make the WebUI link work on the Docker tab.
LABEL net.unraid.docker.webui="http://[IP]:[PORT:8922]"
LABEL net.unraid.docker.icon="https://raw.githubusercontent.com/TehRobot-Assistant/restore-runner/master/icon.png"

# p7zip-full covers RAR (via bundled unRAR), zip, and 7z read. tar + zstd
# are only runtime utilities if someone execs into the container; the Go
# binary uses stdlib + klauspost/compress/zstd directly. ca-certificates
# + wget are for healthchecks and TLS against docker registries.
RUN apt-get update && apt-get install -y --no-install-recommends \
      p7zip-full \
      tar \
      zstd \
      ca-certificates \
      wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /config

# NOTE: no docker CLI. We use the Go client talking directly to the
# socket, which saves ~250 MB of transitive deps.

COPY --from=build /out/restorerunner /usr/local/bin/restorerunner

WORKDIR /config

EXPOSE 8922

VOLUME ["/config"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8922/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/restorerunner"]
