# RestoreRunner — continuous backup verification.
#
# Shape matches tehrobot/patch-pulse / docker-manager: simple, runs as root
# inside the container, single /config data volume. Security comes from
# compose-level constraints (read_only, cap_drop, no-new-privileges) +
# the fact that the only sensitive thing we touch is the user's backup
# repo, accessed via the password they supplied through the web UI.

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

# --- restic install stage --------------------------------------------------
# The restic binary is the core of what we do — install a pinned version
# matching TARGETARCH so the arm64 image genuinely contains arm64 restic.
FROM debian:bookworm-slim AS restic-install

ARG RESTIC_VERSION=0.17.3
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates bzip2 \
    && rm -rf /var/lib/apt/lists/*

RUN RESTIC_ARCH="${TARGETARCH:-amd64}" \
    && curl -sSfL \
        "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${RESTIC_ARCH}.bz2" \
        -o /tmp/restic.bz2 \
    && bunzip2 /tmp/restic.bz2 \
    && install -m 0755 /tmp/restic /usr/local/bin/restic \
    && rm -f /tmp/restic /tmp/restic.bz2

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/TehRobot-Assistant/restore-runner"
LABEL org.opencontainers.image.description="Continuous backup verification — captures a baseline of your source files, then periodically pulls a sample from the backup and hashes it byte-for-byte against the baseline."
LABEL org.opencontainers.image.licenses="MIT"

# Unraid UI hints — surface WebUI link + icon on the Docker tab even when
# the user added the image via the blank "Add Container" form (no CA
# template). Tokens expanded by Unraid at render time.
LABEL net.unraid.docker.webui="http://[IP]:[PORT:8920]"
LABEL net.unraid.docker.icon="https://raw.githubusercontent.com/TehRobot-Assistant/restore-runner/main/icon.png"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      apprise \
      openssh-client \
      wget \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /config

# restic binary (pinned, multi-arch).
COPY --from=restic-install /usr/local/bin/restic /usr/local/bin/restic

# Our binary.
COPY --from=build /out/restorerunner /usr/local/bin/restorerunner

WORKDIR /config

EXPOSE 8920

# Intentionally no ENV RR_CONFIG_DIR / RR_PORT — the binary defaults to
# /config and 8920, and declaring them here causes Unraid to surface them
# as redundant container variables alongside the volume + port mapping.

VOLUME ["/config"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8920/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/restorerunner"]
