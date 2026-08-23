# Multi-stage image build for Synapse.
#
# Targets retained for local development:
#   --target api   minimal distroless API image
#   --target full  Debian development image with JVM dependency resolvers
# Production:
#   --target production  non-root API/worker/migrate image with sandbox helpers and tools
#
# The production target is Linux/amd64 because Synapse's seccomp filter is built for
# linux/amd64. Its Kubernetes workload must also permit unprivileged user namespaces
# for bubblewrap; it does not require privileged mode, SYS_ADMIN, or added capabilities.

FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/synapse-api ./cmd/synapse-api \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-worker ./cmd/synapse-worker \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-sandbox-check ./cmd/synapse-sandbox-check \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-migrate ./cmd/synapse-migrate \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-dast-helper ./cmd/synapse-dast-helper \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-callgraph ./cmd/synapse-callgraph \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-cspm ./cmd/synapse-cspm \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-cli ./cmd/synapse-cli \
    && CGO_ENABLED=0 go build -trimpath -o /out/synapse-verify-restore ./cmd/synapse-verify-restore \
    && mkdir -p /out/project-uploads /out/project-source-artifacts

# The tree-sitter helper is CGO-linked, so build it against Debian glibc for the
# Debian production runtime rather than copying an Alpine/musl-linked executable.
FROM golang:1.26.6-trixie AS ast-build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /out/synapse-ast ./cmd/synapse-ast

# Pinned SCA tools are copied as standalone binaries.
FROM anchore/syft:v1.45.1 AS syft
FROM anchore/grype:v0.115.0 AS grype

# ---------------------------------------------------------------------------
# target: full – batteries-included local-development SCA image.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS full
ARG GRADLE_VERSION=8.10.2
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         openjdk-17-jdk-headless maven git ca-certificates curl unzip tini \
    && curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && ln -s "/opt/gradle-${GRADLE_VERSION}/bin/gradle" /usr/local/bin/gradle \
    && rm -f /tmp/gradle.zip \
    && ln -s "$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")" /opt/java-home \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /home/synapse synapse \
    && mkdir -p /home/synapse/.m2 /home/synapse/.gradle /home/synapse/project-source-artifacts \
    && chown -R synapse:synapse /home/synapse
COPY --from=build /out/synapse-api /usr/local/bin/synapse-api
COPY --from=build /out/synapse-dast-helper /usr/local/bin/synapse-dast-helper
COPY --from=build /out/synapse-cli /usr/local/bin/synapse-cli
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
ENV SYNAPSE_SYFT_BIN=/usr/local/bin/syft \
    SYNAPSE_GRYPE_BIN=/usr/local/bin/grype \
    SYNAPSE_MVN_BIN=/usr/bin/mvn \
    SYNAPSE_GRADLE_BIN=/usr/local/bin/gradle \
    SYNAPSE_PROJECT_UPLOAD_DIR=/home/synapse/project-uploads \
    SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR=/home/synapse/project-source-artifacts \
    JAVA_HOME=/opt/java-home
EXPOSE 8080
USER synapse:synapse
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/synapse-api"]

# ---------------------------------------------------------------------------
# target: api – minimal local-development API image (the historical default).
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build /out/synapse-api /synapse-api
COPY --from=build /out/synapse-dast-helper /synapse-dast-helper
COPY --from=build /out/synapse-cli /synapse-cli
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=build --chown=nonroot:nonroot /out/project-uploads /project-uploads
COPY --from=build --chown=nonroot:nonroot /out/project-source-artifacts /project-source-artifacts
ENV SYNAPSE_SYFT_BIN=/usr/local/bin/syft \
    SYNAPSE_GRYPE_BIN=/usr/local/bin/grype \
    SYNAPSE_PROJECT_UPLOAD_DIR=/project-uploads \
    SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR=/project-source-artifacts
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/synapse-api"]

# ---------------------------------------------------------------------------
# target: production – hardened control-plane runtime.
#
# Debian supplies bwrap. Synapse creates its seccomp BPF program itself, so no
# libseccomp runtime is needed. The OCI/Kubernetes runtime must enable
# unprivileged user namespaces for bwrap; no privileged container or SYS_ADMIN
# capability is used or required.
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS production
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         bubblewrap ca-certificates git tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 synapse \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/synapse --shell /usr/sbin/nologin synapse \
    && install -d -o synapse -g synapse -m 0750 \
         /var/lib/synapse/project-uploads \
         /var/lib/synapse/project-source-artifacts \
         /var/lib/synapse/cache
COPY --from=build /out/synapse-api /opt/synapse/synapse-api
COPY --from=build /out/synapse-worker /opt/synapse/synapse-worker
COPY --from=build /out/synapse-sandbox-check /opt/synapse/synapse-sandbox-check
COPY --from=build /out/synapse-migrate /opt/synapse/synapse-migrate
COPY --from=build /out/synapse-dast-helper /opt/synapse/synapse-dast-helper
COPY --from=build /out/synapse-callgraph /opt/synapse/synapse-callgraph
COPY --from=build /out/synapse-cspm /opt/synapse/synapse-cspm
COPY --from=ast-build /out/synapse-ast /opt/synapse/synapse-ast
COPY --from=build /out/synapse-cli /opt/synapse/synapse-cli
COPY --from=build /out/synapse-verify-restore /opt/synapse/synapse-verify-restore
COPY --from=syft /syft /opt/synapse/syft
COPY --from=grype /grype /opt/synapse/grype
RUN chown -R synapse:synapse /opt/synapse
ENV PATH=/opt/synapse:/usr/bin:/bin \
    HOME=/home/synapse \
    SYNAPSE_SYFT_BIN=/opt/synapse/syft \
    SYNAPSE_GRYPE_BIN=/opt/synapse/grype \
    SYNAPSE_DAST_HELPER_BIN=/opt/synapse/synapse-dast-helper \
    SYNAPSE_CSPM_HELPER_BIN=/opt/synapse/synapse-cspm \
    SYNAPSE_TAINT_CALLGRAPH_BIN=/opt/synapse/synapse-callgraph \
    SYNAPSE_PROJECT_UPLOAD_DIR=/var/lib/synapse/project-uploads \
    SYNAPSE_PROJECT_SOURCE_ARTIFACT_DIR=/var/lib/synapse/project-source-artifacts
WORKDIR /home/synapse
EXPOSE 8080
USER synapse:synapse
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/synapse/synapse-api"]
