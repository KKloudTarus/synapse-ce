# Multi-stage, multi-TARGET build for Synapse.
#
#   --target api  (DEFAULT) → lean distroless image: the API server + CLI + syft + grype.
#                             SCA (SBOM + OSV/Grype vulns + licenses) works; the JVM-from-source
#                             resolvers + git acquisition do NOT (no jdk/mvn/gradle/git in distroless).
#   --target full           → batteries-included (Debian + JDK 17 + Maven + Gradle + git): every SCA
#                             feature works, incl. Maven/Gradle transitive resolution and JVM
#                             reachability, and git-clone acquisition. Used by docker-compose.full.yml.
#
# NOTE on the sandbox: heavy/untrusted tool execution (E9) is confined by bubblewrap, which needs a Linux
# host + user namespaces (and, for egress scoping E12, CAP_NET_ADMIN). A plain container cannot run it, so
# these images default to SANDBOX-OFF (dev). On the API server the Maven/Gradle resolvers are fail-closed
# without the sandbox (they run untrusted build logic) → use `synapse-cli scan` (trusted-local, unsandboxed)
# for full JVM SCA from a container, or deploy on a bubblewrap-capable Linux host to enable the API path.

FROM golang:1.26.4-alpine AS build
WORKDIR /src
# Copy module files first for better layer caching.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/synapse-api ./cmd/synapse-api
# synapse-cli is bundled too so the image doubles as a cross-platform scanner
# (`docker run … synapse-cli scan /scan`) – the SCA path runs identically on any host
# that runs Linux containers (Windows/macOS via Docker Desktop, Linux natively).
RUN CGO_ENABLED=0 go build -trimpath -o /out/synapse-cli ./cmd/synapse-cli

# Pinned SCA tool binaries, shelled out at runtime.
FROM anchore/syft:v1.45.1 AS syft
FROM anchore/grype:v0.115.0 AS grype

# ---------------------------------------------------------------------------
# target: full – batteries-included SCA platform (JVM toolchain + git).
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
    # arch-independent JAVA_HOME: resolve wherever `java` actually points (amd64/arm64 differ).
    && ln -s "$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")" /opt/java-home \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /home/synapse synapse \
    && mkdir -p /home/synapse/.m2 /home/synapse/.gradle \
    && chown -R synapse:synapse /home/synapse
COPY --from=build /out/synapse-api /usr/local/bin/synapse-api
COPY --from=build /out/synapse-cli /usr/local/bin/synapse-cli
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
ENV SYNAPSE_SYFT_BIN=/usr/local/bin/syft \
    SYNAPSE_GRYPE_BIN=/usr/local/bin/grype \
    SYNAPSE_MVN_BIN=/usr/bin/mvn \
    SYNAPSE_GRADLE_BIN=/usr/local/bin/gradle \
    JAVA_HOME=/opt/java-home
EXPOSE 8080
USER synapse:synapse
# tini reaps the child processes mvn/gradle/syft spawn.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/synapse-api"]

# ---------------------------------------------------------------------------
# target: api (DEFAULT – last stage) – minimal, non-root, distroless.
# distroless/static has no git/jdk/mvn/gradle; the `local` kind + SBOM generation
# + OSV/Grype vulns + licenses work here. `make docker-build` builds this stage.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build /out/synapse-api /synapse-api
COPY --from=build /out/synapse-cli /synapse-cli
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=grype /grype /usr/local/bin/grype
ENV SYNAPSE_SYFT_BIN=/usr/local/bin/syft
ENV SYNAPSE_GRYPE_BIN=/usr/local/bin/grype
EXPOSE 8080
USER nonroot:nonroot
# Default to the API server; override for a one-off scan, e.g.:
#   docker run --rm -v "$PWD:/scan:ro" <image> /synapse-cli scan /scan --mode licenses
ENTRYPOINT ["/synapse-api"]
