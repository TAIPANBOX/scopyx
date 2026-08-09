# The enforcement point as a published image.
#
# Published rather than built on the installing machine, which is heraldyx's
# lesson: building from source cost fifteen to forty minutes on a first run and
# put the whole toolchain in the blast radius of an install. What nobody builds,
# nobody breaks.
#
# Static, distroless, non-root, multi-arch. CGO off is what makes the binary
# runnable on distroless static AND what makes cross-compiling to arm64 free:
# there is no C toolchain to arrange, so the arm64 image costs the same as the
# amd64 one.
#
# NEEDS BUILDKIT. `$BUILDPLATFORM` is a BuildKit variable, so the legacy builder
# expands it to nothing and fails with "failed to parse platform". BuildKit is
# the default in Docker 23+ and in Docker Desktop; a host without it needs
# `docker buildx build`, or drop the `--platform=` below and lose only the
# cross-compile.
ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
# Dependencies first, so a code-only change does not re-download the module
# graph on every build.
COPY go.mod go.su[m] ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/scopyx ./cmd/scopyx

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="scopyx"
LABEL org.opencontainers.image.description="A policy enforcement point for agent web egress. Decides each destination before anything leaves, re-decides every redirect, and writes one tamper-evident record."
LABEL org.opencontainers.image.source="https://github.com/TAIPANBOX/scopyx"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# This plane's OWN journal, mounted and never baked. It writes here and never
# into the planes' shared log: a component that mounts the shared log writable
# is one that, once compromised, can corrupt the trail it was adding to. This
# one reaches the internet on purpose, which makes it the last in the estate
# that should be able to rewrite anybody else's record.
VOLUME ["/var/lib/scopyx"]

COPY --from=build /out/scopyx /usr/local/bin/service

# 65532 is distroless's `nonroot` uid. Numeric on purpose: a kubelet with
# runAsNonRoot cannot verify a NAME and refuses the container outright.
USER 65532:65532

# The default bind is loopback, which inside a container reaches nothing. A
# deployment therefore sets SCOPYX_ADDR deliberately, and the moment it does,
# RefuseOpenBind requires credentials with it. That is the intended friction:
# an image that defaulted to 0.0.0.0 would ship the open-proxy posture as the
# easy path.
ENTRYPOINT ["/usr/local/bin/service"]
