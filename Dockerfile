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
# ORDER MATTERS HERE, and it bit once already.
#
# The distroless stage is LAST on purpose: `docker build .` with no `--target`
# builds the final stage, so whichever stage sits at the bottom is what an
# unqualified build produces. With the browser stage appended at the end,
# `docker build .` quietly started producing the 1 GB browser image under the
# default tag, and `docker image ls` reporting the same size for both is what
# gave it away. The variant is opt-in, so it goes above.

# --------------------------------------------------------------------------
# The browser variant, and it is a SEPARATE image on purpose.
# --------------------------------------------------------------------------
#
# `SCOPYX_BACKEND=chromium` drives a browser the operator installed. The image
# above has none, deliberately: it is distroless and about 12 MB, and a
# governance component that put 500 MB of somebody else's browser on every box
# whether or not they wanted rendering would be answering a question nobody
# asked.
#
# So the browser lives here, under its own tag, and the default stays what it
# was. An operator who wants rendering opts in by pulling a different image,
# which is a decision with a size attached rather than a surprise.
#
# WHY DEBIAN AND NOT ALPINE
#
# Chromium on musl exists and is a different browser in the ways that matter
# here: different sandbox behaviour, different crash modes, and a much smaller
# set of people who have run it in anger. This plane's job is to be predictable
# about what a browser does, so it runs the build most of the world runs.
#
# THE SANDBOX IS NOT DISABLED HERE
#
# No `SCOPYX_CHROMIUM_NO_SANDBOX` in this image. On a host whose kernel gives
# Chrome the user namespaces its renderer sandbox needs, it works, and an image
# that turned it off would take that away from everybody to make one platform
# easier. Where it cannot initialise, the DEPLOYMENT decides, visibly, and the
# error names both ways out.
FROM debian:bookworm-slim AS browser
LABEL org.opencontainers.image.title="scopyx (with a browser)"
LABEL org.opencontainers.image.description="scopyx plus Chromium, for SCOPYX_BACKEND=chromium. The default image ships no browser on purpose."
LABEL org.opencontainers.image.source="https://github.com/TAIPANBOX/scopyx"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# `--no-install-recommends` is load-bearing rather than tidy: the recommends of
# chromium pull a desktop's worth of packages, and every one of them is more
# code on the box that reaches the open web.
# The trims below are measured rather than folklore. Before them this layer was
# 714 MB and the image 1.13 GB; each line names what it removes and why that is
# safe for a headless renderer that never draws a window.
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium ca-certificates fonts-liberation \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/lib/chromium/libVkLayer_khronos_validation.so \
 && rm -rf /usr/share/icons /usr/share/doc /usr/share/man /usr/share/locale \
 && rm -rf /usr/share/X11 /usr/share/mime \
 && groupadd -g 65532 nonroot \
 && useradd -u 65532 -g 65532 -M -s /usr/sbin/nologin nonroot \
 && mkdir -p /var/lib/scopyx \
 && chown 65532:65532 /var/lib/scopyx

VOLUME ["/var/lib/scopyx"]
COPY --from=build /out/scopyx /usr/local/bin/service

# Named rather than searched. `cdp.Find` would look on PATH and find the same
# binary, and saying it here means a base image that renames or moves chromium
# fails at startup with a message about the browser instead of at the first
# fetch with a message about the network.
ENV SCOPYX_CHROMIUM=/usr/bin/chromium

# HOME, and without it v0.1.1 could not render on a real node at all.
#
# `useradd -M` creates no home directory, so HOME pointed at /home/nonroot,
# which does not exist. Pointing HOME at a directory that is not there is wrong
# in any container, and in a k3s pod on EC2 it was fatal: Chromium died before
# opening anything, with
#
#   chrome_crashpad_handler: --database is required
#   Trace/breakpoint trap (core dumped)
#
# which says nothing about a home directory.
#
# WHAT IS MEASURED AND WHAT IS NOT, because the difference matters here.
#
# Measured on an EC2 node, 2026-08-10: with HOME=/home/nonroot every fetch
# failed exactly as above; with HOME=/tmp the same pod rendered pages of up to
# 343 subresources. That is the fix, and it is the fix on the machine that
# failed.
#
# NOT reproduced locally. The same amd64 image under `docker run` renders with
# the old HOME, with a read-only root filesystem, with all capabilities
# dropped, with no-new-privileges, and as uid 65532. So the precise trigger is
# something else about that node's runtime, and it is not isolated. The fix
# stands on its own regardless: HOME must name a directory that exists and is
# writable.
#
# /tmp is the one path guaranteed writable in every deployment of this image: a
# tmpfs in compose, an emptyDir in Kubernetes under a read-only root
# filesystem, and the container's own writable layer under a plain `docker
# run`.
ENV HOME=/tmp

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]

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
