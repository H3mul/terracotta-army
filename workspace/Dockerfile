# Workspace image. Build from the repo root: docker build -f workspace/Dockerfile .
# Everything external is pinned: base by digest, node and mise by checksum, npm tools by lockfile.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS base
ARG NODE_VERSION=v22.23.5
ARG NODE_SHA256=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
ARG MISE_VERSION=v2026.11.9
ARG MISE_SHA256=23ba592fcbc61f057e2b82c1eafd085832712ba0c759b714ca16cd06babca378
# amd64 only for now (the homelab nodes); add the arm64 checksums to build for arm.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates python3 curl openssh-server openssh-client tini xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/node.tar.xz https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz \
    && echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && curl -fsSL -o /tmp/mise.tar.gz https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-linux-x64.tar.gz \
    && echo "${MISE_SHA256}  /tmp/mise.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/mise.tar.gz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tar.xz /tmp/mise.tar.gz \
    && useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /workspace/dev /workspace/openspec /run/sshd /etc/terracotta-workspace \
    && chown -R agent /workspace

# Native modules (node-pty) need a compiler; it stays in this stage and out of the final image.
FROM base AS tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY workspace/tools/ /opt/tools/
# No GPU in the workspace: skip onnxruntime's CUDA download (it 404s and is unwanted anyway).
ENV ONNXRUNTIME_NODE_INSTALL_CUDA=skip
RUN cd /opt/tools && npm ci --no-audit --no-fund \
    # npm installs the musl builds too; this image is glibc, so they are dead weight (~1 GB).
    && find node_modules -maxdepth 2 -type d -name '*-musl' -prune -exec rm -rf {} +

FROM base
COPY --from=tools /opt/tools /opt/tools
RUN for b in claude opencode happier claude-mem bun; do ln -s /opt/tools/node_modules/.bin/$b /usr/local/bin/$b; done \
    && claude --version && opencode --version && happier --version && bun --version && mise --version

COPY workspace/bin/ /usr/local/bin/
COPY workspace/etc/gitconfig /etc/gitconfig
COPY workspace/ssh/sshd_config /etc/terracotta-workspace/sshd_config
COPY contract/VERSION /usr/local/share/terracotta/CONTRACT_VERSION
# Never prompt: a denial must end in the broker's hint, not a password prompt.
ENV GIT_TERMINAL_PROMPT=0
USER agent
WORKDIR /workspace
EXPOSE 2222
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s CMD ["ws-supervisor", "--health"]
ENTRYPOINT ["tini", "--", "ws-supervisor"]
