# Workspace image. Build from the repo root: docker build -f workspace/Dockerfile .
# Pin the base by digest at release time (ta-repo-layout 4.1).
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates python3-minimal curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash agent \
    && mkdir -p /workspace/dev /workspace/openspec && chown -R agent /workspace
COPY workspace/bin/ /usr/local/bin/
COPY workspace/etc/gitconfig /etc/gitconfig
COPY contract/VERSION /usr/local/share/terracotta/CONTRACT_VERSION
# Never prompt: a denial must end in the broker's hint, not a password prompt.
ENV GIT_TERMINAL_PROMPT=0
USER agent
WORKDIR /workspace
