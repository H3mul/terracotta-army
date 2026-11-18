FROM python:3.12-slim
# The same image runs two containers in the broker pod: `serve` (default) and the operator
# sshd (command: /usr/local/bin/tg-sshd). openssh is present in both; only one container runs it.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/sh tg \
    && mkdir -p /etc/terracotta /var/lib/terracotta-ssh /run/terracotta /run/sshd \
    && chown tg /var/lib/terracotta-ssh /run/terracotta
WORKDIR /app
COPY general/ ./
RUN pip install --no-cache-dir .
COPY general/ssh/sshd_config /etc/terracotta/sshd_config
COPY general/ssh/entrypoint.sh /usr/local/bin/tg-sshd
USER tg
ENTRYPOINT ["terracotta-general"]
CMD ["serve"]
