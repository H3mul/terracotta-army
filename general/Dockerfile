FROM python:3.12-slim
RUN useradd --create-home --uid 1000 tg
WORKDIR /app
COPY general/ ./
# Stub: install by hash-pinned lockfile once dependencies are real.
RUN pip install --no-cache-dir .
USER tg
ENTRYPOINT ["terracotta-general"]
