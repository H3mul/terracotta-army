FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir starlette uvicorn httpx pyjwt cryptography
WORKDIR /stub
COPY general/tests/fake_github.py tests/integration/stub/server.py ./
COPY policy-seed /seed
CMD ["python", "server.py"]
