FROM python:3.12-slim
RUN pip install --no-cache-dir starlette uvicorn httpx pyjwt cryptography
WORKDIR /stub
COPY general/tests/fake_github.py tests/integration/stub/server.py ./
CMD ["python", "server.py"]
