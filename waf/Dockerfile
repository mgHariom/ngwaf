# Stage 1: Build – install dependencies (needs C compiler for libinjection)
FROM python:3.11-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime – lean image without build tools
FROM python:3.11-slim

COPY --from=builder /install /usr/local
WORKDIR /app
COPY . .

EXPOSE 8000

# Single worker – the async event loop handles concurrency.
# Multiple workers would each get their own in-memory log queue.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]
