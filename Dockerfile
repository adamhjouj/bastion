FROM python:3.12-slim AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x entrypoint-proxy.sh

# The actuator sidecar is the ONLY image that carries docker-cli.
# The model container (blue) and the proxy container are built from the base stage,
# which has no Docker CLI and mounts no socket.
FROM base AS actuator
RUN apt-get update && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
