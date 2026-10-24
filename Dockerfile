FROM python:3.12-slim
WORKDIR /app
# docker CLI: the blue agent's actuator tools (kill_process/isolate_egress/quarantine/
# rotate_secret) + service_status shell out to `docker` against the mounted host socket.
# Client only; the daemon is the host's. ponytail: client in the app image is fine for a
# local demo — prod should split this into an actuator sidecar (actuator.py already flags it).
RUN apt-get update && apt-get install -y --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x entrypoint-proxy.sh
