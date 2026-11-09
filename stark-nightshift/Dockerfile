# Stark Nightshift - web / networking challenge
# Single image, single container, single exposed port.
# Pure standard library: no pip install, no apt, no downloaded binaries.

FROM python:3.11-alpine
WORKDIR /app

COPY src/gatekeeper.py src/bridge.py ./
COPY src/static ./static

# Flag is injected by the platform at deploy time. Never bake a value in here.
RUN chmod 700 /app \
    && touch /flag.txt && chmod 600 /flag.txt

# Only the bridge (web console + WebSocket relay) is exposed. gatekeeper.py binds
# 127.0.0.1:9000 and is reachable solely from the bridge inside this container.
EXPOSE 8080
CMD ["sh", "-c", "python3 gatekeeper.py & exec python3 bridge.py"]
