# Stark Nightshift - web / networking challenge
# One image, one process group, one exposed port. Standard library only.

FROM python:3.11-alpine
WORKDIR /app

COPY src/gatekeeper.py src/bridge.py ./
COPY src/static ./static

# Static flag, same for every player.
RUN chmod 700 /app && \
    printf '%s' 'flag{wh3n_th3_d00r_f0rg3ts_t0_ch3ck}' > /flag.txt && \
    chmod 600 /flag.txt

# Only the web relay is exposed. gatekeeper.py listens on 127.0.0.1:9000 inside the container.
EXPOSE 8080
CMD ["sh", "-c", "python3 gatekeeper.py & exec python3 bridge.py"]
