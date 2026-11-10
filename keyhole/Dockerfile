# Keyhole - reverse engineering challenge
# Single image, single container, single exposed port.

FROM gcc:13-bookworm AS build
WORKDIR /build
COPY src/keyhole.c .
RUN gcc -O2 -s -static -o keyhole keyhole.c

FROM python:3.11-slim
WORKDIR /app

# unprivileged runtime user
RUN useradd -m -u 10001 player

COPY --from=build /build/keyhole /app/keyhole
COPY src/server.py /app/server.py

# Static flag, same for every player.
RUN printf '%s' 'flag{y0u_r34d_th3_h4nd_wr1t1ng}' > /flag.txt && chmod 644 /flag.txt

RUN chown -R player:player /app
USER player

ENV PORT=1337
EXPOSE 1337

CMD ["python3", "/app/server.py"]
