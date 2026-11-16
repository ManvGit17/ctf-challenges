# The Handshake Skimmer - memory forensics / RE challenge
# One image, one process, one exposed port.

########## Stage 1: build the daemon ##########
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY src/daemon/ ./daemon/
COPY src/build/ ./build/

# Shuffle the sessionSlot struct layout, so every build has different offsets.
RUN python3 build/gen_layout.py

WORKDIR /src/daemon
RUN go mod tidy && go build -buildmode=pie -o /out/microtund .

########## Stage 2: runtime ##########
FROM debian:bookworm-slim

RUN mkdir -p /etc/microtun /var/log/microtun

COPY --from=builder /out/microtund /usr/local/bin/microtund
COPY PROTOCOL.md /etc/microtun/PROTOCOL.md

# Static flag, same for every player.
RUN printf '%s' 'flag{sk1mm3d_th3_k3y_fr0m_1ts_0wn_m3m0ry}' > /flag.txt && chmod 644 /flag.txt

# /dump reads the daemon's own /proc/self/mem, which needs no extra
# capabilities. The HTTP API is the only way in.
EXPOSE 8080
CMD ["/usr/local/bin/microtund"]
