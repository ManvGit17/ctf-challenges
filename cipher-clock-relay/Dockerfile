# Cipher-Clock Relay - network / forensics challenge
# Raw TCP service on port 8338.

FROM python:3.12-slim
WORKDIR /app

RUN useradd -m ctfuser

COPY src/relay_server.py /app/relay_server.py

# Static flag, same for every player.
RUN printf '%s' 'flag{7h3_cl0ck_n3v3r_l13s_tw1c3}' > /flag.txt && chmod 644 /flag.txt

USER ctfuser
EXPOSE 8338/tcp
ENTRYPOINT ["python", "relay_server.py"]
