# The Impostor Resolver - web / DNS challenge
# One image, one process, one exposed port.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt

COPY src/server.py .
COPY src/templates ./templates
COPY src/static ./static

# Static flag, same for every player.
RUN printf '%s' 'flag{v3nt_dns_c4ch3_p0is0n1ng}' > /flag.txt && chmod 644 /flag.txt

EXPOSE 5000
CMD ["python", "server.py"]
