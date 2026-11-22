# DNSSEC Matrix - web / networking challenge
# One image, one process, one exposed port.

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt

COPY src/ .

# Static flag, same for every player.
RUN printf '%s' 'flag{dn553c_n53c3_w1ldc4rd_w4lk3r}' > /flag.txt && chmod 644 /flag.txt

EXPOSE 8080
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]
