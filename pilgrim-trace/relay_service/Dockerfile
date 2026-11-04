FROM python:3.11-alpine

RUN touch /flag.txt

COPY relay_server.py /app/relay_server.py
WORKDIR /app

EXPOSE 9000

CMD ["python", "relay_server.py"]
