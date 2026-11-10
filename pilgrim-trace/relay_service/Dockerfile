FROM python:3.11-alpine

RUN printf '%s' 'flag{th3_r1v3r_wh15p3rs_t0_th3_s34}' > /flag.txt

COPY relay_server.py /app/relay_server.py
WORKDIR /app

EXPOSE 9000

CMD ["python", "relay_server.py"]
