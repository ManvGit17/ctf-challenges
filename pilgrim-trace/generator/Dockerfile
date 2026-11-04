# Generates a fresh pilgrims_trace.pcap for a given flag.
# Used by demo.ps1; not part of the live challenge container.
FROM python:3.11-slim
RUN pip install --no-cache-dir scapy==2.5.0
WORKDIR /gen
COPY pilgrim_generate_pcap.py /gen/pilgrim_generate_pcap.py
RUN mkdir /out
ENTRYPOINT ["python", "/gen/pilgrim_generate_pcap.py"]
