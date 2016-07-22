FROM ubuntu:14.04

RUN apt-get update && apt-get install -y \
 python-scapy \
 python-requests \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m tester
USER tester

COPY eicartest.py /home/tester/eicartest.py

ENTRYPOINT ["python", "/home/tester/eicartest.py"]
