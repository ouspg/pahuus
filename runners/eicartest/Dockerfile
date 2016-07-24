FROM ubuntu:14.04

RUN apt-get update && apt-get install -y \
 python-scapy \
 python-requests \
 wget \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m tester
USER tester

COPY runner.sh /home/tester/
COPY eicartest.py /home/tester/

ENTRYPOINT ["/bin/bash", "/home/tester/runner.sh", "/home/tester/eicartest.py"]
