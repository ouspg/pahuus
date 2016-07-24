FROM ubuntu:14.04

RUN apt-get update && \
 apt-get install -y software-properties-common python-software-properties && \
 add-apt-repository -y ppa:oisf/suricata-stable && \
 apt-get update && apt-get install -y \
 suricata \
 python-requests \
 && rm -rf /var/lib/apt/lists/*

#RUN cd /etc/suricata && wget -q https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz -O - | tar -xz
#RUN cp /etc/suricata/rules/suricata-1.3-open.yaml /etc/suricata/suricata.yaml
RUN sed -i \
  -e 's/^ - emerging-policy.rules/## policy/' \
  -e 's/^ - dns-events.rules/## dns-events/' \
  -e 's/^\s*- flow/## - flow/' \
  -e 's/^\s*HOME_NET: ".*"/    HOME_NET: "any"/' \
  -e 's/^\s*EXTERNAL_NET: "!$HOME_NET"/    EXTERNAL_NET: "any"/' \
    /etc/suricata/suricata.yaml && touch /etc/suricata/threshold.config

RUN sed -i \
  -e 's/ !$DNS_SERVERS / any /g' /etc/suricata/rules/*

RUN useradd -m tester
run touch /var/log/suricata.log && chown -R tester /var/log/suricata /var/log/suricata.log
USER tester

COPY runner.sh /home/tester/

ENTRYPOINT ["bash", "/home/tester/runner.sh"]
