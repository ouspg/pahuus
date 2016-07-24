#!/bin/bash

pcapurl="$1"

tmp="$(tempfile)"

wget -q "$pcapurl" -O "$tmp"

suricata -c /etc/suricata/suricata.yaml -r "$tmp" >&2

cat /var/log/suricata/eve.json | grep '"event_type":"alert",'
