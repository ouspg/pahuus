#!/bin/bash

runner="$1"
pcapfile="$2"

tmp="$(tempfile)"

wget -q "$pcapfile" -O "$tmp"

python $runner "$tmp"
