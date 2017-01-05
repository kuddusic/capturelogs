#!/bin/sh
nohup /usr/local/bin/dumpcap -i 4 -b duration:1200 -q  -w /captures/pcap/big.pcap  -f 'port 8080' > /dev/null 2>&1 &
