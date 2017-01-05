#!/bin/sh
nohup  dumpcap -i 4 -b duration:3600 -q  -w /captures/pcap/cm.pcap -f 'host 192.168.10.75 or port 554' > /dev/null &
