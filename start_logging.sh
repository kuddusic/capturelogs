#!/bin/bash
nohup tshark -i 4 -o tcp.desegment_tcp_streams:FALSE -Y rtsp -tad -T fields -E separator='|' -e frame.time -e ip.src -e ip.dst -e rtsp.session -e tcp.stream -e rtsp.request -ertsp.status -ertsp.response -ertsp.transport host 192.168.10.75 >> /captures/log/cmlog &
