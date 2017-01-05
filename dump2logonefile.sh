#!/bin/bash

capture_path="/captures/pcap/"
log_path="/captures/log2/"
script_path="/captures/scripts/"


	fn=$(basename $1)
	sfn=${fn:9}
/usr/local/bin/tshark -r $1 -Y"xml"  -X lua_script:"/captures/scripts/kdecode.lua" -X lua_script1:data-text-lines   -X lua_script1:xml -o tcp.desegment_tcp_streams:TRUE -tad -T fields -Eseparator='|' -E aggregator='~'  -e frame.time -e ip.src -e ip.dst -e tcp.stream -e http.request.method -e http.request.full_uri -e http.header.SOAPAction -e http.response.code -e extract.string  >> $log_path$sfn.log	
	date
	echo "Finished logdump"
	/usr/bin/gzip $log_path$sfn.log
	#/usr/bin/gzip $f
#	mv $f $f".old"
#	add automatic deleting rules like find xargs rm -f
#	find $capture_path -mtime +15 -name '*.gz' | xargs rm -f
#	find $log_path -mtime +15 -name '*.gz' | xargs rm -f

date
