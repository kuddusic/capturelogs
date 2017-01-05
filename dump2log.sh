#!/bin/bash
working=`pgrep dump2log.sh | wc -l`
echo $working
date
if [ $working -gt 2 ] ; then
        echo "Dump2Log is Active. Exiting ..."
	exit 0
fi

capture_path="/captures/pcap/"
log_path="/captures/log/"
script_path="/captures/scripts/"


for f in `find $capture_path -amin +21 -name '*.pcap' -printf "%T@ %Tc %p\n" | sort -n | awk -F" " '{print $9}' | head -n 5000`
do
	fn=$(basename $f)
	sfn=${fn:10}
/usr/local/bin/tshark -r $f -Y"xml"  -X lua_script:"/captures/scripts/kdecode.lua" -X lua_script1:data-text-lines   -X lua_script1:xml -o tcp.desegment_tcp_streams:TRUE -tad -T fields -Eseparator='|' -E aggregator='~'  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.stream -e http.request.method -e http.request.full_uri -e http.header.SOAPAction -e http.response.code -e extract.string  >> $log_path$sfn.log	
	date
	echo "Finished logdump"
	/usr/bin/gzip $log_path$sfn.log
	/usr/bin/gzip $f
#	mv $f $f".old"
#	add automatic deleting rules like find xargs rm -f
#	find $capture_path -mtime +15 -name '*.gz' | xargs rm -f
#	find $log_path -mtime +15 -name '*.gz' | xargs rm -f

done
date
echo "Finished whole job"
