#/usr/bin/env python

import threading
import sys
import subprocess
import Queue
import time

USAGE = "USAGE: >DNS_analysis.py <.pcap> [.pcap...]" 

# From passed in .pcap file, filter out all of the packets of passed in protocal: pcap_protocol 
def Extract_Protocol(pcap_file, pcap_protocol, tshark_out_queue):
	print ("[*] Examining {0}...".format(pcap_file))
	try:
		tshark_out_str = subprocess.check_output(["tshark", "-t","r", "-r", pcap_file, "-R", pcap_protocol])
	except:
		print "Error running tshark command"
	output_list = tshark_out_str.split('\n')
	tshark_out_queue.put(output_list)

#These simple Traffic analysis exist because for whatever reason I can not get a proper tshark quere
#This function is simple, do not pass it pcap data, send it the tshark stdout 
## INPUT
###	tshark_str - tshark stdout output, this function assumes the str text has not been split yet
# 
## OUTPUT
### The URL that client was requesting from the DNS server 
def Extract_DNS_Query_Dict(tshark_str):
	
	result_dict = {}

	for traffic_str in tshark_str:

		if traffic_str.find('Standard query 0x') != -1:
			#This line of traffic hsa been determined to be of the type
			#Client to Server traffic direction, so continue...
			url_index = traffic_str.find('A ') + 2
		
			if url_index != -1:
				#timestamp = traffic_str.split(' ')[1]
				requested_url = traffic_str[url_index:].strip()
				if requested_url in result_dict:
					#(old_count, timestamp_list) = result_dict[requested_url] 
					#result_dict[requested_url] = ( old_count + 1, timestamp_list + [timestamp] )
					result_dict[requested_url] += 1
				else:
					#result_dict[requested_url] = (1, [timestamp]) 
					result_dict[requested_url] = 1
	return result_dict



#This function is simple, do not pass it pcap data, send it the tshark stdout 
#def Extract_DNS_Query_Response_Simple(client2server_string, tshark_str):


if __name__=='__main__':
	print len(sys.argv)
	if len(sys.argv) < 2:
		print USAGE
		exit()
	result_queue = Queue.Queue()
	#This part works!
	for pcap_file in sys.argv[1:]:
		t = threading.Thread(target=Extract_Protocol, args=(pcap_file, "dns", result_queue)) 
		t.daemon = True
		t.start()
	
	while threading.active_count() > 1:
		time.sleep(1)			

	#TEMP sectional code driver
	#file_txt = open('tshark_DNS_out.txt').readlines()
	#result_queue.put(file_txt)
	#END_TEMP

	tshark_out = []
	while not result_queue.empty():	
		pcap_string = result_queue.get()
		print len(pcap_string)
		tshark_out += pcap_string
		#print pcap_string
	print "[*] Pcap lines read in..........[{0}]".format(len(tshark_out))
	result_dict = Extract_DNS_Query_Dict(tshark_out)
	
	print "[*] Unique URLs found...........[{0}]".format(len(result_dict.keys()))
	print "\n---- Unique URLs and times requested ----\n"
	for url in result_dict.keys():
		#(count, _) = result_dict[url]
		count = result_dict[url]
		print "\t{0}...................[{1}]".format(url, count)

	first_url = result_dict.keys()[0]
	'''print "Timestamps from {0}:\n".format(first_url)
	(_,times) = result_dict[first_url] 
	for time in times:
		print "\t{0}".format(time)
	'''