#/usr/bin/env python 
import threading
import sys
import subprocess
import Queue
import time

USAGE = "USAGE: $./{0} <.pcap file> [ Additional .pcap files]".format(sys.argv[0])


def Extract_Unique_DST_addresses(pcap_file, dst_address_dict):
	print ("[*] Examining {0}...".format(pcap_file))
	try:
		tshark_out_str = subprocess.check_output(["tshark", "-r", pcap_file])
		print "{0} lines read in!".format(len(tshark_out_str))
		for str_line in tshark_out_str.split('\n'):
			print str_line
			dst_str_index = str_line.find('->')
			if dst_str_index != -1:
					dst_address = str_line[dst_str_index + 3:].split()[0]
					print dst_address
					dst_address_dict[dst_address] = True
	except:
		print "Error running tshark command"
	
if __name__=='__main__':
	if len(sys.argv) < 2:
		print USAGE
		exit()

	dst_address_dict = {}
	
	pcap_file_list = sys.argv[1:]
	for pcap_file in pcap_file_list:
		t = threading.Thread(target=Extract_Unique_DST_addresses, args=(pcap_file, dst_address_dict)) 
		t.daemon = True
		t.start()

	while threading.active_count() > 1:
		time.sleep(1)
	print "Finished."
	print "\n---- DST IP addresses ----\n"
	for address in dst_address_dict.keys():
		print address