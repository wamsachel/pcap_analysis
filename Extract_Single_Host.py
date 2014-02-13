#/usr/bin/env
import threading
import sys
import subprocess
import Queue
import time

USAGE = "USAGE: $./{0} <ip address> <.pcap file> [ Additional .pcap files]".format(sys.argv[0])


def Extract_Single_Address(pcap_file, ip_address, out_pcap_file):
	print ("[*] Examining {0} for {1}...".format(pcap_file, ip_address))
	try:
		tshark_out_str = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", 
			"ip.dst == {0}".format(ip_address), "-w", out_pcap_file])
					
	except:
		print "Error running tshark command"
	
if __name__=='__main__':
	if len(sys.argv) < 3:
		print USAGE
		exit()

	ip_address = sys.argv[1]
	in_pcap_file = sys.argv[2]
	out_pcap_file = ip_address + ".pcap"
	dst_address_dict = {}
	
	pcap_file_list = sys.argv[2:]
	for pcap_file in pcap_file_list:
		t = threading.Thread(target=Extract_Single_Address, args=(in_pcap_file, ip_address, out_pcap_file)) 
		t.daemon = True
		t.start()

	while threading.active_count() > 1:
		time.sleep(1)
	print "Finished."
	