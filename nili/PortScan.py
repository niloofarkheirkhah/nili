from __future__ import print_function
import sys
import socket
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.error import Scapy_Exception
from scapy.all import *

def PortScan(destIP, minPort, maxPort):
	print ('[*] Staring Scan on Host {}'.format(destIP))
	print ('[*] Press Ctrl+C to Stop Scanning.')
	srcPort = RandShort()
	minPort = int(minPort)
	maxPort = int(maxPort)
	timeout = 0.0001
	conf.verb = 0
	try:
		for destPort in range(minPort, maxPort):
			stealth_scan_resp = sr1(IP(dst=destIP)/TCP(sport=srcPort,dport=destPort,flags="S"),timeout=timeout)
			#banner = sock.recv(1024)
			#if(str(type(stealth_scan_resp))=="<type 'NoneType'>"): ===> AttributeError: 'NoneType' object has no attribute 'haslayer'
			if(str(type(stealth_scan_resp))=="<class 'NoneType'>"):
				# Filtered
				continue
			elif(stealth_scan_resp.haslayer(TCP)):
				if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
					# Open
					print ('Port {}: OPEN'.format(destPort), end='\n')
					# if banner:
						# print (' - {}'.format(banner))
					send_rst = sr(IP(dst=destIP)/TCP(sport=srcPort,dport=destPort,flags="R"),timeout=timeout)
				elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
					# Closed
					continue
			elif(stealth_scan_resp.haslayer(ICMP)):
				if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					# Filtered
					continue

	except KeyboardInterrupt:
		print('[!] Port Scan Stopped.')
		exit(1)
	print('[*] Port Scan Completed Successfully.')
	exit()
