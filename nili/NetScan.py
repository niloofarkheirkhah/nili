from __future__ import print_function
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import struct
import socket
import sys
import os
import time


def NetScan(ipRange, interface='eth0'):
	flag = 0
	for _,c in enumerate(ipRange):
		if(c=='*'):
			flag=1
			break
		if(c=='/'):
			flag=2
			break
	if flag==1:
		arping(ipRange)
		exit()
	if flag==2:
		print('[*] Begin emission:')
		net,_,mask = ipRange.partition('/')
		net = Asc2Dec(net)
		mask = int(mask)
		for ip in (Dec2Asc(net+x) for x in range(1, (1<<32-mask)-1)):
			mac = GetMac(ip, interface)
			if mac:
				print('  {}'.format(mac), end='  ')
				print(ip)
		exit()
	if flag==0:
		print('[!] IP Range is not Valid.')
		exit(1)


def Asc2Dec(asc):
	return struct.unpack('!L',socket.inet_aton(asc))[0]


def Dec2Asc(dec):
	return socket.inet_ntoa(struct.pack('!L',dec))


def GetMac(ip, interface):
	conf.verb = 0
	ans, unans = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(pdst = ip), timeout = 0.01, iface =interface, inter = 0.01)
	for snd,rcv in ans:
		return rcv.sprintf(r'%Ether.src%')
