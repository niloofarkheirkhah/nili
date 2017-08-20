#!/usr/bin/python
from netzob.all import *
import argparse
import NetScan
import PortScan
import MitM
import Reverse
import Fuzzing

def main():
	print ("""
		      #################################################
		      #       <<<<<< Nili Demo Version >>>>>>         #
		      #      <<<<<< Created on July 2017 >>>>>>       #
		      #     <<<<<< Author: Kheirkhah >>>>>>      #				
		      #################################################
	""") 

	parser = argparse.ArgumentParser(description = '', formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-N','--netscan', help = 'scan the network for devices: (for more help use "-NH")\n-N  -r [range]  -i [interface]', action='store_true')
	parser.add_argument('-P','--portscan', help = 'check the open ports of a device: (for more help use "-PH")\n-P  -t [target] -mp [minPort]  -xp [maxPort]', action='store_true')
	parser.add_argument('-M','--mitm', help = 'man in the middle attack: (for more help use "-MH")\n-M  -t [target]  -g [gateway]  -i [interface]  -f [filter (use BPF syntax)]', action='store_true')
	parser.add_argument('-R','--reverse', help = 'protocol reverse engineering: (for more help use "-RH")\n-R  -d [delimiter]',action='store_true')	
	parser.add_argument('-F','--fuzz', help = 'fuzzing: (for more help use "-FH")\n-F  -d [delimiter]  -c [command]  -l [field]  -ml [minLength]  -xl [maxLength] -t [target]  -p [port]', action='store_true')
	parser.add_argument('-NH','--nh', action='store_true')	
	parser.add_argument('-PH','--ph', action='store_true')
	parser.add_argument('-MH','--mh', action='store_true')
	parser.add_argument('-RH','--rh', action='store_true')
	parser.add_argument('-FH','--fh', action='store_true')
	parser.add_argument('-r','--range')
	parser.add_argument('-i','--interface')
	parser.add_argument('-p','--port')
	parser.add_argument('-t','--target')
	parser.add_argument('-mp','--minPort')
	parser.add_argument('-xp','--maxPort')
	parser.add_argument('-g','--gateway')
	parser.add_argument('-f','--filter')
	parser.add_argument('-d','--delimiter')
	parser.add_argument('-c','--command')
	parser.add_argument('-l','--field')
	parser.add_argument('-ml','--minLength')
	parser.add_argument('-xl','--maxLength')

	p = parser.parse_args()

	# netscan
	if p.netscan and p.range and p.interface:
		NetScan.NetScan(p.range, p.interface)
	# portscan
	elif p.portscan and p.target and p.minPort and p.maxPort:
		PortScan.PortScan(p.target, p.minPort, p.maxPort)
	# man in the meiddle
	elif p.mitm and p.target and p.gateway and p.interface and p.filter:
		MitM.MitM(p.target, p.gateway, p.interface, p.filter)
	# reverse
	if p.reverse:
		Reverse.Reverse(p.delimiter)
	# fuzzing
	elif p.fuzz and p.command and p.field and p.minLength and p.maxLength and p.delimiter and p.target and p.port:
		Fuzzing.Fuzzing(p.delimiter, p.command, p.field, p.minLength, p.maxLength, p.target, p.port)
		
	# Help
	elif p.nh:
		print("network scan help:\n")
		print("nili.py -N  -r [range]  -i [interface]\n")
		print("[range]: ip range \n[interface]: network interface")
		exit(0)

	elif p.ph:
		print("port scan help:\n")
		print("nili.py -P  -t [target] -mp [minPort]  -xp [maxPort]\n")
		print("[target]: target ip \n[minPort]: minimum port to scan \n[maxPort]: maximum port to scan")
		exit(0)

	elif p.mh:
		print("man in the middle attack help:\n")
		print("nili.py -M  -t [target]  -g [gateway]  -i [interface]  -f [filter (use BPF syntax)]\n")
		print("[target]: target ip \n[gateway]: gateway ip \n[interface]: network inteface  \n[filter]: sniffing filter using BPF syntax.\n\t  see BPF documentation at: https://biot.com/capstats/bpf.html. example:\n\t\t-tcp src port 21 and (tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)")
		exit(0)

	elif p.rh:
		print("protocol reverse engineering help:\n")
		print("nili.py -R  -d [delimiter] \n")
		print("[delimiter]: protocol fields delimiter ")
		exit(0)

	elif p.fh:
		print("fuzzing help:\n")
		print("nili.py -F  -d [delimiter]  -c [command]  -l [field]  -ml [minLength]  -xl [maxLength] -t [target]  -p [port]\n")
		print("[delimiter]: protocol fields delimiter \n[command]: specify a protocol command \n[field]: specify a protocol field \n[minLength]: minimum length of fuzzing buffer \n[maxLength]: maximum length of fuzzing buffer \n[target]: target IP  \n[port]: target port ")
		exit(0)

	else:
		parser.print_help()

if __name__=="__main__": main() 
