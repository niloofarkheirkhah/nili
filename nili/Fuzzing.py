#!/usr/bin/python
from netzob.all import *
import time
import sys
import os,socket

	

def Fuzzing(delimiter, command, field, minLength, maxLength, target, port):
	minLen= int(minLength)
	maxLen= int(maxLength)
	field= int(field)
	port= int(port)
	#reverse
	msgs = PCAPImporter.readFile("results.pcap").values()
	symbol = Symbol(messages=msgs)
	Format.splitDelimiter(symbol, ASCII(delimiter))	
	symbols = Format.clusterByKeyField(symbol, symbol.fields[0])
	for s in symbols.values():
		i=0
		while i< len(s.fields):			
			Format.splitAligned(s.fields[i], doInternalSlick=True)
			i+=2
	
	#fuzzing
	if (field == 0):	
		symbols[command].fields[field].fields[field].domain = Raw(nbBytes=( minLen, maxLen))
	else:
		for s in symbols.values():
			s.fields[field].domain= Raw(nbBytes=( minLen, maxLen))

	s = symbols[command]
	print ('[*] Connecting to server...')
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((target,port))
	while (1):
		try:	
			data = s.specialize()
			print ("[*] Sending: {0}\n".format(repr(data)))
			sock.send(data)
			time.sleep(1)
			#rcv = sock.recv(1024)
			#print("{0}\r\n".format(rcv))
			#print ('%s\r\n'%rcv)
		except:
			timestr=time.strftime("%m-%d %H:%M:%S")
			f=open(timestr+'.log','w')
			data=str(data)
			f.write(data)
			f.close()
			print ('[!] Couldn\'t connect..')
			exit(0)
