#!/usr/bin/python
from netzob.all import *
import time
import sys
import os,socket
#from itertools import *
import random


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

	fuzzdata = [[] for i in range(len(symbols[command].fields))]
	for x in range (len(symbols[command].fields)):
		for y in range (len(symbols[command].fields[x].getValues())):
			value = symbols[command].fields[x].getValues()[y]
			flag = 0
			for z in range(len(fuzzdata[x])):		
				if (fuzzdata[x][z] == value):
					flag = 1
			if (flag == 0):
				fuzzdata[x].append(value)

	#fuzzing
	print ('[*] Connecting to server...\n')
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((target,port))
	attacks = [FormatString, IntegerOverflow, SQLinjection, SpecialStrings,BufferOverflow]
	for i in range(len(attacks)):
		fuzzdata = attacks[i](fuzzdata, field)
		counter = len(fuzzdata[field])
		for c in range(counter):
			data = b''
			for x in range(len(symbols[command].fields)):
				if x == field:
					data += bytearray(fuzzdata[x][c])
				else:
					data += bytearray(random.choice(fuzzdata[x]))
			print ("[*] Sending: {0}\n".format(repr(data)))
			try:
				sock.send(data)
				time.sleep(1)
				
				#rcv = sock.recv(1024)
				#print("{0}\r\n".format(rcv))
				#print ('%s\r\n'%rcv)
			except KeyboardInterrupt:
				print("\n[!] Keyboard Interrupt!")
				exit(0)
			except:
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((target,port))
					sock.send(data)
					time.sleep(1)
				except:

					timestr=time.strftime("%m-%d %H:%M:%S")
					f=open(timestr+'.log','w')
					data=str(data)
					f.write(data)
					f.close()
					print ('[!] Couldn\'t Connect..\n')
					print ('[!] Possible Vulnerability: {}\n'.format(attacks[i]))
					exit(0)

def BufferOverflow(fuzzdata, field):
	counter = 0
	for length in [128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2, 99999, 100000, 500000, 1000000]:
		for character in ["A", "B", "1", "2", "3", ">", "<", "'", "\"", "/", "\\", "?", "=", "a=", "&", ".", ",", "(", ")", "[", "]", "%", "*", "-", "+", "{", "}", "\x14", "\xFE", "\xFF"]:		
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata


def BufferOverflow(fuzzdata, field):
	counter = 0
	for length in [128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2, 99999, 100000, 500000, 1000000]:
		for character in ["A", "B", "1", "2", "3", ">", "<", "'", "\"", "/", "\\", "?", "=", "a=", "&", ".", ",", "(", ")", "[", "]", "%", "*", "-", "+", "{", "}", "\x14", "\xFE", "\xFF"]:		
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata

def FormatString(fuzzdata, field):
	counter = 0
	for length in [1, 2, 3, 4, 5, 31, 32, 33, 63, 64, 65, 127, 128, 129]:
		for character in ["%n","\"%n\"","%s","\"%s\""]:		
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata

def IntegerOverflow(fuzzdata, field):
	counter = 0
	for length in [1, 2, 3, 4, 5, 31, 32, 33, 63, 64, 65, 127, 128, 129]:
		for character in ["-1","0","0x100","0x1000","0x3fffffff","0x7ffffffe","0x7fffffff","0x80000000","0xfffffffe","0xffffffff", "0x10000", "0x100000"]:
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata

def SQLinjection(fuzzdata, field):
	counter = 0
	for length in [1, 2, 3, 4, 5, 31, 32, 33, 63, 64, 65, 127, 128, 129]:
		for character in ["<>", ";", "|", "--", "*|", "*/*","0","031003000270000", "0 or 1=1", "1;SELECT%20*","OR%201=1"]:
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata

def SpecialStrings(fuzzdata, field):
	counter = 0
	for length in [1, 2, 3, 4, 5, 31, 32, 33, 63, 64, 65, 127, 128, 129]:
		for character in ["/.:/", "\x00\x00", "/.../", "\x00\x00", "/...", "..:","\\\\*","\\\\?\\","/\\" ,"/." ,"!@#$%%^#$%#$@#$%$$@#$%^^**(()","%01%02%03%04%0a%0d%0aADSF","%01%02%03@%04%0a%0d%0aADSF", "/%00/","%00/","%00","%u0000","%\xfe\xf0%\x00\xff", "%\xfe\xf0%\x01\xff"]:
			try:
				fuzzdata[field][counter] = (length * character).encode()
			except:
				fuzzdata[field].append((length * character).encode())
			counter += 1
	return fuzzdata

