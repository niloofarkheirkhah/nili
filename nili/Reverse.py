
#!/usr/bin/python
from netzob.all import *


def Reverse(delimiter):	
	msgs = PCAPImporter.readFile("results.pcap").values()
	symbol = Symbol(messages=msgs)	
	print ("\n[*][1] Regroup messages in a symbol and do a format partitionment with the delimiter:")
	Format.splitDelimiter(symbol, ASCII(delimiter))
	print ("\n[*] Partitionned messages:")
	print (symbol)
	print ("\n[*][2] Cluster according to the key field:")
	symbols = Format.clusterByKeyField(symbol, symbol.fields[0])
	print ("\n[*] Number of commands after clustering: {0}".format(len(symbols)))
	print ("[*] Command list:")
	for keyFieldName, s in symbols.items():
		print ("	- {0}".format(keyFieldName))
	
	print ("\n[*][3] Apply a format partitionment with a sequence alignment on every fields of the symbol:")
	for s in symbols.values():
		i=0
		while i< len(s.fields):			
			Format.splitAligned(s.fields[i], doInternalSlick=True)
			i+=2
		print ("\n[*] Partitionned messages:")
		print (s)
