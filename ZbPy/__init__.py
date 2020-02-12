# Top level interface to the ZbPy Zigbee stack for
# the EFM32 micropython port.
import Radio
import machine
from ubinascii import hexlify, unhexlify
from ZbPy import Parser

Radio.init()
Radio.promiscuous(True)
machine.zrepl(False)

def sniff():
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		# throw away the extra b' and ' on the string
		# representation
		x = repr(hexlify(pkt))[2:-1]
		print(x)

def parse():
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		ieee, type = Parser.parse(pkt)

		if type != "zcl":
			continue

		print(ieee)
		cluster = ieee.payload.payload.cluster
		print(cluster, ": ", ieee.payload.payload.payload)

