# Top level interface to the ZbPy Zigbee stack for
# the EFM32 micropython port.
from ubinascii import hexlify, unhexlify
from ZbPy import Parser, ZCL

try:
	import Radio
	import machine
	import gc
	from micropython import mem_info

	Radio.init()
	Radio.promiscuous(True)
	machine.zrepl(False)
except:
	print("ZbPy failed to import efm32 modules")

def sniff():
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		# throw away the extra b' and ' on the string
		# representation
		x = repr(hexlify(pkt))[2:-1]
		print(x)

def parse(verbose=False):
	mem_info()
	gc.collect()
	mem_info()
	count = 0
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		try:
			ieee, typ = Parser.parse(pkt, filter_dupes=True)
			if typ is None:
				continue
		except:
			print(pkt)
			raise

		if typ != "zcl":
			if typ == "zcl?" and ieee.payload.payload.cluster != 0:
				print(ieee)
			continue

		if verbose:
			print(ieee)
		#cluster = ieee.payload.payload.cluster
		# IEEE/NWK/APS/ZCL/ZCL
		zb = ieee.payload.payload.payload
		zcl = zb.payload
		#print(ieee)

		if verbose or zb.command != 0x0B:
			print(zcl)


handlers = {}

def bind(name, handler):
	global handlers;
	cluster_id, command_id = ZCL.lookup(name)
	if cluster_id not in handlers:
		handlers[cluster_id] = {}
	handlers[cluster_id][command_id] = handler

def loop(verbose=False):
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		try:
			ieee, typ = Parser.parse(pkt, filter_dupes=True)
			if typ != "zcl":
				continue
		except:
			print(pkt)
			continue

		try:
			cluster = ieee.payload.payload.cluster
			#              NWK     APS     ZCL     ZCL
			payload = ieee.payload.payload.payload.payload
			command = payload.command

			if verbose:
				print(command)

			if cluster not in handlers:
				continue
			if command not in handlers[cluster]:
				continue

			handlers[cluster][command](payload)
		except:
			print("Handler failed")
			raise

