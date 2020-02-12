# Top level interface to the ZbPy Zigbee stack for
# the EFM32 micropython port.
try:
	import Radio
	import machine
	from ubinascii import hexlify, unhexlify
	from ZbPy import Parser, ZCL

	Radio.init()
	Radio.promiscuous(True)
	machine.zrepl(False)
except:
	print("ZbPy failed to import")

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
		ieee, typ = Parser.parse(pkt, filter_dupes=True)
		if typ is None:
			continue

		if typ != "zcl":
			if typ == "zcl?" and ieee.payload.payload.cluster != 0:
				print(ieee)
			continue

		#print(ieee)
		#cluster = ieee.payload.payload.cluster
		# IEEE/NWK/APS/ZCL/ZCL
		zcl = ieee.payload.payload.payload.payload
		#print(ieee)
		print(zcl)


handlers = {}

def bind(name, handler):
	global handlers;
	cluster_id, command_id = ZCL.lookup(name)
	if cluster_id not in handlers:
		handlers[cluster_id] = {}
	handlers[cluster_id][command_id] = handler

def loop():
	while True:
		pkt = Radio.rx()
		if pkt is None:
			continue
		ieee, typ = Parser.parse(pkt, filter_dupes=True)
		if typ != "zcl":
			continue

		try:
			cluster = ieee.payload.payload.cluster
			#              NWK     APS     ZCL     ZCL
			payload = ieee.payload.payload.payload.payload
			command = payload.command

			#print(cluster, command)

			if cluster not in handlers:
				continue
			if command not in handlers[cluster]:
				continue

			handlers[cluster][command](payload)
		except:
			print("Handler failed")
			raise

