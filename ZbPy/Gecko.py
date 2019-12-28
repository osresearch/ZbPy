# Silicon Labs Gecko board specific parser and packet sniffer
from micropython import mem_info
from ubinascii import unhexlify, hexlify
import gc

from ZbPy import AES
mem_info()
from ZbPy import IEEE802154
mem_info()
from ZbPy import ZigbeeNetwork
mem_info()
from ZbPy import ZigbeeApplication
mem_info()
from ZbPy import ZigbeeCluster
mem_info()
gc.collect()
mem_info()

import Radio

print("Gecko init")

# This is the "well known" zigbee2mqtt key.
# The Ikea gateway uses a different key that has to be learned
# by joining the network (not yet implemented)
nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
aes = AES.AES(nwk_key)

# Only need one AES object in ECB mode since there is no
# state to track

Radio.init()
seq = 99
pan = 0x1a62
mac_addr = Radio.mac()
nwk_addr = 0xffff
max_spins = 20000


def loop(sniff):
	if sniff:
		Radio.promiscuous(1)

	while True:
		b = Radio.rx()
		if b is None:
			continue

		# discard the weird bytes, not FCS, not sure what they are
		process_packet(b[:-2])

def process_one():
	spins = 0
	while spins < max_spins:
		pkt = process_packet()
		if pkt is not None:
			return pkt
		spins += 1
	return None

def process_packet(data):
	try:
		#print("------")
		#print(data)
		ieee = IEEE802154.IEEE802154(data=data)

		# quick check for ack
		if ieee.ack_req and \
		(((type(ieee.dst) is bytearray) and ieee.dst == mac_addr) \
		or ((ieee.dst is not None) and ieee.dst == nwk_addr)):
			ack(ieee.seq)

		#print(ieee)
		if ieee.frame_type != IEEE802154.FRAME_TYPE_DATA:
			return ieee
		if len(ieee.payload) == 0:
			print(ieee)
			return ieee

		nwk = ZigbeeNetwork.ZigbeeNetwork(data=ieee.payload, aes=aes, validate=False)
		ieee.payload = nwk
		#print(nwk)
		if nwk.frame_type != ZigbeeNetwork.FRAME_TYPE_DATA:
			return ieee

		aps = ZigbeeApplication.ZigbeeApplication(data=nwk.payload)
		nwk.payload = aps
		#print(aps)
		if aps.frame_type != ZigbeeApplication.FRAME_TYPE_DATA:
			return ieee

		# join requests are "special" for now
		if aps.cluster == 0x36:
			return ieee

		zcl = ZigbeeCluster.ZigbeeCluster(data=aps.payload)
		aps.payload = zcl

		print("%02x %04x%c %04x: cluster %04x:%02x/%d" % (
			nwk.seq,
			nwk.src,
			' ' if nwk.src == ieee.src else '+', # repeater
			nwk.dst,
			aps.cluster,
			zcl.command,
			zcl.direction,
		))

		return ieee
	except:
		print(hexlify(data))
		raise

def sniff():
	Radio.promiscuous(True)
	while True:
		bytes = Radio.rx();
		if bytes is None:
			continue
		# throw away the extra two bytes of wtf
		print(hexlify(bytes[:-2]))


beacon_packet = IEEE802154.IEEE802154(frame_type=3, seq=99, command=7, dst=0xffff, dst_pan=0xffff)

def beacon():
	tx(beacon_packet)

def wait_packet(wait_type):
	spins = 0
	while spins < max_spins:
		spins += 1
		b = Radio.rx()
		if b is None:
			continue
		# fast discard
		frame_type = b[0] & 0x7
		if frame_type != wait_type:
			continue
		ieee = IEEE802154.IEEE802154(data=b[:-2])
		print("<--", ieee)
		return ieee
	return None

def tx(msg, wait=True, retries=3):
	print("-->", msg)
	b = msg.serialize()
	for i in range(retries):
		Radio.tx(b)
		if not wait or not msg.ack_req:
			return True

		ack = wait_packet(IEEE802154.FRAME_TYPE_ACK)
		if ack is not None and ack.seq == msg.seq:
			return True
		print("<-- RETRY")
	return False

def discover_pan():
	for i in range(10):
		beacon()
		ieee = wait_packet(IEEE802154.FRAME_TYPE_BEACON)
		if ieee is not None:
			return ieee.src_pan
	return None
	

def leave():
	global seq
	tx(IEEE802154.IEEE802154(
		frame_type=IEEE802154.FRAME_TYPE_DATA,
		seq=seq,
		dst=0x0000,
		dst_pan=pan,
		src=nwk_addr,
		payload=ZigbeeNetwork.ZigbeeNetwork(
			aes=aes,
			frame_type=ZigbeeNetwork.FRAME_TYPE_CMD,
			version=2,
			radius=1,
			seq=12,
			dst=0xfffd,
			src=nwk_addr,
			ext_src=mac_addr,
			discover_route=0,
			security=1,
			sec_seq=bytearray(b'\x00\x00\x00\x00'),
			sec_key=1,
			sec_key_seq=0,
			payload=bytearray(b'\x04\x00')
		),
	))
	seq += 1

def ack(ack_seq):
	tx(IEEE802154.IEEE802154(
		frame_type	= IEEE802154.FRAME_TYPE_ACK,
		seq		= ack_seq
	))

def data_request(src=None):
	global seq
	this_seq = seq
	seq += 1

	if src is None:
		src = nwk_addr
	
	return tx(IEEE802154.IEEE802154(
		frame_type	= IEEE802154.FRAME_TYPE_CMD,
		command		= IEEE802154.COMMAND_DATA_REQUEST,
		ack_req		= True,
		seq		= this_seq,
		src		= src,
		dst		= 0x0000,
		dst_pan		= pan,
		payload		= b'',
	))

def join():
	global seq
	global nwk_addr
	global pan

	Radio.promiscuous(1)

	pan = discover_pan()
	if pan is None:
		print("No PAN received?")
		return False

	print("PAN=0x%04x" % (pan))

	# Send the join request
	if not tx(IEEE802154.IEEE802154(
		frame_type	= IEEE802154.FRAME_TYPE_CMD,
		command		= IEEE802154.COMMAND_JOIN_REQUEST,
		seq		= seq,
		src		= mac_addr,
		src_pan		= 0xFFFF,
		dst		= 0x0000,
		dst_pan		= pan,
		ack_req		= True,
		payload		= b'\x80', # Battery powered, please allocate address
	)):
		print("JOIN_REQUEST: no ack")
		return False
	seq += 1

	if not data_request(src=mac_addr):
		print("DATA_REQUEST: long no ack")
		return False

	assoc = wait_packet(IEEE802154.FRAME_TYPE_CMD)
	if assoc is None:
		print("ASSOCIATE RESPONSE not received?")
		return False
	ack(assoc.seq)

	if assoc.command != IEEE802154.COMMAND_JOIN_RESPONSE:
		print("Not an associate response?")
		return False

	nwk_addr = (assoc.payload[0] << 0) | (assoc.payload[1] << 8)
	status = assoc.payload[2]

	print("New network address 0x%04x status %d" % (nwk_addr, status))
	#Radio.promiscuous(0)
	#Radio.address(nwk_addr, pan)

	#if not data_request():
		#print("DATA_REQUEST: short no ack")

	# try to get the network key
	#for i in range(10):
	print("---- Sending request ----")
	if not data_request():
		print("DATA_REQUEST: short no ack")
	process_one()
		
	#print("Running loop")
	#loop(0)

	return True


def test():
	data = bytearray(unhexlify("41883b621affff00004802fdff382b0b432887480400b19de80b004b120000055665c14f13102410078a3d12501ff1"))
	print(process_packet(data))
