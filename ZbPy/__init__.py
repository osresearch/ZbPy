from ZbPy import IEEE802154
from binascii import hexlify, unhexlify

try:
	import Radio
	Radio.pan(0x1a62)
except:
	print("import Radio failed")

seq = 99

def beacon(tx=Radio.tx):
	global seq
	seq = (seq + 1) & 0x1F

	tx(IEEE802154.IEEE802154(
		frame_type = IEEE802154.FRAME_TYPE_CMD,
		command = IEEE802154.COMMAND_BEACON_REQUEST,
		seq = seq,
		dst = 0xFFFF,
		dst_pan = 0xFFFF,
	).serialize())

def data(tx=Radio.tx, pan=Radio.pan(), dst=0x0000, src=Radio.mac()):
	global seq
	seq = (seq + 1) & 0x1F

	tx(IEEE802154.IEEE802154(
		frame_type = IEEE802154.FRAME_TYPE_CMD,
		command = IEEE802154.COMMAND_DATA_REQUEST,
		seq = seq,
		dst = dst,
		dst_pan = pan,
		src = src,
		src_pan = pan,
		ack_req = True,
	).serialize())

def join(tx=Radio.tx, pan=Radio.pan(), dst=0x0000, mac = Radio.mac()):
	global seq
	seq = (seq + 1) & 0x1F

	tx(IEEE802154.IEEE802154(
		frame_type = IEEE802154.FRAME_TYPE_CMD,
		command = IEEE802154.COMMAND_JOIN_REQUEST,
		seq = seq,
		src = mac,
		src_pan = pan, #0xFFFF,
		dst = dst,
		dst_pan = pan,
		ack_req = True,
		payload = b'\x80',
	).serialize())

def sniff(rx=Radio.rx):
	while True:
		pkt = rx()
		if pkt is None:
			continue
		print(IEEE802154.parse(pkt))
	
