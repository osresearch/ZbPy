# Zigbee Application Support Layer packet parser
#   IEEE802154
#   ZigbeeNetwork (NWK)
#   (Optional encryption, with either Trust Center Key or Transport Key)
#-> ZigbeeApplicationSupport (APS)
#   ZigbeeClusterLibrary (ZCL)

MODE_UNICAST = 0x0
MODE_BROADCAST = 0x2
MODE_GROUP = 0x3

FRAME_TYPE_DATA = 0x0
FRAME_TYPE_ACK = 0x1

class ZigbeeApplication:

	# parse the ZigBee Application packet
	# src/dst are endpoints
	def __init__(self,
		data = None,
		frame_type = FRAME_TYPE_DATA,
		mode = MODE_UNICAST,
		src = 0,
		dst = 0,
		cluster = 0,
		profile = 0,
		seq = 0,
		payload = None,
		ack_req = False,
	):
		if data is not None:
			self.deserialize(data)
		else:
			self.frame_type = frame_type
			self.mode = mode
			self.src = src
			self.dst = dst
			self.cluster = cluster
			self.profile = profile
			self.seq = seq
			self.ack_req = ack_req
			self.payload = payload

	def __str__(self):
		params = [
			"frame_type=" + str(self.frame_type),
			"cluster=0x%04x" % (self.cluster),
			"profile=0x%04x" % (self.profile),
			"mode=" + str(self.mode),
			"seq=" + str(self.seq),
			"src=0x%02x" % (self.src),
		]

		if self.mode == MODE_GROUP:
			params.append("dst=0x%04x" % (self.dst))
		else:
			params.append("dst=0x%02x" % (self.dst))

		if self.ack_req:
			params.append("ack_req=1")

		params.append("payload=" + str(self.payload))

		return "ZigbeeApplication(" + ", ".join(params) + ")"

	def deserialize(self, b):
		j = 0
		fcf = b[j]; j += 1
		self.frame_type = (fcf >> 0) & 3
		self.mode = (fcf >> 2) & 3
		self.ack_req = (fcf >> 7) & 1

		if self.mode == MODE_GROUP:
			self.dst = (b[j+1] << 8) | (b[j+0] << 0)
			j += 2
		else:
			self.dst = b[j]
			j += 1

		self.cluster = (b[j+1] << 8) | (b[j+0] << 0); j += 2
		self.profile = (b[j+1] << 8) | (b[j+0] << 0); j += 2
		self.src = b[j]; j += 1
		self.seq = b[j]; j += 1

		self.payload = b[j:]

		return self

	def serialize(self):
		hdr = bytearray()
		fcf = 0 \
			| (self.frame_type << 0) \
			| (self.mode << 2) \
			| (self.ack_req << 7)

		hdr.append(fcf)
		if self.mode == MODE_GROUP:
			hdr.append((self.dst >> 0) & 0xFF)
			hdr.append((self.dst >> 8) & 0xFF)
		else:
			hdr.append(self.dst & 0xFF)

		hdr.append((self.cluster >> 0) & 0xFF)
		hdr.append((self.cluster >> 8) & 0xFF)
		hdr.append((self.profile >> 0) & 0xFF)
		hdr.append((self.profile >> 8) & 0xFF)
		hdr.append(self.src)
		hdr.append(self.seq)

		if type(self.payload) is bytes or type(self.payload) is bytearray:
			hdr.extend(self.payload)
		else:
			hdr.extend(self.payload.serialize())

		return hdr


if __name__ == "__main__":
	import AES
	import IEEE802154
	from binascii import hexlify
	from ZigbeeNetwork import ZigbeeNetwork
	nwk_key = b"\x01\x03\x05\x07\x09\x0b\x0d\x0f\x00\x02\x04\x06\x08\x0a\x0c\x0d"
	aes = AES.AES(nwk_key)
	golden = bytearray.fromhex("41883b621affff00004802fdff382b0b432887480400b19de80b004b120000055665c14f13102410078a3d12501ff1")
	ieee = IEEE802154.IEEE802154(data=golden)
	nwk = ZigbeeNetwork(aes=aes, data=ieee.payload)
	ieee.payload = nwk
	golden_aps = nwk.payload
	aps = ZigbeeApplication(data=nwk.payload)
	nwk.payload = aps
	print(ieee)
	round_trip = ieee.serialize()
	if golden != round_trip:
		print("---- bad round trip!")
		print(hexlify(golden_aps))
		print(hexlify(aps.serialize()))

