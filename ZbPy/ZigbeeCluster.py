# Zigbee Cluster Library packet parser
#   IEEE802154
#   ZigbeeNetwork (NWK)
#   (Optional encryption, with either Trust Center Key or Transport Key)
#   ZigbeeApplicationSupport (APS)
#-> ZigbeeClusterLibrary (ZCL)

# "Cluster" is a horrible name for a mesh network protocol - it implies
# something about groups of nodes, but is Zigbee-speak for groups of commands.
# The commands are split into different groups for things like On/Off, Level control,
# OTA updates, etc.

FRAME_TYPE_CLUSTER_SPECIFIC = 1
DIRECTION_TO_SERVER = 0
DIRECTION_TO_CLIENT = 1

class ZigbeeCluster:

	def __init__(self,
		data = None,
		frame_type = FRAME_TYPE_CLUSTER_SPECIFIC,
		direction = DIRECTION_TO_SERVER,
		manufacturer_specific = False,
		disable_default_response = False,
		seq = 0,
		command = 0,
		payload = None,
	):
		if data is not None:
			self.deserialize(data)
		else:
			self.frame_type = frame_type
			self.direction = direction
			self.seq = seq
			self.disable_default_response = disable_default_response
			self.manufacturer_specific = manufacturer_specific
			self.command = command
			self.payload = payload

	def __str__(self):
		params = [
			"command=0x%02x" % (self.command),
			"seq=%d" % (self.seq),
			"direction=%d" % (self.direction),
		]

		if self.disable_default_response:
			params.append("disable_default_response=1")
		if self.manufacturer_specific:
			params.append("manufacturer_specific=1")

		params.append("payload=" + str(self.payload))

		return "ZigbeeCluster(" + ", ".join(params) + ")"

	def deserialize(self, b):
		j = 0
		fcf = b[j]; j += 1
		self.frame_type = (fcf >> 0) & 3
		self.manufacturer_specific = (fcf >> 2) & 1
		self.direction = (fcf >> 3) & 1
		self.disable_default_response = (fcf >> 4) & 1

		self.seq = b[j]; j += 1
		self.command = b[j];  j += 1
		self.payload = b[j:]

		return self

	def serialize(self):
		hdr = bytearray()
		fcf = 0 \
			| (self.frame_type << 0) \
			| (self.manufacturer_specific << 2) \
			| (self.direction << 3) \
			| (self.disable_default_response << 4)

		hdr.append(fcf)
		hdr.append(self.seq)
		hdr.append(self.command)

		if type(self.payload) is bytes or type(self.payload) is bytearray:
			hdr.extend(self.payload)
		else:
			hdr.extend(self.payload.serialize())

		return hdr


if __name__ == "__main__":
	from binascii import hexlify
	import AES
	import IEEE802154
	import ZigbeeNetwork
	import ZigbeeApplication
	import ZigbeeCluster
	nwk_key = b"\x01\x03\x05\x07\x09\x0b\x0d\x0f\x00\x02\x04\x06\x08\x0a\x0c\x0d"
	aes = AES.AES(nwk_key)
	# this is a bad cluster 36
	#data = bytearray(b'A\x88\xc6b\x1a\xff\xff\x00\x00\x08\x02\xfc\xff\x00\x00\x1e\xed(\x97\n\x05\x00\xb1\x9d\xe8\x0b\x00K\x12\x00\x004\x042v\x18Q\x9a\xf4N\x14I\xb8\x0bE\x8c')
	data = bytearray.fromhex('418832621affff00004802fdffe36a0bf02803090500b19de80b004b12000021f091dad0985b9dc5e081a8a3282618e177b8be')
	ieee = IEEE802154.IEEE802154(data=data)
	print(ieee)
	nwk = ZigbeeNetwork.ZigbeeNetwork(aes=aes, data=ieee.payload)
	ieee.payload = nwk
	print(nwk)
	aps = ZigbeeApplication.ZigbeeApplication(data=nwk.payload)
	nwk.payload = aps
	print(aps)
	golden_zcl = aps.payload
	zcl = ZigbeeCluster.ZigbeeCluster(data=aps.payload)
	aps.payload = zcl
	print(zcl)
	round_trip = zcl.serialize()
	if round_trip != golden_zcl:
		print("ZCL BAD ROUND TRIP")
	print(hexlify(golden_zcl))
	print(hexlify(round_trip))
	round_trip = ieee.serialize()
	if round_trip != data:
		print("FULL BAD ROUND TRIP")
	print(hexlify(data))
	print(hexlify(round_trip))
