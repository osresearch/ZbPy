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
		payload = b'',
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

		if type(self.payload) is memoryview \
		or type(self.payload) is bytearray \
		or type(self.payload) is bytes:
			if len(self.payload) != 0:
				params.append("payload=" + str(bytes(self.payload)))
		else:
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
		hdr.append(self.seq & 0x7F)
		hdr.append(self.command)

		if type(self.payload) is bytes or type(self.payload) is bytearray:
			hdr.extend(self.payload)
		else:
			hdr.extend(self.payload.serialize())

		return hdr
