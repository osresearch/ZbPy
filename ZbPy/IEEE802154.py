# Process IEEE 802.15.4 packets and return an unpacked form of them

FRAME_TYPE_BEACON = 0x0
FRAME_TYPE_DATA = 0x1
FRAME_TYPE_ACK = 0x2
FRAME_TYPE_CMD = 0x3

COMMAND_JOIN_REQUEST = 0x01
COMMAND_JOIN_RESPONSE = 0x02
COMMAND_DATA_REQUEST = 0x04
COMMAND_BEACON_REQUEST = 0x07

class IEEE802154:
	# Construct an IEEE802154 packet either from individual parts
	# or from a byte stream off the radio passed in as data.
	def __init__(self,
		frame_type = 0,
		src = None,
		dst = None,
		src_pan = None,
		dst_pan = None,
		seq = 0,
		command = 0,
		payload = b'',
		ack_req = False,
		data = None
	):
		if data is None:
			self.frame_type = frame_type
			self.ack_req = ack_req
			self.src = src
			self.dst = dst
			self.src_pan = src_pan
			self.dst_pan = dst_pan
			self.seq = seq
			self.payload = payload
			self.command = command
		else:
			self.deserialize(data)

	# parse an incoming 802.15.4 message
	def deserialize(self,b):
		j = 0
		fcf = b[j+0] << 0 | b[j+1] << 8
		j += 2
		self.frame_type = (fcf >> 0) & 0x7
		self.ack_req = ((fcf >> 5) & 1) != 0
		dst_mode = (fcf >> 10) & 0x3
		src_mode = (fcf >> 14) & 0x3
		self.src = None
		self.dst = None
		self.dst_pan = None
		self.src_pan = None
		self.command = None

		self.seq = b[j]
		j += 1

		if dst_mode != 0:
			# Destination pan is always in the message
			self.dst_pan = (b[j+0] << 0) | (b[j+1] << 8)
			j += 2
			if dst_mode == 2:
				# short destination addresses
				self.dst = b[j+0] << 0 | b[j+1] << 8
				j += 2
			elif dst_mode == 3:
				# long addresses
				self.dst = b[j:j+8]
				j += 8
			else:
				throw("Unknown dst_mode %d" % (dst_mode))

		if src_mode != 0:
			if (fcf >> 6) & 1:
				# pan compression, use the dst_pan
				self.src_pan = self.dst_pan
			else:
				# pan is in the message
				self.src_pan = b[j+0] << 0 | b[j+1] << 8
				j += 2

			if src_mode == 2:
				# short source addressing
				self.src = b[j+0] << 0 | b[j+1] << 8
				j += 2
			elif src_mode == 3:
				# long source addressing
				self.src = b[j:j+8]
				j += 8
			else:
				throw("Unknown src_mode %d" % (src_mode))

		if self.frame_type == FRAME_TYPE_CMD:
			self.command = b[j]
			j += 1

		# the rest of the message is the payload for the next layer
		self.payload = b[j:]

		return self

	def serialize(self):
		hdr = bytearray()
		hdr.append(0) # FCF will be filled in later
		hdr.append(0)
		hdr.append(self.seq & 0x7F)

		fcf = self.frame_type & 0x7
		if self.ack_req:
			fcf |= 1 << 5 # Ack request

		# Destination address mode
		if self.dst_pan is not None:
			hdr.append((self.dst_pan >> 0) & 0xFF)
			hdr.append((self.dst_pan >> 8) & 0xFF)
			if type(self.dst) is int:
				# short addressing, only 16-bits
				fcf |= 0x2 << 10
				hdr.append((self.dst >> 0) & 0xFF)
				hdr.append((self.dst >> 8) & 0xFF)
			elif self.dst is not None:
				# long address, should be 8 bytes
				if len(self.dst) != 8:
					throw("dst address must be 8 bytes")
				fcf |= 0x3 << 10
				hdr.extend(self.dst)

		# Source address mode; can be ommitted entirely
		if self.src is not None:
			if self.src_pan is None or self.src_pan == self.dst_pan:
				fcf |= 1 << 6 # Pan ID compression
			else:
				hdr.append((self.src_pan >> 0) & 0xFF)
				hdr.append((self.src_pan >> 8) & 0xFF)

			if type(self.src) is int:
				# short address, only 16-bits
				fcf |= 0x2 << 14
				hdr.append((self.src >> 0) & 0xFF)
				hdr.append((self.src >> 8) & 0xFF)
			else:
				# long address, should be 8 bytes
				if len(self.src) != 8:
					throw("src address must be 8 bytes")
				fcf |= 0x3 << 14
				hdr.extend(self.src)

		# add in the frame control field
		hdr[0] = (fcf >> 0) & 0xFF
		hdr[1] = (fcf >> 8) & 0xFF

		if self.frame_type == FRAME_TYPE_CMD:
			hdr.append(self.command)

		if type(self.payload) is memoryview \
		or type(self.payload) is bytearray \
		or type(self.payload) is bytes:
			hdr.extend(self.payload)
		else:
			hdr.extend(self.payload.serialize())

		return hdr


	# parse an IEEE802.15.4 command
	def cmd_parse(self, b):
		cmd = b.u8()
		if cmd == 0x04:
			self.payload = "Data request"
		elif cmd == 0x07:
			self.payload = "Beacon request"
		else:
			self.payload = "Command %02x" % (cmd)

	def __str__(self):
		params = [
			"frame_type=" + str(self.frame_type),
			"seq=" + str(self.seq),
		]

		if self.frame_type == FRAME_TYPE_CMD:
			params.append("command=0x%02x" % (self.command))

		if self.ack_req:
			params.append("ack_req=1")

		if type(self.dst) is int:
			params.append("dst=0x%04x" % (self.dst))
		elif type(self.dst) is not None:
			params.append("dst=" + str(self.dst))
		if type(self.dst_pan) is int:
			params.append("dst_pan=0x%04x" % (self.dst_pan))

		if type(self.src) is int:
			params.append("src=0x%04x" % (self.src))
		elif type(self.src) is not None:
			params.append("src=" + str(self.src))
		if type(self.src_pan) is int:
			params.append("src_pan=0x%04x" % (self.src_pan))

		if type(self.payload) is memoryview \
		or type(self.payload) is bytearray \
		or type(self.payload) is bytes:
			if len(self.payload) != 0:
				params.append("payload=" + str(bytes(self.payload)))
		else:
			params.append("payload=" + str(self.payload))

		return "IEEE802154(" + ", ".join(params) + ")"
