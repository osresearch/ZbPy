# Zigbee packet parser
# IEEE802154
# ZigbeeNetwork (NWK)
# (Optional encryption, with either Trust Center Key or Transport Key)
# ZigbeeApplicationSupport (APS)
# ZigbeeClusterLibrary (ZCL)

# Zigbee Trust Center key: 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39

# Not properly supported:
# * Multicast
# * Route discovery
# * Source routing
FRAME_TYPE_DATA = 0
FRAME_TYPE_CMD = 1
FRAME_TYPE_RESERVED = 2
FRAME_TYPE_PAN = 3

CMD_ROUTE_REQUEST	= 0x01
CMD_ROUTE_REPLY		= 0x02
CMD_NETWORK_STATUS	= 0x03
CMD_LEAVE		= 0x04
CMD_ROUTE_RECORD	= 0x05
CMD_REJOIN_REQUEST	= 0x06
CMD_REJOIN_RESPONSE	= 0x07
CMD_LINK_STATUS		= 0x08
CMD_NETWORK_REPORT	= 0x09
CMD_NETWORK_UPDATE	= 0x0a

from ZbPy import CCM

class ZigbeeNetwork:

	# parse the ZigBee network layer
	def __init__(self,
		data = None,
		frame_type = FRAME_TYPE_DATA,
		version = 2,
		discover_route = 1,
		multicast = 0,
		source_route = 0,
		src = 0,
		dst = 0,
		radius = 1,
		seq = 0,
		ext_src = None,
		ext_dst = None,
		payload = b'',
		security = False,
		sec_seq = 0,
		sec_key = 0,
		sec_key_seq = 0,
		aes = None,
		validate = True,
	):
		self.aes = aes
		self.validate = validate

		if data is not None:
			self.deserialize(data)
		else:
			self.frame_type = frame_type
			self.version = version
			self.source_route = source_route
			self.discover_route = discover_route
			self.multicast = multicast
			self.radius = radius
			self.payload = payload
			self.seq = seq
			self.src = src
			self.dst = dst
			self.ext_src = ext_src
			self.ext_dst = ext_dst

			self.security = security
			self.sec_seq = sec_seq
			self.sec_key = sec_key
			self.sec_key_seq = sec_key_seq
			self.valid = True # since we have a cleartext payload

	def __str__(self):
		params = [
			"frame_type=" + str(self.frame_type),
			"version=" + str(self.version),
			"radius=" + str(self.radius),
			"seq=" + str(self.seq),
			"dst=0x%04x" % (self.dst),
			"src=0x%04x" % (self.src),
		]

		if self.ext_src is not None:
			params.append("ext_src=" + str(bytes(self.ext_src)))

		if self.source_route != 0:
			params.append("source_route=1")
		if self.multicast != 0:
			params.append("multicast=1")
		if self.discover_route == 0:
			params.append("discover_route=0")

		if self.security:
			params.extend([
				"security=1",
				"sec_seq=" + str(bytes(self.sec_seq)),
				"sec_key=" + str(self.sec_key),
				"sec_key_seq=" + str(self.sec_key_seq),
			])
			if not self.valid:
				params.append("valid=FALSE")

		if type(self.payload) is memoryview \
		or type(self.payload) is bytearray \
		or type(self.payload) is bytes:
			if len(self.payload) != 0:
				params.append("payload=" + str(bytes(self.payload)))
		else:
			params.append("payload=" + str(self.payload))

		return "ZigbeeNetwork(" + ", ".join(params) + ")"

	# Create an object from bytes on a wire
	def deserialize(self, b):
		j = 0
		fcf = (b[j+1] << 8) | (b[j+0] << 0); j += 2
		self.frame_type		= (fcf >> 0) & 3
		self.version		= (fcf >> 2) & 15
		self.discover_route	= (fcf >> 6) & 3
		self.multicast		= (fcf >> 8) & 1
		self.security		= (fcf >> 9) & 1
		self.source_route	= (fcf >> 10) & 1
		dst_mode		= (fcf >> 11) & 1
		src_mode		= (fcf >> 12) & 1

		self.dst = (b[j+1] << 8) | (b[j+0] << 0); j += 2
		self.src = (b[j+1] << 8) | (b[j+0] << 0); j += 2
		self.radius = b[j]; j += 1
		self.seq = b[j]; j += 1

		self.ext_dst = None
		self.ext_src = None

		# extended dest is present
		if dst_mode:
			self.ext_dst = b[j:j+8]
			j += 8

		# extended source is present
		if src_mode:
			self.ext_src = b[j:j+8]
			j += 8

		if not self.security:
			# the rest of the packet is the payload
			self.payload = b[j:]
		else:
			# security header is present, attempt to decrypt
			# and validate the message.
			try:
				self.ccm_decrypt(b, j)
			except:
				print("---- BAD CCM ----")
				self.valid = False
				self.payload = b[j:]
		return self

	# Convert an object back to bytes, with optional encryption
	def serialize(self):
		hdr = bytearray()
		fcf = 0 \
			| (self.frame_type << 0) \
			| (self.version << 2) \
			| (self.discover_route << 6) \
			| (self.multicast << 8) \
			| (self.security << 9) \
			| (self.source_route << 10)
		hdr.append(0) # FCF will be filled in later
		hdr.append(0)
		hdr.append((self.dst >> 0) & 0xFF)
		hdr.append((self.dst >> 8) & 0xFF)
		hdr.append((self.src >> 0) & 0xFF)
		hdr.append((self.src >> 8) & 0xFF)
		hdr.append(self.radius)
		hdr.append(self.seq & 0x7F)
		if self.ext_dst is not None:
			hdr.extend(self.ext_dst)
			fcf |= 1 << 11
		if self.ext_src is not None:
			hdr.extend(self.ext_src)
			fcf |= 1 << 12

		if type(self.payload) is bytes or type(self.payload) is bytearray:
			payload = self.payload
		else:
			payload = self.payload.serialize()

		# fill in the updated field control field
		hdr[0] = (fcf >> 0) & 0xFF
		hdr[1] = (fcf >> 8) & 0xFF

		if not self.security:
			hdr.extend(payload)
			return hdr
		else:
			fcf |= 1 << 9
			return self.ccm_encrypt(hdr, payload)

	# security header is present; b contains the entire Zigbee NWk header
	# so that the entire MIC can be computed
	def ccm_decrypt(self, b, j):
		# the security control field is not filled in correctly in the header,
		# so it is necessary to patch it up to contain ZBEE_SEC_ENC_MIC32
		# == 5. Not sure why, but wireshark does it.
		sec_hdr = b[j]
		sec_hdr = (sec_hdr & ~0x07) | 0x05
		b[j] = sec_hdr # modify in place
		j += 1
		self.sec_key = (sec_hdr >> 3) & 3
		self.sec_seq = b[j:j+4] ; j += 4

		# 8 byte ieee address, used in the extended nonce
		if sec_hdr & 0x20: # extended nonce bit
			self.ext_src = b[j:j+8]
			j += 8
		else:
			# hopefully the one in the header was present
			self.ext_src = None

		# The key seq tells us which key is used;
		# should always be zero?
		self.sec_key_seq = b[j] ; j += 1

		# section 4.20 says extended nonce is
		# 8 bytes of IEEE address, little endian
		# 4 bytes of counter, little endian
		# 1 byte of patched security control field
		nonce = bytearray(16)
		nonce[0] = 0x01
		nonce[1:9] = self.ext_src
		nonce[9:13] = self.sec_seq
		nonce[13] = sec_hdr # modified sec hdr!
		nonce[14] = 0x00
		nonce[15] = 0x00

		# authenticated data is everything up to the message
		# which includes the network header and the unmodified sec_hdr value
		auth = b[0:j]
		C = b[j:-4]  # cipher text
		M = b[-4:]   # message integrity code

		if not CCM.decrypt(auth, C, M, nonce, self.aes, validate=self.validate):
			print("BAD DECRYPT: ", bytes(b))
			#print("message=", C)
			self.payload = C
			self.valid = False
		else:
			self.payload = C
			self.valid = True

	# Re-encrypt a message and return the security header plus encrypted payload and MIC
	def ccm_encrypt(self, hdr, payload):
		sec_hdr = (0x05 << 0) \
			| (self.sec_key << 3) \
			| (1 << 5)
		sec_hdr_offset = len(hdr) # for updates later
		hdr.append(sec_hdr)
		hdr.extend(self.sec_seq)
		hdr.extend(self.ext_src) # should be only if we have a ext_src, but it has better be there
		hdr.append(self.sec_key_seq)

		nonce = bytearray(16)
		nonce[0] = 0x01
		nonce[1:9] = self.ext_src
		nonce[9:13] = self.sec_seq
		nonce[13] = sec_hdr
		nonce[14] = 0x00
		nonce[15] = 0x00

		mic = CCM.encrypt(hdr, payload, nonce, self.aes)

		# payload is encrypted in place
		hdr.extend(payload)
		hdr.extend(mic)

		# for WTF reasons, they don't send the MIC parameters in the header.
		hdr[sec_hdr_offset] = sec_hdr & ~7

		return hdr
