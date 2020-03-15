# Zigbee/IEEE 802.15.4 device
#
#

from ZbPy import AES
from ZbPy import IEEE802154
from ZbPy import ZigbeeNetwork
from ZbPy import ZigbeeApplication
from ZbPy import ZigbeeCluster
from ZbPy import ZCL
from ZbPy import Parser

from binascii import unhexlify, hexlify
from struct import pack, unpack

try:
	from time import ticks_us
except:
	import time
	def ticks_us():
		return int(time.time() * 1e6)


class IEEEDevice:
	data_request_timeout = 1000000 # usec == 100 ms
	retransmit_timeout = 1000000 # usec == 100 ms

	def __init__(self, radio, router = None):
		self.radio = radio
		self.router = router
		self.seq = 0
		self.pending_seq = None
		self.pending_data = None
		self.handler = lambda x: None
		self.seqs = {}

		self.tx_fail = 0
		self.last_data_request = 0
		self.last_tx = 0
		self.join_failed = False

	def rx(self, data):
		if data is None or len(data) < 2: # or len(data) < 2 or len(data) & 1 != 0:
			self.tick()
			return

		try:
			ieee = IEEE802154.IEEE802154(data=data)

			# check for duplicates, using the short address
			# long address duplicates will be processed
			if type(ieee.src) is int:
				if ieee.src in self.seqs \
				and self.seqs[ieee.src] == ieee.seq:
					return

				self.seqs[ieee.src] = ieee.seq

			print("RX: " + str(Parser.parse(data)[0]))

		except Exception as e:
			print("IEEE error: " + str(hexlify(data)))
			raise
			return

		if ieee.frame_type == IEEE802154.FRAME_TYPE_CMD:
			return self.handle_command(ieee)
		elif ieee.frame_type == IEEE802154.FRAME_TYPE_ACK:
			return self.handle_ack(ieee)
		elif ieee.frame_type == IEEE802154.FRAME_TYPE_BEACON:
			return self.handle_beacon(ieee)
		elif ieee.frame_type == IEEE802154.FRAME_TYPE_DATA:
			# for the next layer up, pass it to the handler
			return self.handler(ieee.payload)
		else:
			# should signal a wtf?
			pass


	def tick(self):
		pkt = self.radio.rx()
		if pkt is not None:
			self.rx(pkt)

		now = ticks_us()

		if self.pending_data \
		and now - self.last_data_request > self.data_request_timeout \
		and self.pending_seq is None:
			self.data_request()
			self.last_data_request = now

		if self.pending_seq is None:
			return

		if self.retries == 0:
			# todo: log that the transmit failed to ever be acked
			self.pending_seq = None
			self.tx_fail += 1
			return

		if now - self.last_tx > self.retransmit_timeout:
			print("RETX %02x %d" % (self.pending_seq, self.retries))
			self.last_tx = now
			self.radio.tx(self.last_pkt)
			self.retries -= 1

	def loop(self):
		while True:
			self.tick()

	# Send an ACK for a sequence number, indicating that it has
	# been received by this device (but nothing else about it)
	# This should never be called: the lowest layer in the radio.c
	# sends autoacks
	def ack(self, ack_seq):
		self.radio.tx(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_ACK,
			seq		= ack_seq,
		).serialize())
		#print("ACKING %02x" % (ack_seq))

	# Send a data request to say "yo we're ready for stuff"
	def data_request(self):
		pan = self.radio.pan()
		src = self.radio.address()
		if src is None:
			src = self.radio.mac()

		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_DATA_REQUEST,
			dst		= self.router,
			dst_pan		= pan,
			src		= src,
			src_pan		= pan,
			ack_req		= True,
		))

	# Send a packet from the upper layer, wrapping it with the
	# IEEE 802.15.4 header, setting the flags as requested
	def tx(self, payload, dst = None, ack_req = False, long_addr = False):
		pan = self.radio.pan()
		src = self.radio.address()
		if src is None:
			src = self.radio.mac()

		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_DATA,
			dst		= dst,
			dst_pan		= pan,
			src		= src,
			src_pan		= pan,
			ack_req		= ack_req,
			payload		= payload,
		))

	def tx_ieee(self, pkt):
		pkt.seq = self.seq
		self.seq = (self.seq + 1) & 0x3F

		#print("SENDING %02x" % (pkt.seq))
		self.last_pkt = pkt.serialize()
		if pkt.command != IEEE802154.COMMAND_DATA_REQUEST:
			print("TX: " + str(Parser.parse(self.last_pkt)[0]))
		self.radio.tx(self.last_pkt)

		if pkt.ack_req:
			self.last_tx = ticks_us()
			self.pending_seq = pkt.seq
			self.retries = 3
		else:
			self.pending_seq = None

	# Send a join request; we must know the PAN
	# from the beacon before sending the join
	def join(self, payload=b'\x80'):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_JOIN_REQUEST,
			ack_req		= 1,
			seq		= self.seq,
			src		= self.radio.mac(),
			src_pan		= 0xFFFF, # not yet part of the PAN
			dst		= self.router,
			dst_pan		= self.radio.pan(),
			payload		= payload, # b'\x80' = Battery powered, please allocate address
		))
		self.pending_data = True
		self.join_failed = False

	# Send a beacon request
	def beacon(self):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_BEACON_REQUEST,
			seq		= self.seq,
			src		= None,
			src_pan		= None,
			dst		= 0xFFFF, # everyone
			dst_pan		= 0xFFFF, # every PAN
			payload		= b'',
		))

	# if we have a pending ACK for this sequence number, flag it as received
	def handle_ack(self, ieee):
		if ieee.seq == self.pending_seq:
			#print("RX ACK %02x" % (ieee.seq))
			self.pending_seq = None

	# process a IEEE802154 command message to us
	def handle_command(self, ieee):
		if ieee.command == IEEE802154.COMMAND_JOIN_RESPONSE:
			if not self.pending_data:
				return
			self.pending_data = False
			(new_nwk, status) = unpack("<HB", ieee.payload)
			if status == 0:
				print("NEW NWK: %04x" % (new_nwk))
				self.radio.address(new_nwk)
			else:
				# throw an error?
				print("JOIN ERROR: %d" % (status))
				self.join_failed = True
			return

		elif ieee.command == IEEE802154.COMMAND_JOIN_REQUEST:
			# not our problem.
			return

		# other commands (data request, etc) are ignored
		print("COMMAND %04x" % (ieee.command))

	# process an IEEE802154 beacon, with a "Association Permit" bit set
	# update our PAN if we don't have one
	def handle_beacon(self, ieee):
		print("BCN %04x:%04x: %02x%02x" % (ieee.src_pan, ieee.src, ieee.payload[1], ieee.payload[0]))
		if self.radio.pan() is None \
		and ieee.payload[1] & 0x80 \
		and ieee.src != 0x0000:
			print("NEW ROUTER: %04x.%04x" % (ieee.src_pan, ieee.src))
			self.router = ieee.src
			self.radio.pan(ieee.src_pan)

class NetworkDevice:
	# This is the "well known" zigbee2mqtt key.
	# The Ikea gateway uses a different key that has to be learned
	# by joining the network (not yet implemented)
	nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
	aes = AES.AES(nwk_key)

	# The addr is [mac, nwk, pan] and are set by outside processes

	def __init__(self, dev, seq = 0):
		self.dev = dev
		self.handler = lambda x: None
		self.seq = 0 # this is the 8-bit sequence and wraps quickly
		self.sec_seq = seq # should be read from a config file and be always incrementing

		# Track the sequence numbers from other hosts
		self.seqs = {}

		# install our rx as the device's receive packet handler
		dev.handler = self.rx
		# todo: add handlers for aborted transactions, etc

	# called by the IEEE device when a new network packet has arrived
	def rx(self, data):
		try:
			nwk = ZigbeeNetwork.ZigbeeNetwork(data=data, aes=self.aes)
			# filter any dupes from this source
			if nwk.src in self.seqs and self.seqs[nwk.src] == nwk.seq:
				return

			self.seqs[nwk.src] = nwk.seq
			print(nwk)
		except:
			print("NWK error: " + hexlify(data))
			raise
			return

		if nwk.frame_type == ZigbeeNetwork.FRAME_TYPE_CMD:
			# what to do with these?
			# route record, etc
			self.handle_command(nwk)
		elif nwk.frame_type == ZigbeeNetwork.FRAME_TYPE_DATA:
			# pass it up the stack
			return self.handler(nwk.payload)
		else:
			print("NWK type %02x?" % (nwk.frame_type))


	def tx(self, dst, payload, frame_type=ZigbeeNetwork.FRAME_TYPE_DATA, security=True):
		self.dev.tx(dst, ZigbeeNetwork.ZigbeeNetwork(
			aes		= self.aes,
			frame_type	= frame_type,
			version		= 2,
			radius		= 1,
			seq		= self.seq,
			dst		= dst, # 0xfffd for broadcast,
			src		= self.radio.address(),
			ext_src		= self.radio.mac(),
			discover_route	= 0,
			security	= security,
			sec_key		= 1,
			sec_key_seq	= 0,
			sec_seq		= pack("<I", self.sec_seq),
			payload		= payload,
		).serialize())

		self.seq = (self.seq + 1) & 0x3F

		if enc:
			self.sec_seq += 1

	# Send a NWK level leave packet
	def leave(self):
		self.tx(
			dst		= ZigbeeNetwork.DEST_BROADCAST,
			frame_type	= ZigbeeNetwork.FRAME_TYPE_CMD,
			payload		= bytearray(b'\x04\x00'),
		)

	def handle_command(self, pkt):
		cmd = pkt.payload[0]
		print("---- CMD %02x ----" % (cmd))
		if cmd == ZigbeeNetwork.CMD_LEAVE:
			print("NWK %04x: LEAVE %02x" % (
				pkt.src,
				pkt.payload[1],
			))
			#self.leave()
			self.dev.radio.address(0xFFFF) # remove our NWK
			self.dev.radio.pan(0xFFFF) # remove our PAN
		elif cmd == ZigbeeNetwork.CMD_ROUTE_REQUEST:
			print("NWK %04x: Route request %02x: %02x%02x" % (
				pkt.src,
				pkt.payload[1],
				pkt.payload[4],
				pkt.payload[3],
			))
		elif cmd == ZigbeeNetwork.CMD_LINK_STATUS:
			count = pkt.payload[1] & 0x1f
			offset = 2
			print("NWK %04x: Links=[" % (pkt.src), end='')
			for i in range(0,count):
				print(" %02x%02x" % (
					pkt.payload[offset+1],
					pkt.payload[offset+0],
				), end='')
				offset += 3
			print(" ]")
		else:
			print("NWK command %02x:" % (cmd), hexlify(pkt.payload))

