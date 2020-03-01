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

	# addr is [mac, nwk, pan]
	def __init__(self, tx, addr, router = None):
		self.tx_raw = tx
		self.addr = addr
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
			if ieee.frame_type == IEEE802154.FRAME_TYPE_ACK:
				# No PAN information
				return self.handle_ack(ieee)
			elif ieee.frame_type == IEEE802154.FRAME_TYPE_BEACON:
				# Need to process before our PAN is defined
				return self.handle_beacon(ieee)
			elif ieee.dst_pan != self.addr[2]:
				# Doesn't match our network, reject
				return
			elif ieee.dst == 0xFFFF:
				# broadcast, we'll process it
				pass
			elif ieee.dst == self.addr[1] or ieee.dst == self.addr[0]:
				# to us, check for an ack request
				if ieee.ack_req:
					self.ack(ieee.seq)
			else:
				# not a broadcast nor unicast to us
				return

			#print("RX: " + str(ieee))
			print("RX: " + str(Parser.parse(data)[0]))

			# check for duplicates
			if ieee.src is int and ieee.src in self.seqs and self.seqs[ieee.src] == ieee.seq:
				return

		except Exception as e:
			print("IEEE error: " + str(hexlify(data)))
			raise
			return

		if ieee.frame_type == IEEE802154.FRAME_TYPE_CMD:
			return self.handle_command(ieee)
		elif ieee.frame_type == IEEE802154.FRAME_TYPE_DATA:
			# for the next layer up, pass it to the handler
			return self.handler(ieee.payload)
		else:
			# should signal a wtf?
			pass


	def tick(self):
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
			self.tx_raw(self.last_pkt)
			self.retries -= 1

	# Send an ACK for a sequence number, indicating that it has
	# been received by this device (but nothing else about it)
	# todo: perhaps this should be fast tracked
	def ack(self, ack_seq):
		self.tx_raw(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_ACK,
			seq		= ack_seq,
		).serialize())
		print("ACKING %02x" % (ack_seq))

	# Send a data request to say "yo we're ready for stuff"
	def data_request(self):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_DATA_REQUEST,
			dst		= self.router,
			dst_pan		= self.addr[2],
			src		= self.addr[1] if self.addr[1] is not None else self.addr[0],
			src_pan		= self.addr[2],
			ack_req		= True,
		))

	# Send a packet from the upper layer, wrapping it with the
	# IEEE 802.15.4 header, setting the flags as requested
	def tx(self, payload, dst = None, ack_req = False, long_addr = False):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_DATA,
			dst		= dst,
			src		= self.addr[0] if long_addr else self.addr[1],
			pan		= self.addr[2],
			ack_req		= ack_req,
			payload		= payload,
		))

	def tx_ieee(self, pkt):
		pkt.seq = self.seq
		self.seq = (self.seq + 1) & 0x3F

		#print("SENDING %02x" % (pkt.seq))
		self.last_pkt = pkt.serialize()
		print("TX: " + str(Parser.parse(self.last_pkt)[0]))
		self.tx_raw(self.last_pkt)

		if pkt.ack_req:
			self.last_tx = ticks_us()
			self.pending_seq = pkt.seq
			self.retries = 3
		else:
			self.pending_seq = None

	# Send a join request
	def join(self, payload=b'\x80'):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_JOIN_REQUEST,
			ack_req		= 1,
			seq		= self.seq,
			src		= self.addr[0],
			src_pan		= 0xFFFF, # not yet part of the PAN
			dst		= self.router,
			dst_pan		= self.addr[2],
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
			print("RX ACK %02x" % (ieee.seq))
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
				self.addr[1] = new_nwk
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

	# process an IEEE802154 beacon, update our PAN if we don't have one
	def handle_beacon(self, ieee):
		print("BCN %04x:%04x: %02x%02x" % (ieee.src_pan, ieee.src, ieee.payload[1], ieee.payload[0]))
		if self.router is None and ieee.payload[1] & 0x80 and ieee.src != 0x0000:
			print("NEW ROUTER: %04x" % (ieee.src))
			self.router = ieee.src
			if self.addr[2] is None:
				print("NEW PAN: %04x" % (ieee.src_pan))
				self.addr[2] = ieee.src_pan

class NetworkDevice:
	# This is the "well known" zigbee2mqtt key.
	# The Ikea gateway uses a different key that has to be learned
	# by joining the network (not yet implemented)
	nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
	aes = AES.AES(nwk_key)

	# The addr is [mac, nwk, pan] and are set by outside processes

	def __init__(self, tx, addr, seq = 0):
		self.tx_packet = tx
		self.handler = lambda x: None
		self.addr = addr
		self.seq = 0 # this is the 8-bit sequence and wraps quickly
		self.sec_seq = seq # should be read from a config file and be always incrementing

		# Track the sequence numbers from other hosts
		self.seq_seen = {}

	# called by the IEEE device when a new network packet has arrived
	def rx(self, data):
		try:
			nwk = ZigbeeNetwork.ZigbeeNetwork(data=data, aes=aes)
			# filter any dupes from this source
			if nwk.src in self.seqs and self.seqs[nwk.src] == nwk.seq:
				return

			self.seqs[nwk.src] = nwk.seq
			print(nwk)
		except:
			print("NWK error: " + hexlify(data))
			return

		if nwk.frame_type == ZigbeeNetwork.FRAME_TYPE_CMD:
			# what to do with these?
			# route record, etc
			pass
		elif nwk.frame_type == ZigbeeNetwork.FRAME_TYPE_DATA:
			# pass it up the stack
			return self.handler(nwk.payload)


	def tx(self, dst, payload, frame_type=ZigbeeNetwork.FRAME_TYPE_DATA, security=True):
		self.tx_packet(dst, ZigbeeNetwork.ZigbeeNetwork(
			aes		= self.aes,
			frame_type	= frame_type,
			version		= 2,
			radius		= 1,
			seq		= self.seq,
			dst		= dst, # 0xfffd for broadcast,
			src		= self.addr[1],
			ext_src		= self.addr[0],
			discover_route	= 0,
			security	= security,
			sec_key		= 1,
			sec_key_seq	= 0,
			sec_seq		= pack("<I", self.sec_seq),
			payload		= payload,
		))

		self.seq = (self.seq + 1) & 0x3F

		if enc:
			self.sec_seq += 1

	def leave(self):
		self.tx(
			dst		= ZigbeeNetwork.DEST_BROADCAST,
			frame_type	= ZigbeeNetwork.FRAME_TYPE_CMD,
			payload		= bytearray(b'\x04\x00'),
		)
