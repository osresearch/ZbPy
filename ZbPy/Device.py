# Zigbee/IEEE 802.15.4 device
#
#

from ZbPy import AES
from ZbPy import IEEE802154
from ZbPy import ZigbeeNetwork
from ZbPy import ZigbeeApplication
from ZbPy import ZigbeeCluster
from ZbPy import ZCL

from binascii import unhexlify, hexlify

try:
	from time import ticks_us
except:
	import time
	def ticks_us():
		return int(time.time() * 1e6)


class IEEEDevice:
	def __init__(self, tx, mac, nwk = None, pan = None):
		self.raw_tx = tx
		self.nwk = nwk
		self.mac = mac
		self.pan = pan
		self.seq = 0
		self.pending_seq = None
		self.handler = lambda x: None


	def rx(self, data):
		if data is None:
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
			elif ieee.dst_pan != self.pan:
				# Doesn't match our network, reject
				return
			elif ieee.dst != 0xFFFF:
				# broadcast, we'll process it
				pass
			elif ieee.dst == self.nwk or ieee.dst == self.mac:
				# to us, check for an ack request
				if ieee.ack_req:
					self.tx_ack(ieee.seq)
			else:
				# not a broadcast nor unicast to us
				return
			print(ieee)
		except Exception as e:
			print("IEEE error: " + str(hexlify(data)) + ": " + str(e))
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
		if self.pending_seq is None:
			return
		if self.retries == 0:
			# todo: log that the transmit failed to ever be acked
			self.pending_seq = None
			return

		now = ticks_us()
		if now - self.last_tx < self.retry_timer:
			return

		self.last_tx = now
		self.raw_tx(self.last_pkt)
		self.retries -= 1

	# Send an ACK for a sequence number, indicating that it has
	# been received by this device (but nothing else about it)
	# todo: perhaps this should be fast tracked
	def tx_ack(self, ack_seq):
		self.raw_tx(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_ACK,
			seq		= ack_seq,
		))

	# Send a packet from the upper layer, wrapping it with the
	# IEEE 802.15.4 header, setting the flags as requested
	def tx(self, payload, dst = None, ack_req = False, long_addr = False):
		pkt = IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_DATA,
			dst		= dst,
			src		= self.mac if long_addr else self.nwk,
			pan		= self.pan,
			ack_req		= ack_req,
			seq		= self.seq,
			payload		= payload,
		)

		self.tx_ieee(pkt)

	def tx_ieee(self, pkt):
		self.last_pkt = pkt.serialize()
		self.raw_tx(self.last_pkt)

		self.seq = (pkt.seq + 1) & 0x3F

		if pkt.ack_req:
			self.last_tx = ticks_us()
			self.pending_seq = pkt.seq
			self.retries = 0
		else:
			self.pending_seq = None

	# Send a join request
	def join(self, payload=b'\x80'):
		self.tx_ieee(IEEE802154.IEEE802154(
			frame_type	= IEEE802154.FRAME_TYPE_CMD,
			command		= IEEE802154.COMMAND_JOIN_REQUEST,
			seq		= self.seq,
			src		= self.mac,
			src_pan		= 0xFFFF, # not yet part of the PAN
			dst		= 0x0000, # coordinator
			dst_pan		= self.pan,
			payload		= payload, # b'\x80' = Battery powered, please allocate address
		))

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
			self.pending_seq = None

	# process a IEEE802154 command message to us
	def handle_command(self, ieee):
		if ieee.command == COMMAND_JOIN_RESPONSE:
			(new_nwk, status) = unpack("<HB", ieee.payload)
			if status == 0:
				print("NEW NWK: %04x" % (new_nwk))
				self.nwk = new_nwk
			else:
				# throw an error?
				print("JOIN ERROR: %d" % (status))
			return

		# other commands (data request, etc) are ignored
		print("COMMAND %04x" % (ieee.command))

	# process an IEEE802154 beacon, update our PAN if we don't have one
	def handle_beacon(self, ieee):
		if self.pan is None:
			print("NEW PAN: %04x" % (ieee.src_pan))
			self.pan = ieee.src_pan

class NetworkDevice:
	# This is the "well known" zigbee2mqtt key.
	# The Ikea gateway uses a different key that has to be learned
	# by joining the network (not yet implemented)
	nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
	aes = AES.AES(nwk_key)

	# The NWK and MAC are to be set by the outside

	def __init__(self, tx, seq=0, nwk=None, mac=None):
		self.tx_packet = tx
		self.handler = lambda x: None
		self.nwk = nwk
		self.mac = mac
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
			src		= self.nwk,
			ext_src		= self.mac,
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
