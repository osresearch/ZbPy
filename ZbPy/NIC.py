# Zigbee/IEEE 802.15.4 serial NIC device
#
#

import gc
import os
import sys
import machine
import Radio
from ZbPy import IEEE802154
from binascii import unhexlify, hexlify
from struct import unpack

Radio.init()

def loop():
	pan_set = False

	incoming = ''
	machine.zrepl(False)

	while True:
		pkt = Radio.rx()
		if pkt is not None:
			# throw away the extra b' and ' on the string
			# representation
			x = repr(hexlify(pkt))[2:-1]
			print(x)

			ieee = IEEE802154.IEEE802154(data=pkt)

			if ieee.frame_type == IEEE802154.FRAME_TYPE_CMD \
			and ieee.command == IEEE802154.COMMAND_JOIN_RESPONSE:
				# reponse to our join request; update our short address
				(new_nwk, status) = unpack("<HB", ieee.payload)
				if status == 0:
					print("NIC: NEW NWK %04x" % (new_nwk))
					Radio.address(new_nwk)
				else:
                                	print("NIC: NEW NWK failed")

			elif ieee.frame_type == IEEE802154.FRAME_TYPE_BEACON \
			and not pan_set \
			and ieee.payload[1] & 0x80 \
			and ieee.src != 0x0000:
				print("NIC: NEW PAN %04x" % (ieee.src_pan))                        
				Radio.pan(ieee.src_pan)
				pan_set = True

			x = None
			gc.collect()

		if machine.stdio_poll():
			y = sys.stdin.read(1)
			if y == '\r':
				continue
			if y != '\n':
				incoming += y
				continue
			#print("SEND:", incoming)
			try:
				x = unhexlify(incoming)
				Radio.tx(x)
			except:
				print("TX FAIL")
			incoming = ''
			x = None
			gc.collect()

