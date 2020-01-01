#
# Wrapper for all of the IEEE802.15.4 and ZigBee layers
#
from binascii import unhexlify, hexlify

from ZbPy import AES
from ZbPy import IEEE802154
from ZbPy import ZigbeeNetwork
from ZbPy import ZigbeeApplication
from ZbPy import ZigbeeCluster
from ZbPy import Parser

import gc
gc.collect()

# This is the "well known" zigbee2mqtt key.
# The Ikea gateway uses a different key that has to be learned
# by joining the network (not yet implemented)
nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
aes = AES.AES(nwk_key)

# Only need one AES object in ECB mode since there is no
# state to track

def parse(data, verbose=False, validate=True):
	#print("------")
	#print(data)
	ieee = IEEE802154.IEEE802154(data=data)

	if verbose: print(ieee)

	if ieee.frame_type != IEEE802154.FRAME_TYPE_DATA:
		return ieee, "ieee"
	if len(ieee.payload) == 0:
		return ieee, "ieee"

	nwk = ZigbeeNetwork.ZigbeeNetwork(
		data=ieee.payload,
		aes=aes,
		validate=validate
	)

	ieee.payload = nwk
	if verbose: print(nwk)

	if nwk.frame_type != ZigbeeNetwork.FRAME_TYPE_DATA:
		return ieee, "nwk"

	aps = ZigbeeApplication.ZigbeeApplication(data=nwk.payload)
	nwk.payload = aps

	if verbose: print(aps)

	if aps.frame_type != ZigbeeApplication.FRAME_TYPE_DATA:
		return ieee, "aps"

	# join requests are "special" for now
	if aps.cluster == 0x36:
		return ieee, "join"

	zcl = ZigbeeCluster.ZigbeeCluster(data=aps.payload)
	aps.payload = zcl

	if verbose: print(zcl)

	return ieee, "zcl"
