#
# Wrapper for all of the IEEE802.15.4 and ZigBee layers
#
from binascii import unhexlify, hexlify

from ZbPy import AES
from ZbPy import IEEE802154
from ZbPy import ZigbeeNetwork
from ZbPy import ZigbeeApplication
from ZbPy import ZigbeeCluster
from ZbPy import ZCL

import gc
gc.collect()

# This is the "well known" zigbee2mqtt key.
# The Ikea gateway uses a different key that has to be learned
# by joining the network (not yet implemented)
nwk_key = unhexlify(b"01030507090b0d0f00020406080a0c0d")
aes = AES.AES(nwk_key)

# Pre-allocate message types for the parser
# Only one message can be parsed at a time
ieee = IEEE802154.IEEE802154()
nwk = ZigbeeNetwork.ZigbeeNetwork(aes=aes)
aps = ZigbeeApplication.ZigbeeApplication()
zcl = ZigbeeCluster.ZigbeeCluster()
cmd = ZCL.ZCL()

# For filtering dupes
seqs = {}

def parse(data, verbose=False, filter_dupes=False):
	global seqs

	#print("------")
	#print(data)
	ieee.deserialize(data)

	if verbose: print(ieee)

	if ieee.frame_type != IEEE802154.FRAME_TYPE_DATA:
		return ieee, "ieee"
	if len(ieee.payload) == 0:
		return ieee, "ieee"

	nwk.deserialize(ieee.payload)
	ieee.payload = nwk
	if verbose: print(nwk)

	if nwk.frame_type != ZigbeeNetwork.FRAME_TYPE_DATA:
		return ieee, "nwk"

	if filter_dupes:
		if nwk.src in seqs and seqs[nwk.src] == nwk.seq:
			return ieee, "dupe"
	seqs[nwk.src] = nwk.seq

	aps.deserialize(nwk.payload)
	nwk.payload = aps

	if verbose: print(aps)

	if aps.frame_type != ZigbeeApplication.FRAME_TYPE_DATA \
	or aps.profile != ZigbeeApplication.PROFILE_HOME:
		return ieee, "aps"

	zcl.deserialize(aps.payload)
	aps.payload = zcl

	if verbose: print(zcl)

	cmd.cluster = aps.cluster
	cmd.command = zcl.command
	if not cmd.deserialize(zcl.payload):
		return ieee, "zcl?"

	# Successfully decoded all the way to the ZCL layer
	zcl.payload = cmd

	return ieee, "zcl"
