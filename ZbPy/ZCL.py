# Zigbee Cluster Library packet parser
#   IEEE802154
#   ZigbeeNetwork (NWK)
#   (Optional encryption, with either Trust Center Key or Transport Key)
#   ZigbeeApplicationSupport (APS)
#   ZigbeeClusterLibrary (ZCL)
# ->ZCL ClusterParser
import struct

clusters = {
0x00: {
	'name': 'Basic',
},
0x01: {
	'name': 'PowerConfig',
},
0x02: {
	'name': 'DeviceTemp',
},
0x03: {
	'name': 'Identify',
},
0x04: {
	'name': 'Groups',
},
0x05: {
	'name': 'Scenes',
},
0x06: {
	'name': 'OnOff',
	0x00: [ "Off", "!", [] ],
	0x01: [ "On", "!", [] ],
	0x02: [ "Toggle", "!", [] ],
	0x40: [ "OffWithEffect", "!BB", ["id", "variant"] ],
	0x41: [ "OnWithRecall", "!", [] ],
	0x42: [ "OnWithTimedOff", "!Bhh", ["on", "time", "wait"] ],
},
0x07: {
	'name': 'OnOffConfig',
},
0x08: {
	'name': 'LevelControl',
	0x00: [ "MoveToLevel", "!Bh", [ "level", "time" ] ],
	0x01: [ "Move", "!BB", [ "dir", "rate" ] ],
	0x02: [ "Step", "!BBh", [ "dir", "step", "time" ] ],
	0x03: [ "Stop", "!", [] ],
	0x04: [ "MoveToLevelOnOff", "!Bh", [ "level", "time" ] ],
	0x05: [ "MoveOnOff", "!BB", [ "dir", "rate" ] ],
	0x06: [ "StepOnOff", "!BBh", [ "dir", "step", "time" ] ],
	0x07: [ "Stop", "!", [] ],
},
}

def lookup(name):
	cluster_name,command_name = name.split(".")
	for cluster_id, cluster in clusters.items():
		if cluster_name != cluster["name"]:
			continue
		for command_id, fmt in cluster.items():
			if fmt[0] == command_name:
				return cluster_id, command_id
	raise(name + ": Unknown cluster/command")
	

def unpack(fmt,names,data):
	try:
		ret = {}
		vals = struct.unpack(fmt, data)
		i = 0
		for name in names:
			ret[name] = vals[i]
			i += 1
		return ret
	except:
		print("unpack(",fmt,data,") failed")
		raise

def pack(fmt, names, data):
	l = []
	for name in names:
		l.append(data[name])
	return struct.pack(fmt, *l)
	

class ZCL:
	def __init__(self,
		data = None,
		cluster = None,
		command = None,
		name = None,
		payload = {}
	):
		self.command = command
		self.cluster = cluster
		if data is not None:
			self.deserialize(data)
		else:
			self.name = name
			self.payload = payload

	def __str__(self):
		return "ZCL(name='" + self.name + "', payload=" + str(self.payload) + ")"

	def deserialize(self, b):
		if self.cluster not in clusters:
			return None
		cluster = clusters[self.cluster];
		if self.command not in cluster:
			return None
		fmt = cluster[self.command]
		self.name = cluster["name"] + "." + fmt[0]
		#print("unpack(",fmt,")")
		self.payload = unpack(fmt[1], fmt[2], b)
		return self

	def serialize(self):
		cluster_id, command_id = lookup(self.name)
		fmt = clusters[cluster_id][command_id]
		return pack(fmt[1], fmt[2], self.payload)

#print(ZCL(cluster=0x08, command=0x06, data=b'\x00+\x05\x00'))
#x = ZCL(name='LevelControl.StepOnOff', payload={'dir': 0, 'step': 43, 'time': 5})
#print(x.serialize())

