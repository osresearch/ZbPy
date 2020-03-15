from ZbPy import Device
from binascii import hexlify, unhexlify

try:
	import Radio
	#Radio.pan(0x1a62)
	dev = Device.IEEEDevice(radio=Radio)
	nwk = Device.NetworkDevice(dev=dev)	
except:
	print("import Radio failed")

def sniff(rx=Radio.rx):
	while True:
		pkt = rx()
		if pkt is None:
			continue
		print(IEEE802154.parse(pkt))
	
