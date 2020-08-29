from ZbPy import Device
from binascii import hexlify, unhexlify


try:
	import Radio
	# for now hard code the pan and router so that we have
	# a device we can reboot
	router = 0x3f15 # was unhexlify("d0cf5efffe295828")
	Radio.pan(0x1a62) 
	#Radio.promiscuous(1) # should turn off when we're done
	dev = Device.IEEEDevice(radio=Radio, router=router)
	nwk = Device.NetworkDevice(dev=dev)	
except:
	print("import Radio failed")

def sniff(rx=Radio.rx):
	while True:
		pkt = rx()
		if pkt is None:
			continue
		print(IEEE802154.parse(pkt))
