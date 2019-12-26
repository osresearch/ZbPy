# Gecko Zigbee Python interface

This is a pure Python implementation of a IEEE802.15.4 and ZigBee network stack
that works with MicroPython.

It was developed for the Silicon Labs Gecko boards used in
Ikea Tradfri devices.  The firmware port of MicroPython lives in
[osresearch/micropython/ports/efm32](https://github.com/osresearch/micropython/tree/efm32/ports/efm32).
The underlying ZigBee radio interface also lives in the machine specific
port for that board; this is the hardware agnostic software stack that
processes the packets.

# Installing

![Ikea Tradfri remote with header attached](images/ikea-remote.jpg)

See the
[README](https://github.com/osresearch/micropython/blob/efm32/ports/efm32/README.md)
in the MicroPython port for details on building and installing using OpenOCD + SWD.

Using [`ampy.py`](https://learn.adafruit.com/micropython-basics-load-files-and-run-code/install-ampy) you can
install all of the code from the `ZbPy` directory into the flash on the device.

# ZigBee network layers

* Phyiscal layer (handled by the radio)
* IEEE802.15.4
* NWK - Network Layer
* Security Layer (not really a layer, an optional part of the NWK header)
* APS - Application Support Layer
* ZCL - ZigBee Cluster Library

