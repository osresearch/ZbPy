# Process a packet buffer by consuming the data in it
class Packet:
	def __init__(self):
		self._offset = 0
		self._data = None
	def init(self, data):
		self._offset = 0
		self._data = data
	def len(self):
		return len(self._data)
	def offset(self):
		return self._offset
	def remaining(self):
		return self.len() - self.offset()
	def u8(self):
		x = self._data[self._offset]
		self._offset += 1
		return x
	def u16(self):
		x = 0 \
		  | self._data[self._offset+1] << 8 \
                  | self._data[self._offset+0] << 0
		self._offset += 2
		return x
	def u32(self):
		x = 0 \
		  | self._data[self._offset+3] << 24 \
		  | self._data[self._offset+2] << 16 \
		  | self._data[self._offset+1] << 8 \
                  | self._data[self._offset+0] << 0
		self._offset += 4
		return x
	def data(self, len):
		x = self._data[self._offset:self._offset+len]
		self._offset += len
		return x

