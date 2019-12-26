# Zigbee uses a weird AES mode called CCM*
# It requires encrypting/decrypting the message and auth data twice
# But it is a standard, so we have to support it.
# Trying to read the spec is awful, but translating the wireshark code
# is not too bad...

# Decrypt a message in place and compute the message integrity code (MIC)
# based on the clear text and the authorization message. The nonce will
# be updated in counter mode as it is used; should be 0 at the start
#
# Caveats:
# This does not handle l_m > 65535, but zigbee never has more than 64 bytes
# There is weirdness in the B0 computation that hardcodes the length l_M

def decrypt(auth, message, mic, nonce, aes, validate=True):
	l_m = len(message)
	l_M = len(mic)
	l_a = len(auth)

	if l_M != 4:
		raise("MIC must be 4 bytes")
	if len(nonce) != 16:
		raise("Nonce must be 16 bytes")

	# decrypt the MIC block in place if there is a MIC
	if validate:
		xor = aes.encrypt(nonce)
		for j in range(l_M):
			mic[j] ^= xor[j]

	# decrypt each 16-byte block in counter mode
	# including any partial block at the end
	for i in range(0, l_m, 16):
		block_len = l_m - i
		if block_len > 16:
			block_len = 16

		# increment the counter word,
		nonce[15] += 1
		xor = aes.encrypt(nonce)
		for j in range(block_len):
			message[i+j] ^= xor[j]

	# avoid the extra encryption if not validating
	if not validate:
		return True

	#
	# check the message integrity code with the messy CCM*
	#

	# Generate the first cipher block B0
	xor[0] = 1 << 3 # int((4 - 2)/2) << 3
	if l_a != 0:
		xor[0] |= 0x40
	xor[0] |= 1
	xor[1:14] = nonce[1:14] # src addr and counter
	xor[14] = (l_m >> 8) & 0xFF
	xor[15] = (l_m >> 0) & 0xFF
	xor = aes.encrypt(xor)

	# process the auth length and auth data blocks
	xor[0] ^= (l_a >> 8) & 0xFF
	xor[1] ^= (l_a >> 0) & 0xFF
	j = 2
	for i in range(l_a):
		if (j == 16):
			xor = aes.encrypt(xor)
			j = 0
		xor[j] ^= auth[i]
		j += 1

	# pad out the rest of this block with 0
	j = 16

	# process the clear text message blocks
	for i in range(l_m):
		if (j == 16):
			xor = aes.encrypt(xor)
			j = 0
		xor[j] ^= message[i]
		j += 1

	# fixup any last bits
	if j != 0:
		xor = aes.encrypt(xor)

	# If all went well, the xor block should match the decrypted MIC
	return xor[0:l_M] == mic


# Encypts a message in place and returns the 4-byte MIC
# Nonce should have the counter value of 0; will be modified in place as well
def encrypt(auth, message, nonce, aes):
	l_m = len(message)
	l_M = 4
	l_a = len(auth)

	if len(nonce) != 16:
		raise("Nonce must be 16 bytes")

	# Generate the first cipher block B0
	# and run in CBC mode to compute the MIC
	xor = bytearray(16)
	xor[0] |= 1 << 3 # int((4 - 2)/2) << 3
	xor[0] |= 0x40
	xor[0] |= 1
	xor[1:14] = nonce[1:14] # src addr and counter
	xor[14] = (l_m >> 8) & 0xFF
	xor[15] = (l_m >> 0) & 0xFF
	xor = aes.encrypt(xor)

	# process the auth length and auth data blocks
	xor[0] ^= (l_a >> 8) & 0xFF
	xor[1] ^= (l_a >> 0) & 0xFF
	j = 2
	for i in range(l_a):
		if (j == 16):
			xor = aes.encrypt(xor)
			j = 0
		xor[j] ^= auth[i]
		j += 1

	# pad out the rest of this block with 0
	j = 16

	# process the clear text message blocks
	for i in range(l_m):
		if (j == 16):
			xor = aes.encrypt(xor)
			j = 0
		xor[j] ^= message[i]
		j += 1

	# fixup any last bits
	if j != 0:
		xor = aes.encrypt(xor)

	# the cleartext MIC is the first few bytes of the last cipher text block
	mic = xor[0:l_M]

	# Use the nonce with counter 0 to encrypt the MIC
	xor = aes.encrypt(nonce)
	for i in range(l_M):
		mic[i] ^= xor[i]

	# now repeat the process to encrypt the message in a counter mode
	# XOR each 16-byte block in counter mode
	# including any partial block at the end
	for i in range(0, l_m, 16):
		block_len = l_m - i
		if block_len > 16:
			block_len = 16

		# increment the counter word,
		nonce[15] += 1
		xor = aes.encrypt(nonce)
		for j in range(block_len):
			message[i+j] ^= xor[j]

	# return the encrypted MIC
	return mic

if __name__ == "__main__":
	import AES
	aes = AES.AES(b"\x01\x03\x05\x07\x09\x0b\x0d\x0f\x00\x02\x04\x06\x08\x0a\x0c\x0d")
	message = bytearray(b'\x0c\x00\x00\x06\x00\x04\x01\x01#\x01\r\x02')
	mic = encrypt(
		bytearray(b'H\x02\xfd\xff8+\x0bC-\x87H\x04\x00\xb1\x9d\xe8\x0b\x00K\x12\x00\x00'), # auth
		message,
		bytearray(b'\x01\xb1\x9d\xe8\x0b\x00K\x12\x00\x87H\x04\x00-\x00\x00'), # nonce
		aes
	)
	#print("message=", message)
	#print("mic=", mic)
	cipher_mic= bytearray(b'\x12P\x1f\xf1')
	cipher_message = bytearray(b'\x05Ve\xc1O\x13\x10$\x10\x07\x8a=')
	if message != cipher_message:
		print("cipher message bad")
	if mic != cipher_mic:
		print("cipher mic bad")
	if message == cipher_message and mic == cipher_mic:
		#print("Good cipher!")
		pass

