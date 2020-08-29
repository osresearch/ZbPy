#
#
try:
	# if Crypto.Cipher.AES is availble, use it instead
	from Crypto.Cipher import AES as PyAES
	class AES:
		def __init__(self, key_encrypt):
			self.aes = PyAES.new(key_encrypt, PyAES.MODE_ECB)

		def encrypt(self, plaintext):
			return bytearray(self.aes.encrypt(bytes(plaintext)))

		def decrypt(self, ciphertext):
			return bytearray(self.aes.decrypt(bytes(ciphertext)))

except:
	# Gecko AES wrapper in ECB mode.
	# on the actual hardware, use the accelerated mode
	# This uses a temporary buffer for the output and must be used
	# before the next operation.
	from machine import Crypto

	class AES:
		def __init__(self, key_encrypt):
			self.key_encrypt = key_encrypt
			self.key_decrypt = Crypto.aes_decryptkey(key_encrypt)
			self.out = bytearray(16)

		def encrypt(self, plaintext):
			Crypto.aes_ecb_encrypt(self.key_encrypt, plaintext, self.out)
			return self.out

		def decrypt(self, ciphertext):
			Crypto.aes_ecb_decrypt(self.key_decrypt, ciphertext, self.out)
			return self.out
