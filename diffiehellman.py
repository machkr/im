import hashlib
from binascii import hexlify
from os import urandom

class DiffieHellman():
	def __init__(self, generator, prime_group, key_length):
		"""
		Generate public and private keys.
		"""

		# Minimum key length
		minimum_key_length = 180

		# Default key length
		default_key_length = 540

		# Default generator
		default_generator = 2

		# Possible generators
		generator_options = [ 2, 3, 5, 7 ]

		# Check for invalid generator
		if generator not in generator_options:

			# Print error message
			print("Error: invalid generator; using default.")

			# Set generator to default
			self.generator = default_generator

		# Valid generator
		else:

			# Set generator to parameter
			self.generator = generator

		# Check for an invalid key length
		if key_length < minimum_key_length:

			# Print error message
			print("Error: insufficient key length; using default.")

			# Set key length to default
			self.key_length = default_key_length

		# Valid key length
		else:

			# Set key length to parameter
			self.key_length = key_length

		# Set prime number
		self.prime = self.getprime(prime_group)

		# Generate private key
		self.private_key = self.genprivatekey(key_length)

		# Generate public key
		self.public_key = self.genpublickey()

	def getprime(self, prime_group):
		"""
		Given a prime group number, return a prime number.
		"""

		# Default prime group
		default_prime_group = 17

		# Possible prime numbers (MODP Diffie-Hellman Groups, Internet Society)
		primes = {
			5:  0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
			14: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
			15: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
			16: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
			17: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
			18: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
		}

		# Check if invalid prime group 
		if prime_group not in primes.keys():
			
			# Print error message
			print("Error: no prime group %i; using default." % prime_group)
			
			# Extract prime number using default prime group
			return primes[default_prime_group]

		# Valid prime group
		else:
			
			# Extract prime number using parameter
			return primes[prime_group]

	def genrandom(self, num_bits):
		"""
		Generate a random number of given length in bits.
		"""

		# Random number to be generated
		random_number = 0

		# Number of bytes to generate
		bytes = num_bits // 8 + 8

		# While random number has not reached necessary length
		while random_number.bit_length() < num_bits:

			# Generate a random number of bytes in big-endian format
			random_number = int.from_bytes(urandom(bytes), byteorder='big')

		# Return result
		return random_number

	def genprivatekey(self, num_bits):
		"""
		Generate a private key using a random number generator.
		"""

		return self.genrandom(num_bits)

	def genpublickey(self):
		"""
		Generate a public key (generator ^ private_key) % prime.
		"""

		return pow(self.generator, self.private_key, self.prime)

	def verpublickey(self, other_key):
		"""
		Checks that other party's public key is valid.
		"""

		# Public key must be between 2 and our prime number
		if other_key > 2 and other_key < self.prime - 1:

			# Check Legendre Symbol equal to 1
			if pow(other_key, (self.prime - 1) // 2, self.prime) == 1:

				# Key passed verification
				return True
	
		# Key failed verification
		return False

	def gensecret(self, private_key, other_key):
		"""
		Combine private key with other party's public key to generate a shared
		secret.
		"""

		# Verify other party's public key
		if self.verpublickey(other_key):

			# Return (other_key ^ private_key) % prime
			return pow(other_key, private_key, self.prime)

		# Other party's public key failed verification	
		else:

			# Raise exception
			raise Exception("Other party's public key is invalid.")

	def genkey(self, other_key):
		"""
		Generate shared secret key.
		"""

		# Shared secret
		self.secret = self.gensecret(self.private_key, other_key)

		try:
			# Convert shared secret (integer) to bytes for hash function
			secret_bytes = self.secret.to_bytes(self.secret.bit_length() // 8 + 1, byteorder = 'big')

		# Unable to convert to bytes	
		except AttributeError:

			# Make it a string
			secret_bytes = str(self.secret)

		# Hash using SHA-512
		hash = hashlib.sha512()

		# Hash shared secret bytes
		hash.update(bytes(secret_bytes))

		# Shared secret hashed to produce shared secret key
		self.secret_key = hash.digest()

	def getkey(self):
		"""
		Return shared secret key.
		"""

		return self.secret_key

	def versecretkey(self, other_hash, nonce=None):
		"""
		Verifies that the hash of the secret key and nonce
		matches the provided hash
		"""

		# Return result
		return self.digest(self.secret_key, nonce) == other_hash

	def digest(self, string, nonce=None):
		"""
		Digests a given string using SHA-512
		"""

		# If nonce exists
		if nonce:

			# Store nonce
			self.nonce = nonce

			# Append nonce to string to be hashed
			string += bytes(nonce, 'utf-8')

		# Hash using SHA-512
		hash = hashlib.sha512()

		# Hash shared secret bytes
		hash.update(bytes(string, 'utf-8'))

		# Hash secret key and nonce
		return hash.digest()

if __name__ == "__main__":

	# Parameters for key exchange (would need to be exchanged)
	pub_gen = 2			# Could be 2, 3, 5, or 7
	pub_grp = 5			# Could be 5, 14, 15, 16, 17, or 18
	key_len = 256		# Could be anything greater than or equal to 180

	# Generating public/private keys using negotiated parameters
	alice = DiffieHellman(pub_gen, pub_grp, key_len)
	bob = DiffieHellman(pub_gen, pub_grp, key_len)

	# This is where public keys would be exchanged between parties

	# Generating shared secret key
	alice.genkey(bob.public_key)
	bob.genkey(alice.public_key)

	print("Public Key:", alice.public_key)

	# Keys match
	if alice.getkey() == bob.getkey():

		# Print success message
		print("Shared secret keys match.")

		# Print key
		print("Key:", hexlify(alice.secret_key))

	# Keys don't match
	else:

		# Print failure message
		print("Shared secret keys do not match.")

		# Print each party's secret
		print("Alice's Secret:", alice.secret)
		print("Bob's Secret:", bob.secret)

	# nonce = 'ABC'
	# nonced =  + bytes(nonce, 'utf-8')

	if alice.versecretkey(bob.digest(bob.secret_key)):
		print('True')
	else:
		print('False')
