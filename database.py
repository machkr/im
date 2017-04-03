from binascii import hexlify, unhexlify
from bcrypt import hashpw, checkpw, gensalt
from datetime import datetime, timedelta
from os import urandom
import pyDes
import pymysql as mysql

class database():
	def __init__(self):
		# Database parameters
		self.host = 'netsecdb.cvfrpuoosleq.us-east-1.rds.amazonaws.com'
		self.port = 3306
		self.user = 'admin'
		self.password = '7CzlYgscU4VSlvW9eoJmW0DRC8s97v'
		self.db = 'netsecdb'

		# Database connection
		self.database = mysql.connect(host = self.host,
								 	  port = self.port,
								 	  user = self.user,
								 	  password = self.password,
								 	  db = self.db)

		# Database cursor
		self.cursor = self.database.cursor()

	def create_user(self, username, password):
		"""Creates and stores a new user"""

		try:
			# Generate password hash
			hash = hashpw(password.encode('utf-8'), gensalt())

			# Create user using stored procedure
			self.cursor.callproc('create_user', (username, hash))

			# Retrieve result of procedure
			result = self.cursor.fetchone()

			# Success
			if result[0] == 'TRUE':

				# Success message
				print("User created successfully.")

				# Commit changes to database
				self.database.commit()

				# Return result
				return True

			# Failure
			else:

				# Raise exception
				raise ValueError("Username already exists.")

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print(exception)

			# Return result
			return False

	def login(self, username, password):
		"""Authenticates a user"""

		try:
			# Check if user exists
			self.cursor.callproc('check_user', (username,))

			# Retrieve result from procedure
			result = self.cursor.fetchone()

			# User exists
			if result[0] == 'TRUE':
				
				# Get corresponding password hash
				self.cursor.callproc('get_password', (username,))

				# Retrieve result from procedure
				result = self.cursor.fetchone()

				# Check password against password hash
				if checkpw(password.encode('utf-8'), result[0]):

					# Sets 'last login' to current time
					self.cursor.callproc('login', (username,))
					
					# Success message
					print("User logged in successfully.")

					# Commit changes to database
					self.database.commit()
				
					# Return result
					return True

				# Password hashes don't match
				else:

					# Raise exception
					raise ValueError("Incorrect password.")

			# User does not exist
			elif result[0] == 'FALSE': 

				# Raise exception
				raise ValueError("User does not exist.")

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print(exception)

			# Return result
			return False

	def establish(self, username_x, username_y):
		"""Establishes a conversation and key between users (for encryption/sending)"""

		try:
			# Check if users exist
			self.cursor.callproc('check_users', (username_x, username_y,))

			# Retrieve result from procedure
			result = self.cursor.fetchone()

			# Users exist
			if result[0] == 'TRUE':

				# Get conversation id if a conversation between them exists
				self.cursor.callproc('get_conversation_id', (username_x, username_y,))

				# Retrieve result from procedure
				result = self.cursor.fetchone()
				conversation_id = result[0]

				# Conversation exists
				if conversation_id != '':

					# Get key corresponding to conversation
					self.cursor.callproc('get_key', (conversation_id,))

					# Retrieve result from procedure
					result = self.cursor.fetchone()
					key = result[0]

					# If key has expired (30 second expiration)
					if (datetime.now() - result[1] > timedelta(seconds=30)):
						
						# Generate a new key (8 bytes/64 bits)
						new_key = urandom(8)
						
						# Update conversation's key
						self.cursor.callproc('update_key', (conversation_id, new_key,))
						
						# Commit changes to database
						self.database.commit()

						# Return newly-generated key
						return new_key

					# Key has not expired
					else: 

						# Return existing key
						return key	

				else: # Conversation does not exist

					# Generate conversation id (8 bytes/64 bits)
					id = urandom(8)

					# Generate shared key (8 bytes/64 bits)
					key = urandom(8)

					# Create conversation between users
					self.cursor.callproc('create_conversation', (id, username_x, username_y, key,))

					# Commit changes to database
					self.database.commit()

					# Return key
					return key

			# One or both users do not exist
			else:

				# Raise exception
				raise ValueError("User does not exist.")

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print(exception)

			# Return result
			return None


	def retrieve(self, username_x, username_y):
		"""Retrieves a stored key (for decryption/receiving)"""

		try:
			# Check if users exist
			self.cursor.callproc('check_users', (username_x, username_y,))

			# Retrieve result from procedure
			result = self.cursor.fetchone()

			# Users exist
			if result[0] == 'TRUE':

				# Get conversation id if a conversation between them exists
				self.cursor.callproc('get_conversation_id', (username_x, username_y,))

				# Retrieve result from procedure
				result = self.cursor.fetchone()

				# Conversation exists
				if result[0] != '':

					# Get key corresponding to conversation
					self.cursor.callproc('get_key', (result[0],))

					# Retrieve result from procedure
					result = self.cursor.fetchone()

					# Return key
					return result[0]

				# Conversation does not exist
				else:

					# Raise exception
					raise ValueError("Conversation does not exist.")

			# One or both users do not exist
			else:

				# Raise exception
				raise ValueError("User does not exist.")

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print(exception)

			# Return result
			return None

if __name__ == "__main__":

	# Initialize database
	db = database()
	
	# Testing functionality
	# Creating users
	print("Creating user: Matthew...")
	db.create_user('matthew', 'password')

	print("Creating user: Sterling...")
	db.create_user('sterling', 'password')

	# Logging in users
	print("Logging in user: Matthew...")
	db.login('matthew', 'password')

	print("Logging in user: Sterling...")
	db.login('sterling', 'password')

	# Establishing key
	print("Establishing conversation...")
	key1 = db.establish('matthew', 'sterling')
	print("Established Key:", key1)

	# Retrieving key
	key2 = db.retrieve('matthew', 'sterling')
	print("Retrieve 'matthew', 'sterling':", key2)

	# Retrieving key, reversed
	key3 = db.retrieve('sterling', 'matthew')
	print("Retrieve 'sterling', 'matthew':", key3)

	# Check consistent keys
	if key1 == key2 and key2 == key3:
		print("Success")
	else:
		print("Failure")

	# DES sample message
	dat = "This is a test of DES."

	# Configuring DES object
	des = pyDes.des(key1, pad="0", padmode=pyDes.PAD_NORMAL)

	# Encrypting data
	enc = des.encrypt(dat)

	# Decrypting data
	dec = des.decrypt(enc).decode()

	# Output
	print("Plaintext:", dat)
	print("Encrypted:", enc)
	print("Decrypted:", dec)

	# Check consistent plaintext/ciphertext
	if dat == dec:
		print("Success")
