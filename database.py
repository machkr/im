from base64 import b64encode, b64decode
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
		"""
		Creates and stores a new user.
		"""

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
				print("[CLIENT]: User created successfully.")

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
			print('[CLIENT]:', exception)

			# Return result
			return False

	def login(self, username, password):
		"""
		Authenticates a user
		"""

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
					print("[CLIENT]: User logged in successfully.")

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

				# Create new user with this username and password
				self.create_user(username, password)

				# Return result
				return True

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print('[CLIENT]:', exception)

			# Return result
			return False

	def establish(self, username_x, username_y):
		"""
		Establishes a conversation and key between users.
		To be used for encryption and sending messages.
		"""

		try:
			# Check if users exist
			self.cursor.callproc('check_users', 
				(username_x, username_y,))

			# Retrieve result from procedure
			result = self.cursor.fetchone()

			# Users exist
			if result[0] == 'TRUE':

				# Get conversation id if a conversation between them exists
				self.cursor.callproc('get_conversation_id', 
					(username_x, username_y,))

				# Retrieve result from procedure
				result = self.cursor.fetchone()
				conversation_id = result[0]

				# Conversation exists
				if conversation_id != '':

					# Get key corresponding to conversation
					self.cursor.callproc('get_time', (conversation_id,))

					# Retrieve result from procedure
					result = self.cursor.fetchone()

					# If key has expired (30 second expiration)
					if (datetime.now() - result[0] > timedelta(seconds=30)):
						
						# Generate an updated key (24 bytes/192 bits)
						updated_key = urandom(24)
						
						# Update conversation's key
						self.cursor.callproc('update_time', 
							(conversation_id,))
						
						# Commit changes to database
						self.database.commit()

						# Return newly-generated key
						return updated_key

					# Key has not expired
					else: 

						# Return nothing
						return None	

				else: # Conversation does not exist

					# Generate conversation id (24 bytes/192 bits)
					id = urandom(24)

					# Generate shared key (24 bytes/192 bits)
					new_key = urandom(24)

					# Create conversation between users
					self.cursor.callproc('create_conversation', 
						(id, username_x, username_y,))

					# Commit changes to database
					self.database.commit()

					# Return key
					return new_key

			# One or both users do not exist
			else:

				# Raise exception
				raise ValueError("User does not exist.")

		# Catch any exception raised
		except Exception as exception:

			# Print exception
			print('[SERVER]:', exception)

			# Return result
			return None

	def encrypt(self, key, plaintext):
		"""
		Encrypts a given plaintext with a given key using DES.
		"""

		# Check that key is bytestring
		if type(key) is not bytes:

			# Decode key
			key = self.decode(key)

		# Configure Triple-DES object using first 24 bytes of key
		des = pyDes.triple_des(key[:24], padmode=pyDes.PAD_PKCS5)

		# Encrypt message and return bytestring
		return self.encode(des.encrypt(plaintext))

	def decrypt(self, key, ciphertext):
		"""
		Decrypts a given ciphertext with a given key using DES.
		"""

		# Check that key is bytestring
		if type(key) is not bytes:

			# Decode key
			key = self.decode(key)

		# Configure Triple-DES object using first 24 bytes of key
		des = pyDes.triple_des(key[:24], padmode=pyDes.PAD_PKCS5)

		# Decrypt message and decode bytes into string
		return des.decrypt(self.decode(ciphertext))

	def encode(self, bytestring):
		"""
		Encodes a bytestring as a base-64 string.
		"""

		return b64encode(bytestring).decode()

	def decode(self, string):
		"""
		Decodes a base-64 string as a bytestring.
		"""

		return b64decode(string)
