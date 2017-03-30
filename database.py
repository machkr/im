from bcrypt import hashpw, checkpw, gensalt
from os import urandom
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

			if result[0] == 'TRUE': # Success

				# Success message
				print("User created successfully.")

				# Commit changes to database
				self.database.commit()

				# Return result
				return True

			else: # Failure

				# Raise exception
				raise ValueError("Username already exists.")

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

			if result[0] == 'TRUE': # User exists
				
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

				else: # Password hashes don't match

					# Raise exception
					raise ValueError("Incorrect password.")

			elif result[0] == 'FALSE': # User does not exist

				# Raise exception
				raise ValueError("User does not exist.")

		except Exception as exception:

			# Print exception
			print(exception)

			# Return result
			return False

	def generate(self, username_x, username_y):
		"""Generates a new key"""

		return urandom(7)

	def retrieve(self, username_x, username_y):
		"""Retrieves a stored key"""

if __name__ == "__main__":
	db = database()
	db.create_user('matthew', 'password')
	db.login('matthew', 'password')
	db.login('matthew1', 'password')
	db.login('matthew', 'password1')
