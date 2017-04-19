from database import *
from diffiehellman import DiffieHellman
from getpass import getpass
from random import SystemRandom
from threading import Thread
import socket
import sys
import time
import os

# Server connection parameters
IP = '127.0.0.1'
PORT = 8888

# Global client variables
DESTINATION_LOGGED_IN = False
SERVER_AUTHENTICATED = False
LOGGED_IN = False
CLIENT_KEY = None	# Key shared with destination user
SERVER_KEY = None	# Key shared with server

# Initialize database connection
DB = database()

# Diffie-Hellman object, initialized once authenticated
DH = None

def main():
	"""
	Primary functionality of the client
	"""

	# Access global variables
	global LOGGED_IN
	global SERVER_AUTHENTICATED
	global DESTINATION_LOGGED_IN
	global SERVER_KEY
	global DH

	# While user is not logged in
	while not LOGGED_IN:

		# Get username
		username = input('[CLIENT]: Username: ')

		if username == 'server':
			print('[CLIENT]: Invalid username: try again.')
			continue

		# Get password
		password = getpass('[CLIENT]: Password: ')

		# Attempt to log in
		LOGGED_IN = DB.login(username, password)

	# User was successfully authenticated
	print('[CLIENT]: Authentication successful.')

	# Attempt to connect to server
	print('[CLIENT]: Attempting to connect to remote server.')

	# Create socket for client
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		# Connect to the server
		client_socket.connect((IP, PORT))

		# Print success message
		print('[CLIENT]: Connection successful.')

	except Exception as exception:

		# Unable to connect
		print('[CLIENT]: Error: could not connect to ', IP, ':', PORT, '.', sep='')
		sys.exit()

	print('[CLIENT]: Initiating Diffie-Hellman key exchange.')

	# New psuedorandom object
	random = SystemRandom()

	# Select Diffie-Hellman generator
	generator = random.choice([2, 3, 5, 7])

	# Select Diffie-Hellman prime group
	prime_group = random.choice([5, 14, 15, 16, 17, 18])

	# Generate Diffie-Hellman public/private key pair
	DH = DiffieHellman(generator, prime_group, 256)

	# Send Diffie-Hellman key exchange information
	client_socket.sendall(str.encode('s:' + username + '!!d:server!!data:' + str(generator) + '++' + str(prime_group) + '++' + str(DH.public_key) +'!!sid:0'))

	# Notify user that Diffie-Hellman is being sent
	print('[CLIENT]: Diffie-Hellman request sent.')

	# Start client receiving thread
	thread_receive = Thread(target=recv_thread, args=(client_socket, username,))
	thread_receive.start()

	# While key has yet to be negotiated with server
	while not SERVER_AUTHENTICATED:

		# Wait
		time.sleep(1)

	# Request username of user to communicate with
	destination = input('[CLIENT]: Destination User: ')

	# Loop continuously until ready to send messages
	while not DESTINATION_LOGGED_IN:

		# Encrypt initialization message
		data = DB.encrypt(SERVER_KEY, 'init')

		# Send initialization message to server
		client_socket.sendall(str.encode('s:' + username + '!!d:' + destination + '!!data:' + data + '!!sid:3'))

		# Wait
		time.sleep(5)

	# Start client input thread
	thread_input = Thread(target=input_thread, args=(client_socket, username, destination))
	thread_input.start()

def input_thread(sock, username, destination):
	"""
	Handles sending messages from the client
	"""

	# Access global variables
	global CLIENT_KEY
	global SERVER_KEY

	# Notify user of thread starting
	print("[CLIENT]: Input thread started.")

	# Loop continuously
	while True:

		# Get user input
		data = input()

		# Check if user wishes to exit client
		if data == 'exit':
			break

		# Encrypt with key shared between clients
		ciphertext = DB.encrypt(CLIENT_KEY, data)

		# Encrypt with key shared between client and server
		ciphertext = DB.encrypt(SERVER_KEY, ciphertext)

		# Send encrypted message -- had .encode before
		sock.sendall(str.encode('s:' + username + '!!' + 'd:' + destination + '!!' + 'data:' + ciphertext + '!!sid:9'))

	# Close socket
	sock.close()

def recv_thread(sock, username):
	"""
	Handles receiving messages from server
	"""

	# Access global variables
	global SERVER_AUTHENTICATED
	global DESTINATION_LOGGED_IN
	global CLIENT_KEY
	global SERVER_KEY
	global DH

	# Notify user of thread starting
	print("[CLIENT]: Receiving thread started.")
	data = ""

	# Loop continuously
	while True:
		try:
			# Receive 4KB of data from the socket
			raw_data = sock.recv(4096)

			# End thread if no data received
			if not raw_data:
				break

			# Parse data
			raw_data = raw_data.decode().strip().split('!!')

			# Strip fields of the data
			source = raw_data[0][2:].strip()
			destination = raw_data[1][2:].strip()
			data = raw_data[2][5:].strip()
			sid = raw_data[3][4:].strip()

			# Diffie-Hellman reply
			if sid == '1' and source == 'server':

				# Notify user
				print('[CLIENT]: Received Diffie-Hellman response from server.')

				# Extract Diffie-Hellman response parameters
				server_public_key, key_hash, nonce = data.strip().split('++')

				# Generate shared secret key using server's public key
				DH.genkey(int(server_public_key))

				# Verify shared secret key using receieved hash
				if not DH.versecretkey(key_hash):

					# Notify user of unsucessful authentication
					print('[CLIENT]: Failed to verify key.')

					# End program
					sys.exit()

				else: # Verification successful

					# Notify user of successful authentication
					print('[CLIENT]: Key verified.')

					# Set global variables
					SERVER_KEY = DH.secret_key
					SERVER_AUTHENTICATED = True

				# Hash nonce with secret key
				hash = DH.digest(SERVER_KEY, nonce)

				# Notify user of further verification
				print('[CLIENT]: Sending final verification to server.')

				# Send verification to server
				sock.sendall(str.encode('s:' + username + '!!' + 'd:server!!' + 'data:' + str(hash) + '!!sid:2'))

			# Check if destination user is online
			elif sid == '4' and data == 'true' and source =='server':

				# Set global variable
				DESTINATION_LOGGED_IN = True

			# Check for a client-client key
			elif data[0:6] == 'KEYGEN':

				# DEBUG
				print('DEBUG:', data)

				# Extract key
				CLIENT_KEY = DB.decrypt(SERVER_KEY, data[7:])

				# While key is not divisible by 4
				while len(CLIENT_KEY) % 4 != 0:

					# Replace base-64 padding
					CLIENT_KEY += '='

				# Notify user that a key has been receieved
				print('[CLIENT]: Received a key for communication:', CLIENT_KEY)

				# Continue looping
				continue

		# Catch error in receiving data
		except Exception as exception:
			print("[CLIENT]: Error:", exception, '.')

			# Exit program
			sys.exit()

		# If data exists
		if (data != "" or data) and source != 'server':

			# If client key was extracted
			if CLIENT_KEY:

				try:
					# Decrypt the data
					plaintext = DB.decrypt(CLIENT_KEY, data)

					# Print the decrypted message
					print('[' + source + ']: ' + plaintext)

				except:
					pass
			else:

				# Print encrypted message
				print('[' + source + ']: ' + data)

if __name__ == '__main__':
	main()