from contextlib import suppress
from database import *
from diffiehellman import DiffieHellman
from random import SystemRandom
from threading import Thread
import os
import socket
import string
import sys
import time

# Dictionary of users with corresponding socket
USERS = {'server': None}

# Count of currently connected users
USER_COUNT = 1

# Dictionary of users with server's Diffie-Hellman object
DH = {'server': None}

# Dictionary of connected users and whether key is assigned
CONNECTIONS = {('server', 'server'): True}

# COunt of current user connections
CONNECTION_COUNT = 1

# Initialize database connection
DB = database()

def main():
	"""
	Primary functionality of the server
	"""

	# Initialize server
	print('[SERVER]: Initializing...')
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind(('localhost', 8888))
	server_socket.listen(10)
	print('[SERVER]: Initialization complete.')

	# Start thread to handle the printing of connected users
	user_list_thread = Thread(target=print_connected_users)
	user_list_thread.start()

	# Start thread to handle key assignments
	key_assignment_thread = Thread(target=assign_keys)
	key_assignment_thread.start()

	# Notify user that server is ready
	print('[SERVER]: Ready to accept incoming connections.')

	# loop to handle client connections
	while True:

		# Accept client connection
		(client_socket, address) = server_socket.accept()

		# Print connection information
		print('[SERVER]: Connection received from ', address, '.', sep='')

		# Start thread to handle client connection
		client_thread = Thread(target=client_connection, args=(client_socket,address))
		client_thread.start()

def client_connection(sock, addr):
	"""
	Handles client connection with the server
	"""

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

			# Diffie-Hellman parameters from client
			if sid == '0' and destination == 'server':

				# Notify user that request has been receieved
				print('[SERVER]: Receieved Diffie-Hellman request from ', source, '.', sep='')

				# Extract Diffie-Hellman parameters from data
				generator, prime_group, client_public_key = data.strip().split('++')

				# Initialize new Diffie Hellman object for this client
				DH[source] = DiffieHellman(int(generator), int(prime_group), 256)

				# Generate shared secret key using client's public key
				DH[source].genkey(int(client_public_key))

				# Generate hash of generated secret key
				hash = DH[source].digest(DH[source].secret_key)

				# New psuedorandom object
				random = SystemRandom()

				# Generate random nonce
				nonce = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))

				# Notify user of response being sent
				print('[SERVER]: Sending Diffie-Hellman response to ', source, '.', sep='')

				# Send server's public key, hash of the secret key, and a challenge
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:' + str(DH[source].public_key) + '++' + str(hash) + '++' + str(nonce) + '!!sid:1'))

			# Verification of Diffie-Hellman shared key
			elif sid == '2' and destination == 'server':

				# Notify user that verification has been receieved
				print('[SERVER]: Receieved final verification from ', source, '.', sep='')

				# Check received hash against established secret key
				if not DH[source].versecretkey(data, nonce):

					# Notify user of unsucessful authentication
					print('[SERVER]: Failed to verify key.')

					# Close socket
					sock.close()

				else: # Verification successful

					# Notify users of successful verification
					print('[SERVER]: Key verified.')

					# Add username and socket to dictionary
					add_new_connection(source, sock)

			# Client-to-client communication initialization
			elif sid == '3':

				# Verify by decrypting data
				if str(DB.decrypt(DH[source].secret_key, data), 'utf-8') == 'init':

					# If the destination user is connected
					if is_user_connected(destination):

						# Create the connection between the two users
						CONNECTIONS[(source, destination)] = False
						CONNECTIONS[(destination, source)] = False

						# Encrypt message
						data = DB.encrypt(DH[source].secret_key, 'online')

					# Destination user is not connected
					else: 

						# Encrypt message
						data = DB.encrypt(DH[source].secret_key, 'offline')

					# Send message to client indicating user is online/offline
					sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:' + data +  '!!sid:4'))
				
				# Decrypted data was not 'init'
				else:

					# Notify user that client was unauthenticated
					print('[SERVER]: Client attempted to initiate conversation without encryption.')

					# CLose socket
					sock.close()

			# Check that destination user is connected and not the server
			elif is_user_connected(destination):

				# Check that destination is not server
				if destination == 'server':

					# If it is, continue
					continue

				# # Print contents of receieved data
				# print('[SERVER]: Source:', source, 'Destination:', destination, 'Data:', data, 'SID: ', sid)

				# Decrypt data received from source
				source_data = DB.decrypt(DH[source].secret_key, data)

				# Encrypt the data for the destination
				destination_data = DB.encrypt(DH[destination].secret_key, source_data)

				# Forward data to destination user's socket
				USERS[destination].sendall(str.encode('s:' + source + '!!' + 'd:' + destination + '!!' + 'data:' + destination_data + '!!sid:5'))

				# Notify user that data was sent
				print('[SERVER]: Data from ', source, ' sent to ', destination, '.', sep='')

			# Destination user not connected
			else:

				# Notify user that destination is not connected
				print('[SERVER]: Data from', source, ' was not sent to', destination, 'because destination is not connected.')

				# Encrypt message
				data = DB.encrypt(DH[source].secret_key, 'offline')

				# Send message to client that destination is offline
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:' + data + '!!sid:4'))

		# Catch exception
		except Exception as exception:

			# Print error
			print("[SERVER]: Error:", exception, '.')

			# Exit program
			sys.exit()

	sock.close()

def is_user_connected(username):
	"""
	Checks if a user is currently connected
	"""

	# If username is in dictionary of connected users
	if username in USERS:

		# Return true
		return True

	# Otherwise
	else:

		# Return false
		return False

def add_new_connection(username, sock):
	"""
	Adds a user and their corresponding socket to the
	dictionary of users
	"""

	USERS[username] = sock

def print_connected_users():
	"""
	Handles listing the currently connected users and
	current connections
	"""

	# Access global variables
	global USER_COUNT
	global CONNECTION_COUNT

	# Loop continuously
	while True:

		if len(USERS) != USER_COUNT:

			# Print connected users
			print('[SERVER]: Users: ' + str(list(USERS.keys())))

			# Update count
			USER_COUNT = len(USERS)

		if len(CONNECTIONS) != CONNECTION_COUNT:

			# Print user connections
			print('[SERVER]: Connections:' + str(list(CONNECTIONS.items())))

			# Update count
			CONNECTION_COUNT = len(CONNECTIONS)

def assign_keys():

	# Loop continuously
	while True:

		# Wait
		time.sleep(1)

		# For each connection
		for (source, destination) in CONNECTIONS.keys():

			# Server entries
			if source == 'server' or destination == 'server':

				# Skip
				continue

			# Attempt to generate a key (new or updated)
			key = DB.establish(source, destination)

			# Key not expired
			if not key:

				# Skip
				continue

			# Notify user that a key has been generated
			print('[SERVER]: Generated key of length ', len(key), ' for ', source, ' and ', destination, '.', sep='')

			# Encrypt key for each user it is to be sent to
			key_source = DB.encrypt(DH[source].secret_key, key)
			key_destination = DB.encrypt(DH[destination].secret_key, key)

			# Send the negotiated key to each user
			USERS[source].sendall(str.encode('s:server!!d:' + source + '!!data:KEYGEN-' + key_source + '!!sid:9999'))
			USERS[destination].sendall(str.encode('s:server!!d:' + destination + '!!data:KEYGEN-' + key_destination + '!!sid:9999'))

			# If connection does not have a key assigned
			if not CONNECTIONS[(source, destination)]:

				# Set key assignment to true
				CONNECTIONS[(source, destination)] = True
				CONNECTIONS[(destination, source)] = True

if __name__ == '__main__':
	main()
