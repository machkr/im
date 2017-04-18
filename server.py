from contextlib import suppress
from database import *
from diffiehellman import DiffieHellman
from random import SystemRandom
import os
import socket
import string
import sys
import threading
import time

# Dictionary of users with corresponding socket
CONNECTED_USERS = {'server': None}

# Dictionary of users with the server's corresponding Diffie-Hellman object
DH = {'server': None}

# Dictionary of connected users with whether they've been assigned a key
CONNECTIONS = {('server', 'server'): True}

# Initialize database connectionn
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
	print('[SERVER]: Starting connected users thread...')
	user_list_thread = threading.Thread(target=print_connected_users)
	user_list_thread.start()

	# Start thread to handle key assignments
	print('[SERVER]: Starting key assignment thread...')
	key_assignment_thread = threading.Thread(target=assign_keys)
	key_assignment_thread.start()

	# loop to handle client connections
	while True:

		# Accept client connection
		(client_socket, address) = server_socket.accept()

		# Print connection information
		print('[SERVER]: Connection received from', address, '.')

		# Start thread to handle client connection
		print('[SERVER]: Starting client connection thread...')
		client_thread = threading.Thread(target=client_connection, args=(client_socket,address))
		client_thread.start()

def client_connection(sock, addr):
	"""
	Handles client connection with the server
	"""

	print('[SERVER]: Client connection thread started.')

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
				print('[SERVER]: Receieved Diffie-Hellman request from client.')

				# Extract Diffie-Hellman parameters from data
				generator, prime_group, client_public_key = data.strip().split('++')

				# Initialize new Diffie Hellman object for this client
				DH[source] = DiffieHellman(int(generator), int(prime_group), 256)

				print('Server Public Key:', DH[source].public_key)

				# Generate shared secret key using client's public key
				DH[source].genkey(int(client_public_key))

				# Generate hash of generated secret key
				hash = DH[source].digest(DH[source].secret_key)

				# New psuedorandom object
				random = SystemRandom()

				# Generate random nonce
				nonce = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))

				# Notify user of response being sent
				print('[SERVER]: Sending Diffie-Hellman response to client.')

				# Send server's public key, hash of the secret key, and a challenge
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:'
				 + str(DH[source].public_key) + '++' + str(hash) + '++' + str(nonce) + '!!sid:1'))

			# Verification of Diffie-Hellman shared key
			elif sid == '2' and destination == 'server':

				# Notify user that verification has been receieved
				print('[SERVER]: Receieved final verification from client.')

				if not DH[source].versecretkey(data, DH[source].nonce):

					# Notify user of unsucessful authentication
					print('[SERVER]: Failed to verify key.')

					# Close socket
					sock.close()

				else: # Verification successful

					# Notify users of successful verification
					print('[SERVER]: Key verified.')

			# Client-to-client communication initialization
			elif sid == '3' and destination != 'server':

				# Print contents of receieved data
				print('[SERVER]: Source: ', source, ' Destination: ', destination, ' Data: ', data, 'SID: ', sid)

				# Verify by decrypting data
				if DB.decrypt(DH[source].secret_key, data) == 'init':

					# Add username and socket to dictionary for each message received
					add_new_connection(source, sock)

					# If the destination user is connected
					if is_user_connected(destination):

						# Create the connection between the two users
						CONNECTIONS[(source, destination)] = False 

						# Send message to client indicating user is online
						sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:true' +  '!!sid:4'))

					else: # Destination user is not connected

						# Send message to client indicating user is offline
						sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:false' +  '!!sid:4'))
				
				# Decrypted data was not 'init'
				else:

					# Notify user that client was unauthenticated
					print('[SERVER]: Client attempted to initiate conversation without encryption.')

					# CLose socket
					sock.close()
			# else:

			# 	# Send message to client
			# 	sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:data not sent user not online' + '!!sid:9'))

			# Check that destination user is connected and not the server
			elif is_user_connected(destination) and destination != 'server':

				# Print contents of receieved data
				print('[SERVER]: Source: ', source, ' Destination: ', destination, ' Data: ', data, 'SID: ', sid)

				source_data = DB.decrypt(DH[source].secret_key, data)
				destination_data = DB.encrypt(DH[destination].secret_key, source_data)

				# Forward data to destination user's socket
				CONNECTED_USERS[destination].sendall(str.encode('s:' + source + '!!' + 'd:' + destination + '!!' + 'data:' + destination_data + '!!sid:9'))

				# Notify user that data was sent
				print('[SERVER]: Data from', source, 'sent to', destination, '.')

			else:
				print('[SERVER]: Data from', source, 'not sent to', destination, 'because destination is not connected.')
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:data not sent user not online' + '!!sid:9'))

		except Exception as exception:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			print(exc_type, fname, exc_tb.tb_lineno, exception)
			# print("[SERVER]: Error:", exception, '.')
			break

	sock.close()

def is_user_connected(username):
	"""
	Checks if a user is currently connected
	"""

	# If username is in dictionary of connected users
	if username in CONNECTED_USERS:

		# Return true
		return True

	# Otherwise
	else:

		# Return false
		return False

def add_new_connection(username, sock):
	"""
	Adds a user and their corresponding socket to the
	dictionary of user connections
	"""

	CONNECTED_USERS[username] = sock

def print_connected_users():
	"""
	Handles listing the currently connected users and
	current connections
	"""

	# Notify user of thread starting
	print('[SERVER]: Connected users thread started.')

	# Loop continuously
	while True:
		print('[SERVER]: Users: ' + str(list(CONNECTED_USERS.keys())))
		print('[SERVER]: Connections:' + str(list(CONNECTIONS.keys())))
		time.sleep(10)

def assign_keys():

	# Notify user of thread starting
	print('[SERVER]: Key assignment thread started.')

	# Loop continuously
	while True:
		time.sleep(1)

		# For each connection
		for connection in CONNECTIONS.keys():

			# If connection does not have a key assigned
			if CONNECTIONS[connection] == False:

				# Set source and destination based on connection
				source = connection[0]
				destination = connection[1]

				# Generate a key
				key = DB.establish(source, destination)

				# Notify user that a key has been generated
				print('[SERVER]: Generated key for', source, 'and', destination, ':', DB.encode(key))

				# Encrypt key for each user it is to be sent to
				key_source = DB.encrypt(DH[source].secret_key, key)
				key_destination = DB.encrypt(DH[destination].secret_key, key)

				# Send the negotiated key to each user
				CONNECTED_USERS[source].sendall(('s:server!!d:' + source + '!!data:KEYGEN-' + key_source + '!!sid:9999'))
				CONNECTED_USERS[destination].sendall(('s:server!!d:' + destination + '!!data:KEYGEN-' + key_destination + '!!sid:9999'))

				# Set key assignment to true
				CONNECTIONS[connection] = True

if __name__ == '__main__':
	main()
