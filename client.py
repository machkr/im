from database import *
import os
import socket
import sys
import threading
import time

# Server connection parameters
IP = '127.0.0.1'
PORT = 8888

# Global client variables
DESTINATION_LOGGED_IN = False
SERVER_AUTHENTICATED = False
MASTER_KEY = None
LOGGED_IN = False
PASSWORD = ''

# Initialize database connection
db = database()

def main():
	global LOGGED_IN
	global SERVER_AUTHENTICATED
	global DESTINATION_LOGGED_IN
	global PASSWORD

	while not LOGGED_IN:
		username = input('[C]: Username: ')
		password = input('[C]: Password: ')
		LOGGED_IN = database.login(db, username, password)
		PASSWORD = password

	print('[C]: Authentication successful.')

	print('[C]: Attempting to connect to remote server')
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		client_socket.connect((IP, PORT))
		print('[C]: Connection successful.')
	except:
		print('[C]: Could not connect to ',IP, ':', PORT)
		sys.exit()

	destination = input('[C]: Destination username: ')

	thread_receive = threading.Thread(target=recv_thread, args=(client_socket,))
	thread_receive.start()

	while (not SERVER_AUTHENTICATED) and (not DESTINATION_LOGGED_IN):
		#XOR message
		message = xor('init', PASSWORD)

		client_socket.sendall(str.encode('s:' + username + '!!d:' + destination + '!!data:' + message + '!!sid:0'))
		time.sleep(5)

	thread_input = threading.Thread(target=input_thread, args=(client_socket, username, destination))
	thread_input.start()

def input_thread(sock, username, destination):
	global MASTER_KEY

	while True:
		data = input()

		if data == 'exit':
			break

		message = db.encode(db.encrypt(db.decode((MASTER_KEY)), data))

		sock.sendall(('s:' + username + '!!' + 'd:' + destination + '!!' + 'data:' + message + '!!sid:9').encode())

	sock.close()

def recv_thread(sock):
	print("[C]: Receive thread started.")
	data = ""

	global SERVER_AUTHENTICATED
	global DESTINATION_LOGGED_IN
	global MASTER_KEY

	while True:
		try:
			data = sock.recv(4096)

			#data parsing
			data = data.decode().strip().split('!!')

			source = data[0][2:].strip()
			destination = data[1][2:].strip()
			message = data[2][5:].strip()
			sid = data[3][4:].strip()

			#check if the server is authenticated
			if sid == '1' and message == 'ack_init':
				SERVER_AUTHENTICATED = True

			#check if destination user is online
			if sid == '2' and message == 'true':
				DESTINATION_LOGGED_IN = True

			#check for an exchanged key
			if message[0:6] == 'KEYGEN':
				print('DEBUG:', message)

				MASTER_KEY = xor(message[7:], PASSWORD)

				if (len(MASTER_KEY) % 4) != 0:
					MASTER_KEY = MASTER_KEY + '='

				print('[C]: Received a key for communication: ', MASTER_KEY)
				continue

		except Exception as e:
			print('[C]: Connection with server lost. Aborting program.')
			sys.exit()

		if data != "" or data:
			if MASTER_KEY:
				try:
					decrypted = db.decrypt(db.decode((MASTER_KEY)), db.decode(message))
					print('[' + source + ']: ' + decrypted)
				except:
					pass
			else:
				print('[' + source + ']: ' + message)

def xor(data, key):
	data_len = len(data)
	key_len = len(key)

	if data_len > key_len:
		key = key + ('0'*(data_len - key_len))
	elif data_len < key_len:
		key = key[0:data_len]
	return ''.join([chr(ord(one) ^ ord(two)) for (one, two) in zip(data, key)])

if __name__ == '__main__':
	main()