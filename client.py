import socket
import sys
import threading
import time
import os
from database import *

IP = '127.0.0.1'
PORT = 8888
SERVER_AUTHENTICATED = False
LOGGED_IN = False
DESTINATION_LOGGED_IN = False
db = database()
MASTER_KEY = None

def main():
	global LOGGED_IN
	global SERVER_AUTHENTICATED
	global DESTINATION_LOGGED_IN

	while not LOGGED_IN:
		username = input('[C]: Username: ')
		password = input('[C]: Password: ')

		LOGGED_IN = db.login(username, password)

	print('[C]: Authentication successful.')

	print('[C]: Attempting to connect to remote server.')
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		client_socket.connect((IP, PORT))
		print('[C]: Connection successful.')
	except:
		print('[C]: Could not connect to ', IP, ':', PORT, '.', sep='')
		sys.exit()

	destination = input('[C]: Destination username: ')

	#client_socket.sendall(str.encode('s:' + username + '+d:' + destination + '+data:init+sid:0'))

	thread_receive = threading.Thread(target=recv_thread, args=(client_socket,))
	thread_receive.start()

	while (not SERVER_AUTHENTICATED) and (not DESTINATION_LOGGED_IN):
		client_socket.sendall(str.encode('s:' + username + '!!d:' + destination + '!!data:init!!sid:0'))
		time.sleep(5)

	thread_input = threading.Thread(target=input_thread, args=(client_socket, username, destination))
	thread_input.start()

def input_thread(sock, username, destination):
	global MASTER_KEY

	while True:
		data = input()

		if data == 'exit':
			break
		data_encrypted = db.encrypt(db.decode(MASTER_KEY), data)
		message = db.encode(data_encrypted)

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
			data = data.decode()
			data.strip()
			data_split = data.split('!!')
			source = data_split[0][2:].strip()
			destination = data_split[1][2:].strip()
			message = data_split[2][5:].strip()
			sid = data_split[3][4:].strip()

			if sid == '1' and message == 'ack_init':
				SERVER_AUTHENTICATED = True
			if sid == '2' and message == 'true':
				DESTINATION_LOGGED_IN = True
			if message[0:6] == 'KEYGEN':
				MASTER_KEY = message[7:]
				print('[C]: Received a key for communication:', MASTER_KEY)
				continue

		except Exception as e:
			print('[C]: Connection with server lost. Aborting program.')
			print(e)
			sys.exit()

		if data != "" or data:
			
			if MASTER_KEY:
				message = db.decode(message) #bytes
				decrypted = db.decrypt(db.decode(MASTER_KEY), message)

				print('[' + source + ']: ' + decrypted)
			else:
				print('[' + source + ']: ' + message)

main()