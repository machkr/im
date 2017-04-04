import socket
import sys
import threading
import time
from contextlib import suppress
from database import *
from base64 import b64encode, b64decode


#dict mappting usernames to their respective sockets
connected_users = {'server':None}
connections = {('server', 'server'):True}
passwords = {'alice':'123', 'mike':'123', 'sterling':'applesauce', 'matt':'password'}
db = database()

def main():
	print('[S]: Initializing server.')
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	print('[S]: Socket created.')
	server_socket.bind(('localhost', 8888))

	print('[S]: Socket bound.')
	server_socket.listen(10)

	user_list_thread = threading.Thread(target=print_connected_users)
	user_list_thread.start()

	key_assignment_thread = threading.Thread(target=assign_keys)
	key_assignment_thread.start()

	while True:
		(client_socket, address) = server_socket.accept()
		print('[S]: Connection received from ', address, '.')

		client_thread = threading.Thread(target=client_connection, args=(client_socket,address))
		client_thread.start()

def client_connection(sock, addr):
	while True:
		try:
			data = sock.recv(4096)

			if not data:
				break

			#data parsing
			data = data.decode()
			data.strip()
			data_split = data.split('!!')
			source = data_split[0][2:].strip()
			destination = data_split[1][2:].strip()
			message = data_split[2][5:].strip()
			sid = data_split[3][4:].strip()
			print('[S]: Source: ', source, ' Destination: ', destination, ' Message: ', message, 'SID: ', sid)

			if sid == '0' and message == 'init':
				#add username and socket to dictionairy for each message received
				add_new_connection(source, sock)

				if is_user_connected(destination):
					connections[(source,destination)] = False

				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:ack_init' +  '!!sid:1'))
				time.sleep(1)
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:ack_init' +  '!!sid:2'))


			#send message to destination if the destination is connected, and is not the server itself
			#the server itself is exluded, as an initial message is always sent to the server as a 'login'
			#message after a client authenticates

			if is_user_connected(destination) and destination != 'server':
				connected_users[destination].sendall(str.encode('s:' + source + '!!' + 'd:' + destination + '!!' + 'data:' + message + '!!sid:9'))
				print('[S]: Data from ', source, ' sent to ', destination)
			elif destination == 'server':
				pass
			else:
				print('[S]: Data from ', source, ' NOT sent to ', destination, ' because destination not connected.')
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:data not sent user not online' + '!!sid:9'))

		except Exception as e:
			print("[S]: User logged out.")

			with suppress(Exception):
				for key in connected_users.keys():
					if connected_users[key] == sock:
						del connected_users[key]
			break

	sock.close()

def is_user_connected(username):
	'''
	Check if user is connected to the server
	'''

	if username in connected_users:
		return True
	else:
		return False

def add_new_connection(username, sock):
	'''
	Add new connection to list of connections to the server
	'''

	connected_users[username] = sock

def print_connected_users():
	'''
	Continuously print logged in users
	'''

	while True:
		print('[S]:' + str(connected_users.keys()))
		print('[S]:' + str(connections.keys()))
		time.sleep(10)

def assign_keys():
	while True:
		time.sleep(1)
		for connection in connections.keys():
			if connections[connection] == False:
				source = connection[0]
				destination = connection[1]

				key = (db.establish(source, destination))
				encoded = b64encode(key)
				key = encoded.decode()

				print('[S]: Generated key for ', source, ' and ', destination, ': ', key)

				connected_users[source].sendall(('s:server!!d:' + source + '!!data:KEYGEN-' + key + '!!sid:9999').encode())
				connected_users[destination].sendall(('s:server!!d:' + destination + '!!data:KEYGEN-' + key + '!!sid:9999').encode())

				connections[connection] = True

if __name__ == '__main__':
	main()