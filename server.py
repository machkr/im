from contextlib import suppress
from database import *
import socket
import sys
import threading
import time

# Dictionary of users with corresponding socket
connected_users = {'server': None}

# Dictionary of connected users with whether they've been assigned a key
connections = {('server', 'server'): True}
passwords = {'alice':'123', 'mike':'123', 'sterling':'password', 'matt':'password'} #mapping of usernames to passwords

# Initialize database connectionn
db = database()

def main():
	print('[S]: Initializing server.')
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind(('localhost', 8888))
	server_socket.listen(10)

	#thread to handle the printing of connected users
	user_list_thread = threading.Thread(target=print_connected_users)
	user_list_thread.start()

	#thread to handle key assignments
	key_assignment_thread = threading.Thread(target=assign_keys)
	key_assignment_thread.start()

	#loop to handle client connections
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
			data = data.decode().strip().split('!!')

			source = data[0][2:].strip()
			destination = data[1][2:].strip()
			message = data[2][5:].strip()
			sid = data[3][4:].strip()

			print('[S]: Source: ', source, ' Destination: ', destination, ' Message: ', message, 'SID: ', sid)

			#if this is an initialization message
			if sid == '0':
				message_verification = xor('init', passwords[source])

				#if the user is authentic
				if message == message_verification:
					#add username and socket to dictionairy for each message received
					add_new_connection(source, sock)

					#if  the destination user is connected
					if is_user_connected(destination):
						connections[(source,destination)] = False #create the connection between the two users

					#send responses to the authenticated user
					print('[S]: User authenticated. Sending responses')
					sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:ack_init' +  '!!sid:1'))
					time.sleep(1)
					sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:ack_init' +  '!!sid:2'))
				else:
					print('[S]: User is attempting to authenticate with an invalid password')
					sock.close()
			else:
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:data not sent user not online' + '!!sid:9'))

			#if the destination user is connected, and the destination is not the server itself
			#retrieve the destination user's socket, forward the data
			if is_user_connected(destination) and destination != 'server':
				connected_users[destination].sendall(str.encode('s:' + source + '!!' + 'd:' + destination + '!!' + 'data:' + message + '!!sid:9'))
				print('[S]: Data from ', source, ' sent to ', destination)
			elif destination == 'server':
				pass
			else:
				print('[S]: Data from ', source, ' NOT sent to ', destination, ' because destination not connected.')
				sock.sendall(str.encode('s:server' + '!!' + 'd:' + source + '!!' + 'data:data not sent user not online' + '!!sid:9'))

		except Exception as e:
			print("[S]: User logged out:", e)
			'''
			with suppress(Exception):
				for key in connected_users.keys():
					if connected_users[key] == sock:
						del connected_users[key]
			'''
			break

	sock.close()

def is_user_connected(username):
	if username in connected_users:
		return True
	else:
		return False

def add_new_connection(username, sock):
	connected_users[username] = sock

def print_connected_users():
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

				key = db.encode(db.establish(source, destination))

				print('[S]: Generated key for ', source, ' and ', destination, ': ', key)

				key_source = xor(key, passwords[source])
				key_destination = xor(key, passwords[destination])

				connected_users[source].sendall(('s:server!!d:' + source + '!!data:KEYGEN-' + key_source + '!!sid:9999').encode())
				connected_users[destination].sendall(('s:server!!d:' + destination + '!!data:KEYGEN-' + key_destination + '!!sid:9999').encode())

				connections[connection] = True

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
