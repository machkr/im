from tkinter import *
from tkinter import ttk
from database import *
import MySQLdb
import socket
import sys
import threading
import time

IP = '127.0.0.1'
PORT = 8888
USERNAME = ''
SOCK = None
DATA_BUFFER = ''

class MyApp:

	db = database()

	def __init__(self, myParent):
		"""
		input: parent object, should be root
		output: none
		description: initial login screen, calls login functions for application
		"""

		# global vars
		self.username = "" #controls the username of the logged in user
		
		# setting parent for the window
		self.parent = myParent

		# create and pack container
		self.myContainer1 = Frame(myParent)
		self.myContainer1.pack()

		self.prompt = Label(self.myContainer1, text="Please Enter your Account Credentials:")
		self.prompt.pack(side="top", fill='both', expand=True, padx=6, pady=20)

		# create and pack input fields from username, password
		Label(self.myContainer1, text="Username").pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.username = Entry(self.myContainer1)
		self.username.pack(side="top", fill='both', expand=True, padx=4, pady=4)
		Label(self.myContainer1, text="Password").pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.password = Entry(self.myContainer1, show="*", width=15)
		self.password.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		# creation of login button, binding to appropriate actions
		self.button1 = Button(self.myContainer1)
		self.button1["text"] = "Login"
		self.button1.pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.button1.bind("<Button-1>", self.login_click)

		# creation of user creation button, binding to appropriate actions
		self.button2 = Button(self.myContainer1)
		self.button2["text"] = "Create Account"
		self.button2.pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.button2.bind("<Button-1>", self.create_click)

		# error display for login
		self.login_error = Label(self.myContainer1, text="", font=(40))
		self.login_error.pack(side="top", fill='both', expand=True, padx=4, pady=4)

	#####################################
	#WINDOW LAYOUT AND DISPLAY FUNCTIONS#
	#####################################

	def main_menu(self):
		"""
		input: none
		output: none
		description: display main menu
		"""

		global USERNAME

		print("main menu initialized...")

		# destroy and resize orginal frame
		self.myContainer1.destroy()
		self.parent.minsize(width=700, height=500)

		# create and pack container
		self.myContainer1 = Frame(self.parent)
		self.myContainer1.pack()

		self.username_label = Label(self.myContainer1, text=("Username: " + str(USERNAME)), font=(30))
		self.username_label.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		self.connect_error = Label(self.myContainer1, text="", font=(30))
		self.connect_error.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		self.create_connection(IP, PORT)

		# create and pack input fields from username, password
		Label(self.myContainer1, text="Destination username:").pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.destination = Entry(self.myContainer1, width=15)
		self.destination.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		# creation of login button, binding to appropriate actions
		self.button1 = Button(self.myContainer1)
		self.button1["text"] = "Connect"
		self.button1.pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.button1.bind("<Button-1>", self.begin_chat_click)

	def chat_menu(self):
		"""
		input: none
		output: none
		description: display main menu
		"""

		global USERNAME
		global DATA_BUFFER

		print("main menu initialized...")

		# destroy and resize orginal frame
		self.myContainer1.destroy()
		self.parent.minsize(width=700, height=500)

		# create and pack container
		self.myContainer1 = Frame(self.parent)
		self.myContainer1.pack()

		self.username_label = Label(self.myContainer1, text=("Username: " + str(USERNAME)), font=(30))
		self.username_label.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		# create and pack input fields from username, password
		Label(self.myContainer1, text="Message:").pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.message = Entry(self.myContainer1, width=15)
		self.message.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		# creation of login button, binding to appropriate actions
		self.button1 = Button(self.myContainer1)
		self.button1["text"] = "Send"
		self.button1.pack(side="top", fill='both', expand=True, padx=4, pady=4)
		self.button1.bind("<Button-1>", self.send_click)

		# create second container
		self.myContainer2 = Frame(self.parent, width=600, height=500, bd = 1, relief = GROOVE)
		self.myContainer2.pack(padx = 5, pady = 5)

		self.messages = Label(self.myContainer2, text="", font=(30))
		self.messages.pack(side="top", fill='both', expand=True, padx=4, pady=4)

		self.myContainer2.after(500, self.update_messages)


	########################
	#BUTTON CLICK FUNCTIONS#
	########################

	def login_click(self, event):
		"""
		input: event object
		output: none
		description: actions for login button
		"""

		global USERNAME

		print("login details:")

		USERNAME = self.username.get()

		print("username:", self.username.get())
		print("password:", self.password.get())
		logged_in = database.login(self.db, self.username.get(), self.password.get())

		if(logged_in):
			print("Beginning code once logged in...")
			self.main_menu()
		else:
			self.login_error['text'] = "Incorrect Login Information"
			self.login_error['fg'] = 'red'

	def create_click(self, event):
		"""
		input: event object
		output: none
		description: actions for creating accounts
		"""

		print("user creation details:")

		print("username:", self.username.get())
		print("password:", self.password.get())

		account_created = database.create_user(self.db, self.username.get(), self.password.get())

		if(account_created):
			pass
		else:
			self.login_error['text'] = "Error creating account"
			self.login_error['fg'] = 'red'

	def begin_chat_click(self, event):
		global DESTINATION
		DESTINATION = self.destination.get()
		self.begin_chat(USERNAME, self.destination.get())

	def send_click(self, event):
		global DESTINATION
		self.send_data(USERNAME, DESTINATION, self.message.get())
		self.messages['text'] = DATA_BUFFER

	########################
	#NETWORKING FUNCTIONS  #
	########################

	def create_connection(self, ip, port):
		global USERNAME
		global SOCK

		print("starting connection procedure...")
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			client_socket.connect((ip, port))
			print('[C]: Connection successful.')
			self.connect_error['text'] = "Connected to server"
		except:
			print('[C]: Could not connect to ',ip, ':', port)
			self.connect_error['text'] = "Could not connect to server"
			self.connect_error['fg'] = 'red'

		client_socket.sendall(str.encode('s:' + USERNAME + '+d:server+data:initialization'))
		SOCK = client_socket

	def begin_chat(self, username, destination):
		SOCK.sendall(str.encode('s:' + username + '+' + 'd:' + destination + '+' + 'data:has connected'))

		self.chat_menu()

		thread_receive = threading.Thread(target=self.recv_thread, args=(SOCK,))
		thread_receive.start()

	def send_data(self, username, destination, message):
		SOCK.sendall(str.encode('s:' + username + '+' + 'd:' + destination + '+' + 'data:' + message))

	def recv_thread(self, sock):
		print("[C]: Receive thread started.")
		data = ""
		global DATA_BUFFER

		while True:
			try:
				data = sock.recv(4096)
				DATA_BUFFER = data
			except:
				print('[C]: Connection with server lost. Aborting program.')
				sys.exit()

			if data != "" or data:
				print(data.decode())

	def update_messages(self):
		self.messages['text'] = DATA_BUFFER
		self.myContainer2.after(500, self.update_messages)
	

root = Tk()
root.minsize(width=700, height=500)
root.wm_title("CryptoMSG")
myapp = MyApp(root)
root.mainloop()