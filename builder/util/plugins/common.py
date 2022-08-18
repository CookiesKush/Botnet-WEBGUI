import os, sys, ctypes, shutil
from colorama import Fore, Style
from cookies_package import *
from time import sleep



'''
MAIN FUNCTIONS
'''
def temp():
    temp = os.getenv("TEMP")
    return temp

def cleanup(filename):
    try:
        os.remove(f'{filename}.spec');os.remove(f'{filename}.py');shutil.rmtree('build');shutil.rmtree('dist')
    except: pass

def compile(filename):
    os.system(f"pyinstaller --onefile --noconsole --clean --log-level=ERROR -n {filename} {filename}.py")

def compile_forceadmin(filename):
    os.system(f"pyinstaller --onefile --noconsole --uac-admin --clean --log-level=ERROR -n {filename} {filename}.py")


'''
OTHER FUNCTIONS
'''

def clear():
    os.system('cls')

def settitle(str):
    ctypes.windll.kernel32.SetConsoleTitleW(f"{str} | CookiesKush420#9599 | BETA v1.0.0")

def print_slow(str):
    for letter in str: sys.stdout.write(letter);sys.stdout.flush();sleep(0.05)



'''
BANNERS
'''

banner = Style.BRIGHT + f'''{Fore.LIGHTGREEN_EX}
 

             __           .~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
           _/  \_         |    {Fore.CYAN}Welcome to BotNet Builder{Fore.LIGHTGREEN_EX}       |
           ({Fore.LIGHTRED_EX}҂{Fore.WHITE}`_´{Fore.LIGHTGREEN_EX})         {Fore.LIGHTGREEN_EX}|  {Fore.CYAN}New Features Coming Soon...{Fore.LIGHTGREEN_EX}   |
           <,{Fore.LIGHTBLACK_EX}═╦╤─{Fore.YELLOW} ҉ {Fore.LIGHTRED_EX}- -   {Fore.LIGHTGREEN_EX}'─────────────────────────────────'
           _/--\_         
   

    {Fore.LIGHTGREEN_EX}1{Fore.RESET}.{Fore.CYAN} Create client payload
    {Fore.LIGHTGREEN_EX}2{Fore.RESET}.{Fore.CYAN} Create server
    {Fore.LIGHTGREEN_EX}420{Fore.RESET}.{Fore.LIGHTRED_EX} Exit RAT Builder
{Fore.RESET}'''