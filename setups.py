import os, requests, pyautogui


if os.path.exists("C:\\Users\\Callum\\AppData\\Local\\Programs\\Python"):
    try:
        os.system("pip install --upgrade pip")
        os.system("pip install -r requirements.txt")
        os.system("pip uninstall enum34 -y")
    except Exception as e: print(e); exit()
else:
    print("Failed to find a python installation, installing python please wait...")
    r = requests.get("https://www.python.org/ftp/python/3.9.8/python-3.9.8-amd64.exe")
    with open("python.exe", "wb") as f: f.write(r.content)
    pyautogui.alert("Running the installer now\n\n\nMake sure to tick the 'Add Python 3.9.8 to PATH' checkbox then hit install now\nAfter thats done just close the program DONT click 'Disable path length limit' otherwise you will need to remove python and start all over")
    os.startfile("python.exe")
    exit()

os.system("cls")
print("Installed requirements successfully")