import psutil, time


blocked_process = []

def process_control():
    while True: 
        if blocked_process:
            for proc in psutil.process_iter():
                try:
                    if proc.name().split(".")[0] in blocked_process: proc.kill()
                except: pass
        else: print("No process to kill")
        time.sleep(0.5)



process_control()