import threading

QUEUE = []

def queue_add(botNum, command):
    QUEUE.append(f"{botNum}:{command}")

def queue_next():
    return QUEUE.pop(-1)

def run_queue():
    while True:
        try: 
            out = (queue_next())
            # split out into botNum and command
            botNum, command = out.split(':')
            print(f"{botNum}\n{command}")
        except IndexError: pass
    

queue_add(1, 'Hello')
threading.Thread(target=run_queue).start()