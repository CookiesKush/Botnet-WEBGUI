import os
stream = os.popen('mkdir test')
output = stream.read()
print(output)