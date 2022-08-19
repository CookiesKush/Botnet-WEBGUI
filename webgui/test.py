# bandwidth_monitor.py
# 
# Author: Derek Haas
# Description: Use psutil to get the net io counters to report data usage
#
# Date: June 26  2020
#

import psutil
import time
import ctypes



# Get the all the network stats for the first calculation
netStats = psutil.net_io_counters(pernic=True)

# Get the bytes sent and received for the different interfaces
sentStart = []
receivedStart = []
for interface in netStats:
  sentStart.append(netStats[interface][1])
  receivedStart.append(netStats[interface][2])


dataTotal = 0

while True:
	# Get the current data
	netStats = psutil.net_io_counters(pernic=True)
	
	for i,interface in enumerate(netStats):
		receivedData = netStats[interface][2] - receivedStart[i]
		dataTotal += receivedData
	


	
	print('Data recieved: %.2f MB'%dataTotal)
	ctypes.windll.kernel32.SetConsoleTitleW(f"Data Sent: %.2f MB"%dataTotal)

	
	# Get the bytes sent and received for the different interfaces
	sentStart = []
	receivedStart = []
	for interface in netStats:
		sentStart.append(netStats[interface][1])
		receivedStart.append(netStats[interface][2])

	time.sleep(0.2)

