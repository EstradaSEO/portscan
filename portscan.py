#!/usr/bin/python3

import nmap

print("[Info tool] => Scanning open ports through IP address")
print(" Source https://pypi.org/project/python-nmap/\n")

host= input("[+] Enter IP targeted: ")
nm= nmap.PortScanner()
opened_ports="-p "
count=0
results= nm.scan(hosts=host, arguments="-n -Pn -T5")
#print (results)
print("Host : %s" % host)
print("State : %s" % nm[host].state())
for proto in nm[host].all_protocols():
    print("Protocol : %s" % proto)
    lport = nm[host][proto].keys()
    sorted (lport)
    for port in lport:
        print ("port : %s\tstate : %s" % (port, nm[host][proto][port]['state']))
        if count==0:
        	opened_ports= opened_ports+" "+str(port)
        	count=1
        else:
        	opened_ports= opened_ports+","+str(port)

print("\nOpened Ports:"+opened_ports+" "+str(host))	
