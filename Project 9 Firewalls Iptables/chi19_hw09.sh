#! /bin/bash

### HW#: 09
### Name: Max Chi
### ecn login: chi19
### Due Date: 3/27/2018

#can add sudo to all bash commands to implement superuser

###Flush the iptables
sudo iptables -t nat -F
sudo iptables -F

### a) Place no restriction on outbound packets.
sudo iptables -I OUTPUT 1 -j ACCEPT

### b) Block a list of specific ip addresses for all incoming connections.
ListIPs=("128.48.86.7" "128.10.6.3" "128.31.2.5")
for x in ${ListIPs[@]}
do
    sudo iptables -A INPUT -s $x -j DROP
done

### c) Block your computer from being pinged by all other hosts.
###referenced lecture 18.11 from professor Kak's notes 
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

### d) Set up port-forwarding forom an unused port of your choice to port 22 on your computer. Test if you can ssh into your machine using both ports.

###Set up randomly chosen unused port (port 50)
sudo iptables -A INPUT -p tcp --dport 50 -j ACCEPT
###Forward port 50 to port 22. Referenced from professor Kak's notes lecture 18.13
sudo iptables -t nat -A PREROUTING -p tcp -d 128.20.10.6 --dport 50 -j DNAT --to-destination 10.0.2.15:22

### e) Allow for SSH access (port 22) to your machine from only the ecn.purdue.edu domain.
sudo iptables -A INPUT ! -s ecn.purdue.edu -p tcp --dport 22 -j REJECT


### f) Assuming you are running an HTTPD server on your machine that can make available your entire home directory to the outside world, write a rule that allows only a single IP address in the internet to access your machine for the HTTP service.
sudo iptables -A INPUT -p tcp ! -s 128.161.121.35 --dport 80 -j REJECT


### g) Permit Auth/Ident (port 113) that is used by some services like SMTP and IRC.
sudo iptables -A INPUT -p tcp --dport 113 -j ACCEPT
