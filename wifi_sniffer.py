from scapy.all import *

# Packet handler function
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source: {src_ip} → Destination: {dst_ip}")

# Get available network interfaces
def list_interfaces():
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print("\n[+] Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")
    return interfaces

if __name__ == "__main__":
    interfaces = list_interfaces()
    choice = int(input("\n[+] Select the interface number to sniff on: ")) - 1
    iface = interfaces[choice]

    print(f"\n[*] Starting packet sniffing on {iface}...\n")

    try:
        sniff(iface=iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffing...")
    except Exception as e:
        print(f"[!] Error: {e}")
