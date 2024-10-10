PRE INSTALLATION

![image](https://github.com/user-attachments/assets/fb5929d1-8432-4dce-86bc-d35031e25858)

And before performing your coding you must install Wimpcp or npcap

WIMPCAP INSTALLATION
![342219303-48f3a796-b115-490f-a2f4-c858366a0a93](https://github.com/user-attachments/assets/d5513597-d139-41cc-9cf9-88e8dbc9d651)

NPCAP INSTALLATION
![342219629-4edf4646-5646-420c-947d-97d40ebaa2fe](https://github.com/user-attachments/assets/90c00d74-6592-450a-90a4-ce9473fade52)

CODE

    import scapy.all as scapy

    def packet_callback(packet):
      if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

    print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

    if packet.haslayer(scapy.TCP):
        try:
            payload = packet[scapy.Raw].load
            decoded_payload = payload.decode('utf-8', 'ignore')
            print(f"TCP Payload")
        except (IndexError, UnicodeDecodeError):
            print("Unable to decode TCP payload.")

    elif packet.haslayer(scapy.UDP):
        try:
            payload = packet[scapy.Raw].load
            decoded_payload = payload.decode('utf-8', 'ignore')
            print(f"UDP Payload")
        except (IndexError, UnicodeDecodeError):
            print("Unable to decode UDP payload.")

    def start_sniffing():
      scapy.sniff(store=False, prn=packet_callback)
    
    start_sniffing()
