# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    operation = int(hex_data[12:16], 16)
    # MAC_Address = [int(hex_data[16:18]), int(hex_data[18,20]), int(hex_data[20,22]), int(hex_data[22,24]), int(hex_data[24,26]), int(hex_data[26:28])]
    MAC_Address = hex_data[16:28]
    Sender_IP = hex_data[28:36]

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")

    # Byte 2 to 3 is the Protocol Type
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")

    # Byte 4 is the Hardware Size
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")

    # Byte 5 is the Protocol Size
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")

    # Byte 6 and 7 is the Operation
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")

    # Byte 8 to 13 is the MAC Address
    result = ":".join(MAC_Address[i:i+2] for i in range(0, len(MAC_Address), 2))
    print(f"  {'MAC Address:':<25} {hex_data[16:28]:<20} | {result}")

    # Byte 14 to 17 is the IP Address
    # (Sender_IP[i:i+2] for i in range(0, len(Sender_IP)

    result2 = []
    for i in range(0, len(Sender_IP), 2):
        result2.append(int(((Sender_IP[i:i+2])),16))
    result2 = ".".join(str(item) for item in result2)


    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {result2}")


