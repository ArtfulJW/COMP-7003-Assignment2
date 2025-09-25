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
    TargetMAC_Address = hex_data[36:48]
    TargetIP_Address = hex_data[48:56]

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
    result2 = []
    for i in range(0, len(Sender_IP), 2):
        result2.append(int(((Sender_IP[i:i+2])),16))
    result2 = ".".join(str(item) for item in result2)
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {result2}")

    # Byte 18 to 23 is Target MAC Address
    result3 = ":".join(TargetMAC_Address[i:i+2] for i in range(0, len(TargetMAC_Address), 2))
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {result3}")

    # Byte 24 to 27 is Target IP Address
    result4 = []
    for i in range(0, len(TargetIP_Address), 2):
        result4.append(int(((TargetIP_Address[i:i+2])),16))
    result4 = ".".join(str(item) for item in result4)
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {result4}")

def parse_IPV4_header(hex_data):
    version = int(hex_data[0:1], 16)
    header_length = int(int(hex_data[1:2]) * 32 / 8)
    total_length = int(hex_data[4:8], 16)

    flags_fragoffset = bin(int(hex_data[12:14], 16))[:3]
    flags_fragoffset_asBits = bin(int(hex_data[12:14], 16))[2:]
    reserved_flag = flags_fragoffset_asBits[:1]
    dont_fragment_flag = flags_fragoffset_asBits[1:2]
    more_fragment_flag = flags_fragoffset_asBits[2:3]
    fragment_offset = int(hex_data[14:16], 16)

    protocol = int(hex_data[18:20], 16)
    source_ip = hex_data[24:32]
    destination_ip = hex_data[32:40]

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[0:1]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {str(header_length) + ' bytes'}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {flags_fragoffset}")
    print(f"    {'Reserved:':<25} {reserved_flag:<20}")
    print(f"    {'DF (Do not Fragment):':<25} {dont_fragment_flag:<20}")
    print(f"    {'MF (More Fragment):':<25} {more_fragment_flag:<20}")
    print(f"    {'Fragment Offset:':<25} {hex(int(hex_data[14:16], 16))} | {fragment_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")

    result = []
    for i in range(0, len(source_ip), 2):
        result.append(int(((source_ip[i:i+2])),16))
    result = ".".join(str(item) for item in result)
    print(f"  {'Source IP:':<25} {source_ip:<20} | {result}")

    result2 = []
    for i in range(0, len(destination_ip), 2):
        result2.append(int(((destination_ip[i:i+2])),16))
    result2 = ".".join(str(item) for item in result2)
    print(f"  {'Destination IP:':<25} {destination_ip:<20} | {result2}")

def parse_udp_header(hex_data):
    source_port = int(hex_data[:4], 16)
    destination_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    payload = hex_data[16:]

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {payload}")