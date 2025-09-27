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
    elif ether_type == "0800":
        parse_IPV4_header(payload)
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

    # left adjust to fix not enough zeros to display other flags
    flags_fragoffset_asBits = flags_fragoffset_asBits.ljust(3,'0')

    # Flag and frag offset only zero causes print errors for me
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

    if protocol == 17:
        parse_udp_header(hex_data[40:])
    elif protocol == 6:
        parse_tcp_header(hex_data[40:])

def parse_IPV6_header(hex_data):
    version = hex_data[:1]

    traffic_class = format(int(hex_data[1:3],16), 'b').zfill(8)
    dscp = traffic_class[:6]
    ecn = traffic_class[6:]

    flow_label = hex_data[2:8]
    payload_length = hex_data[8:12]
    next_header = hex_data[12:14]
    hop_limit = hex_data[14:16]

    source_address = hex_data[16:48]
    result = []
    for i in range(0, len(source_address), 4):
        result.append(source_address[i:i+4])
    source_address_result = ":".join(str(item) for item in result)

    destination_address = hex_data[48:80]
    result = []
    for i in range(0, len(destination_address), 4):
        result.append(destination_address[i:i+4])
    destination_address_result = ":".join(str(item) for item in result)

    payload = hex_data[80:]

    print(f"IPV6 Header:")
    print(f"  {'Version:':<25} {bin(int(version, 16))[2:]:<20} | {version}")
    print(f"  {'Traffic Class:':<25} {traffic_class:<20} | {int(traffic_class, 16)}")
    print(f"     {'DSCP:':<25} {dscp:<20} | {int(dscp, 16)}")
    print(f"     {'ECN:':<25} {ecn:<20} | {int(ecn, 16)}")
    print(f"  {'Flow Label:':<25} {bin(int(flow_label, 16))[2:]:<20} | {int(flow_label, 16)}")
    print(f"  {'Payload Length:':<25} {payload_length:<20} | {int(payload_length, 16)}")
    print(f"  {'Next Header:':<25} {next_header:<20} | {int(next_header, 16)}")
    print(f"  {'Hop Limit:':<25} {hop_limit:<20} | {int(hop_limit, 16)}")
    print(f"  {'Source Address:':<25} {source_address_result:<20}")
    print(f"  {'Destination Address:':<25} {destination_address_result:<20}")

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
    
def parse_tcp_header(hex_data):
    source_port = int(hex_data[:4], 16)
    destination_port = int(hex_data[4:8], 16)
    sequence_number = int(hex_data[8:16], 16)
    acknowledgement_number = int(hex_data[16:24],16)

    # Data Offset
    data_offset = hex_data[24:28]
    header_length = int(int(data_offset[:1]) * 32 / 8)


    flags_as_bits = bin(int(data_offset, 16))

    # Reserved (first 3 bits of the 1st byte of the Data Offset)
    reserved_flag = flags_as_bits[5:8]
    accurate_ecn = flags_as_bits[8:9]
    cwr = flags_as_bits[9:10]
    ece = flags_as_bits[10:11]
    urg = flags_as_bits[11:12]
    ack = flags_as_bits[12:13]
    psh = flags_as_bits[13:14]
    rst = flags_as_bits[14:15]
    syn = flags_as_bits[15:16]
    fin = flags_as_bits[16:17]

    window = hex_data[28:32]
    checksum = hex_data[32:36]
    urg_ptr = hex_data[36:40]
    payload = hex_data[40:]

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {sequence_number}")
    print(f"  {'Acknowledgement Number:':<25} {hex_data[16:24]:<20} | {acknowledgement_number}")
    print(f"  {'Data Offset:':<25} {data_offset[:1]:<20} | {str(header_length) + ' bytes'}")
    print(f"  {'Reserved:':<25} {bin(int(reserved_flag)):<20} | {int(reserved_flag, 16)}")
    print(f"  {'Flags:':<25} {format(int(data_offset[1:], 16), '#010b'):<20} | {int(flags_as_bits[9:], 2)}")
    print(f"     {'Accurate ECN:':<25} {accurate_ecn:<20}")
    print(f"     {'CWR:':<25} {cwr:<20}")
    print(f"     {'ECE:':<25} {ece:<20}")
    print(f"     {'URG:':<25} {urg:<20}")
    print(f"     {'ACK:':<25} {ack:<20}")
    print(f"     {'PSH:':<25} {psh:<20}")
    print(f"     {'RST:':<25} {rst:<20}")
    print(f"     {'SYN:':<25} {syn:<20}")
    print(f"     {'FIN:':<25} {fin:<20}")
    print(f"  {'Window Size:':<25} {window:<20} | {int(window, 16)}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Urgent Pointer:':<25} {urg_ptr:<20} | {int(urg_ptr, 16)}")
    print(f"  {'Payload (hex):':<25} {payload}")
    
def parse_ICMPV6_header(hex_data):
    type = hex_data[:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    payload = hex_data[8:]

    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {type:<20} | {int(type, 16)}")
    print(f"  {'Code:':<25} {code:<20} | {int(code, 16)}")
    print(f"  {'Checksum:':<25} {checksum:<20} | {int(checksum, 16)}")
    print(f"  {'Payload (hex):':<25} {payload}")

def parse_ICMP(hex_data):
    type = hex_data[:2]
    code = hex_data[2:4]
    checksum = hex_data[4:8]
    payload = hex_data[8:]

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {type:<20} | {int(type, 16)}")
    print(f"  {'Code:':<25} {code:<20} | {int(code, 16)}")
    print(f"  {'Checksum:':<25} {hex(int(checksum, 16)):<20} | {int(checksum, 16)}")
    print(f"  {'Payload (hex):':<25} {payload}")

def parse_dns_header(hex_data):
    transaction_id = hex_data[:4]
    flags = hex_data[4:8]

    flags_as_bits = bin(int(flags, 16))[2:].zfill(16)
    response = flags_as_bits[:1]
    opcode = flags_as_bits[1:5]
    authoritative = flags_as_bits[5:6]
    truncated = flags_as_bits[6:7]
    recursion_desired = flags_as_bits[7:8]
    recursion_available = flags_as_bits[8:9]
    z_flag = flags_as_bits[9:10]
    answer_authenticated = flags_as_bits[10:11]
    non_authenticated = flags_as_bits[11:12]
    reply_code = flags_as_bits[12:]

    questions = hex_data[8:12]
    answer_rrs = hex_data[12:16]
    authority_rrs = hex_data[16:20]
    additional_rrs = hex_data[20:24]
    payload = hex_data[24:]

    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {hex(int(hex_data[:4], 16)):<20} | {int(transaction_id, 16)}")
    print(f"  {'Flags:':<25} {flags:<20} | {bin(int(flags, 16))}")
    print(f"     {'Response:':<25} {response:<20}")
    print(f"     {'Opcode:':<25} {opcode:<20} | {int(opcode, 16)}")
    print(f"     {'Authoritative:':<25} {authoritative:<20}")
    print(f"     {'Truncated:':<25} {truncated:<20}")
    print(f"     {'Recursion Desired:':<25} {recursion_desired:<20}")
    print(f"     {'Recursion Available:':<25} {recursion_available:<20}")
    print(f"     {'Z:':<25} {z_flag:<20} | {int(z_flag, 16)}")
    print(f"     {'Answer Authenticated:':<25} {answer_authenticated:<20}")
    print(f"     {'Non Authenticated Data:':<25} {non_authenticated:<20}")
    print(f"     {'Reply Code:':<25} {reply_code:<20} | {int(reply_code, 16)}")
    print(f"  {'Questions:':<25} {questions:<20} | {int(questions, 16)}")
    print(f"  {'Answer RRs:':<25} {answer_rrs:<20} | {int(answer_rrs, 16)}")
    print(f"  {'Authority RRs:':<25} {authority_rrs:<20} | {int(authority_rrs, 16)}")
    print(f"  {'Additional RRs:':<25} {additional_rrs:<20} | {int(additional_rrs, 16)}")
    print(f"  {'Payload (hex):':<25} {payload}")
