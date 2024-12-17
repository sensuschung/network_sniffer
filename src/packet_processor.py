from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo
from scapy.contrib.igmp import IGMP 
from scapy.packet import Raw
from storage import Packet
import time

# 扩展协议映射字典，包括 Telnet（协议号 23）
PROTOCOL_MAP = {
    1: "ICMP",                # ICMP
    2: "IGMP",                # IGMP
    6: "TCP",                 # TCP
    17: "UDP",                # UDP
    47: "GRE",                # Generic Routing Encapsulation
    50: "ESP",                # Encapsulating Security Payload
    51: "AH",                 # Authentication Header
    58: "ICMPv6",             # ICMP for IPv6
    80: "HTTP",               # Hypertext Transfer Protocol
    443: "HTTPS",             # HTTP Secure
    89: "OSPF",               # Open Shortest Path First
    132: "SCTP",              # Stream Control Transmission Protocol
    143: "L2TP",              # Layer 2 Tunneling Protocol
    253: "SVRLOC",            # SVRLOC Protocol (Service Location)
    4: "IPIP",                # IP-in-IP tunneling
    115: "LDP",                # Label Distribution Protocol
    124: "PPTP",               # Point-to-Point Tunneling Protocol
    132: "SCTP",               # Stream Control Transmission Protocol
    133: "RSVP",               # Resource Reservation Protocol
    137: "MPLS",               # Multi-Protocol Label Switching
    197: "VTP",                # VLAN Trunking Protocol
    202: "L2TPv3",             # Layer 2 Tunneling Protocol v3
    23: "TELNET",              # Telnet
}

def get_ip_frag(packet):
    if IP in packet:
        return packet[IP].frag
    return 0

def is_fragmented(packet):
    return IP in packet and (packet[IP].flags & 1 != 0 or packet[IP].frag > 0)

def reassemble_fragments(fragments):
    """
    Reassembles fragmented IP packets into a single data payload.
    Args:
        fragments (list): A list of fragmented packets. Each fragment is expected to be a Scapy packet object containing an IP layer.
    Returns:
        bytes: The reassembled data payload from the fragmented packets, excluding the transport layer header (TCP/UDP).
    Notes:
        - The function assumes that all fragments belong to the same original packet.
        - The function handles both TCP and UDP transport layers.
        - The function calculates the total length of the reassembled data by considering the fragment offsets and payload lengths.
        - The function creates a bytearray to store the complete data and then fills it with the payloads from each fragment.
        - The function removes the transport layer header from the reassembled data before returning it.
    """
    # 计算总数据长度
    total_length = max((frag[IP].frag * 8) + len(frag[IP].payload) for frag in fragments if IP in frag)

    # 创建字节数组存储完整数据
    full_data = bytearray(total_length)
    header_length = 0
    # print(fragments[0])
    if TCP in fragments[0]:
        header_length = fragments[0][TCP].dataofs * 4
    if UDP in fragments[0]:
        header_length = 8
    # print(header_length)
    # 拼接所有分片的数据负载
    for frag in fragments:
        if IP in frag:
            offset = frag[IP].frag * 8
            payload = bytes(frag[IP].payload)
            full_data[offset:offset + len(payload)] = payload

    return full_data[header_length:]

def process_packet(packet):
    """
    Processes a network packet and returns a summary string based on the packet type.

    Args:
        packet: The network packet to be processed.

    Returns:
        A string summarizing the type of the packet and its details.

    Packet Types:
        - ARP: Address Resolution Protocol packets.
        - IP: Internet Protocol packets (IPv4 and IPv6).
        - IGMP: Internet Group Management Protocol packets.
        - TCP: Transmission Control Protocol packets, including:
            - Telnet: Port 23.
            - HTTP: Port 80.
            - HTTPS: Port 443.
        - UDP: User Datagram Protocol packets, including:
            - DNS: Port 53.
            - SNMP: Port 161.
            - NTP: Port 123.
            - DHCP: Ports 67 and 68.
        - ICMP: Internet Control Message Protocol packets.
        - Other: Any other packet types not specifically handled.
    """
    if ARP in packet:
        return f"ARP Packet: {packet.summary()}"
    elif IP in packet or IPv6 in packet:
        if IGMP in packet:
            return f"IGMP Packet: {packet.summary()}"
        elif TCP in packet:
            if packet[TCP].dport == 23 or packet[TCP].sport == 23:
                return f"Telnet Packet: {packet.summary()}"
            elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return f"HTTP Packet: {packet.summary()}"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return f"HTTPS Packet: {packet.summary()}"
            else:
                return f"TCP Packet: {packet.summary()}"
        elif UDP in packet:
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                return f"DNS Packet: {packet.summary()}"
            elif packet[UDP].dport == 161 or packet[UDP].sport == 161:
                return f"SNMP Packet: {packet.summary()}"
            elif packet[UDP].dport == 123 or packet[UDP].sport == 123:
                return f"NTP Packet: {packet.summary()}"
            elif packet[UDP].dport == 67 or packet[UDP].sport == 67 or packet[UDP].dport == 68 or packet[UDP].sport == 68:
                return f"DHCP Packet: {packet.summary()}"
            else:
                return f"UDP Packet: {packet.summary()}"
        elif ICMP in packet:
            return f"ICMP Packet: {packet.summary()}"
        else:
            return f"IP Packet: {packet.summary()}"
    else:
        return f"Other Packet: {packet.summary()}"

def parse_raw(packet,details):
    """
    Parses the raw payload from a network packet and appends it to the details list.

    Args:
        packet (scapy.packet.Packet): The network packet to parse.
        details (list): A list to append the decoded raw payload or error message.

    Returns:
        scapy.packet.Raw or None: The raw payload if present, otherwise None.
    """
    raw = None
    if Raw in packet:
        raw = packet[Raw]
        try:
            details.append(raw.load.decode(errors='ignore'))  # 安全解码
        except Exception as e:
            details.append(f"Error decoding payload: {str(e)}")
    return raw

def format_packet(packet):
    """
    Formats the details of a given network packet into a human-readable string.
    Args:
        packet: The network packet to be formatted. This packet can contain various protocol headers such as Ethernet, ARP, IP, IPv6, IGMP, TCP, UDP, ICMP, ICMPv6 Echo Request, and ICMPv6 Echo Reply.
    Returns:
        tuple: A tuple containing:
            - formatted_details (str): A string with the formatted details of the packet.
            - raw (str or None): The raw payload data if available, otherwise None.
    """
    details = []

    raw_parse = False

    raw = None

    # 处理 Ethernet Header
    if Ether in packet:
        eth = packet[Ether]
        details.append("Ethernet Header:")
        details.append(f"    Destination MAC: {eth.dst}")
        details.append(f"    Source MAC: {eth.src}")
        details.append(f"    Type: {hex(eth.type)}")

    # 处理 ARP
    if ARP in packet:
        arp = packet[ARP]
        details.append("\nARP Header:")
        details.append(f"    Opcode: {arp.op}")
        details.append(f"    Source MAC: {arp.hwsrc}")
        details.append(f"    Destination MAC: {arp.hwdst}")
        details.append(f"    Source IP: {arp.psrc}")
        details.append(f"    Destination IP: {arp.pdst}")

    # 处理 IP
    if IP in packet:
        ip = packet[IP]
        details.append("\nIP Header:")
        details.append(f"    Version: {ip.version} (IPv4)")
        details.append(f"    Header Length: {ip.ihl * 4} bytes")
        details.append(f"    Total Length: {ip.len} bytes")
        details.append(f"    Identification: {hex(ip.id)}")
        details.append(f"    Flags: {(ip.flags)}")
        details.append(f"    TTL: {ip.ttl}")
        details.append(f"    Protocol: {ip.proto}")
        details.append(f"    Source IP: {ip.src}")
        details.append(f"    Destination IP: {ip.dst}")

    # 处理 IPv6
    if IPv6 in packet:
        ipv6 = packet[IPv6]
        details.append("\nIPv6 Header:")
        details.append(f"    Version: {ipv6.version} (IPv6)")
        details.append(f"    Traffic Class: {ipv6.tc}")
        details.append(f"    Flow Label: {ipv6.fl}")
        details.append(f"    Payload Length: {ipv6.plen}")
        details.append(f"    Next Header: {ipv6.nh}")
        details.append(f"    Hop Limit: {ipv6.hlim}")
        details.append(f"    Source IP: {ipv6.src}")
        details.append(f"    Destination IP: {ipv6.dst}")



    # 处理 IGMP
    if IGMP in packet:
        igmp = packet[IGMP]
        details.append("\nIGMP Header:")
        details.append(f"    Type: {igmp.type}")
        if hasattr(igmp, 'gaddr'):
            details.append(f"    Group Address: {igmp.gaddr}")
        else:
            details.append("    Group Address: N/A")

    # 处理 TCP
    if TCP in packet:
        tcp = packet[TCP]
        details.append("\nTCP Header:")
        details.append(f"    Source Port: {tcp.sport}")
        details.append(f"    Destination Port: {tcp.dport}")
        details.append(f"    Sequence Number: {tcp.seq}")
        details.append(f"    Acknowledgment Number: {tcp.ack}")
        details.append(f"    Data Offset: {tcp.dataofs * 4} bytes")
        details.append(f"    Flags: {(tcp.flags)}")
        details.append(f"    Window Size: {tcp.window}")
        details.append(f"    Checksum: {hex(tcp.chksum)}")
        details.append(f"    Urgent Pointer: {tcp.urgptr}")
        details.append(f"    Options: {tcp.options}")

        if PROTOCOL_MAP.get(tcp.dport,0)!=0 or PROTOCOL_MAP.get(tcp.sport,0)!=0:
            protocol_name = PROTOCOL_MAP.get(tcp.dport, 0) or PROTOCOL_MAP.get(tcp.sport, 0)
            details.append(f"\n{protocol_name} Info:")
            raw = parse_raw(packet,details)
            raw_parse = True

    # 处理 UDP
    if UDP in packet:
        udp = packet[UDP]
        details.append("\nUDP Header:")
        details.append(f"    Source Port: {udp.sport}")
        details.append(f"    Destination Port: {udp.dport}")
        details.append(f"    Length: {udp.len}")
        details.append(f"    Checksum: {hex(udp.chksum)}")

        if PROTOCOL_MAP.get(udp.dport,0)!=0 or PROTOCOL_MAP.get(udp.sport,0)!=0:
            protocol_name = PROTOCOL_MAP.get(udp.dport, 0) or PROTOCOL_MAP.get(udp.sport, 0)
            details.append(f"\n{protocol_name} Info:")
            raw = parse_raw(packet,details)
            raw_parse = True

    # 处理 ICMP
    if ICMP in packet:
        icmp = packet[ICMP]
        details.append("\nICMP Header:")
        details.append(f"    Type: {icmp.type}")
        details.append(f"    Code: {icmp.code}")
        # details.append(f"    Checksum: {hex(icmp.chksum)}")
        details.append(f"    ID: {icmp.id}")
        details.append(f"    Sequence: {icmp.seq}")

    # 处理 ICMPv6 Echo Request
    if ICMPv6EchoRequest in packet:
        icmpv6_echo_req = packet[ICMPv6EchoRequest]
        details.append("\nICMPv6 Echo Request:")
        details.append(f"    Type: {icmpv6_echo_req.type}")
        details.append(f"    Code: {icmpv6_echo_req.code}")
        details.append(f"    Identifier: {icmpv6_echo_req.id}")
        details.append(f"    Sequence: {icmpv6_echo_req.seq}")
    
    # 处理 ICMPv6 Echo Reply
    if ICMPv6EchoReply in packet:
        icmpv6_echo_reply = packet[ICMPv6EchoReply]
        details.append("\nICMPv6 Echo Reply:")
        details.append(f"    Type: {icmpv6_echo_reply.type}")
        details.append(f"    Code: {icmpv6_echo_reply.code}")
        details.append(f"    Identifier: {icmpv6_echo_reply.id}")
        details.append(f"    Sequence: {icmpv6_echo_reply.seq}")
    
    # 处理 Raw 数据
    if not raw_parse:
        details.append("\nUnkown Payload:")
        raw = parse_raw(packet,details)
        if not raw:
            details.append("    No payload data found")

    formatted_details = '\n'.join(item if item is not None else '' for item in details)

    return formatted_details,raw

def extract_packet_info(packet, packet_count):
    """
    Extracts and returns detailed information from a network packet.
    Args:
        packet: The network packet to be processed.
        packet_count: The count of the packet being processed.
    Returns:
        tuple: A tuple containing the following elements:
            - packet: The original packet.
            - packet_count: The count of the packet being processed.
            - timestamp: The timestamp when the packet was captured.
            - src: The source IP address.
            - dst: The destination IP address.
            - proto: The protocol used by the packet.
            - length: The length of the packet.
            - summary: A summary of the packet.
            - details: Detailed information about the packet (currently None).
            - hex_data: The hexadecimal representation of the packet data (currently None).
            - raw: The raw packet data (currently None).
            - is_fragment: A boolean indicating if the packet is a fragment.
            - fragment_id: The fragment identifier if the packet is a fragment.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
    fragment_id = None
    is_fragment = False
    src,dst = None,None
    # 协议识别：首先判断是否包含特定协议（如 ARP, IGMP, Telnet）
    if ARP in packet:
        proto = "ARP"
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
    elif IGMP in packet:
        proto = "IGMP"
        src = packet[IP].src
        dst = packet[IP].dst
    elif IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        # 获取 IP 协议号
        proto_num = packet[IP].proto if IP in packet else None
        ip_layer = packet[IP]
        is_fragment = is_fragmented(packet)   
        if is_fragment:
            fragment_id = (ip_layer.src, ip_layer.dst, ip_layer.proto, ip_layer.id)
        # 从协议映射字典中获取协议名称
        proto = PROTOCOL_MAP.get(proto_num, "Unknown") if proto_num is not None else "Unknown"
    elif IPv6 in packet:
        src = packet[IPv6].src
        dst = packet[IPv6].dst
        proto_num = packet[IPv6].nh if IPv6 in packet else None
        proto = PROTOCOL_MAP.get(proto_num, "Unknown") if proto_num is not None else "Unknown"
    else:
        proto = "Unknown"
    
    length = len(packet)
    summary = packet.summary()
    raw_data = bytes(packet)
    hex_data = None
    # details,raw = format_packet(packet)
    details = None
    raw = None
    

    return (packet,packet_count, timestamp, src, dst, proto, length, summary, details,hex_data,raw,is_fragment,fragment_id)

def process_packet(packet:Packet):
    """
    Processes a network packet and updates its details, raw information, and formatted hexadecimal representation.

    Args:
        packet (Packet): The network packet to be processed. It is expected to have attributes `packet`, `update_details`, `update_raw`, and `update_hex`.

    Returns:
        None
    """
    details,raw_info = format_packet(packet.packet)
    hex_data = None
    formatted_hex = ""
    if raw_info:
        hex_data = raw_info.load.hex()
        formatted_hex = ' '.join([hex_data[i:i+2].zfill(2) for i in range(0, len(hex_data), 2)])
    packet.update_details(details)
    packet.update_raw(raw_info)
    packet.update_hex(formatted_hex)
