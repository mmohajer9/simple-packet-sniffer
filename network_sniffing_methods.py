import socket
import struct
import textwrap


#a function to make the mac address readable from bytes
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format , bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#Unpacking The Ethernet_Frame - Data Link Layer
def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac) , get_mac_addr(src_mac) , socket.htons(proto) , data[14:]



#a function to make the ip address readable from bytes
def ipv4(addr):
    return '.'.join(map(str,addr))
 
#Unpacking the Version Header (IPV4)

def ipv4_packet(data):
    #avalin byte dade bad az protocol ethernet 4byte aval version + 4byte 2vome IHL
    version_internet_header_length = data[0]
    
    #4bit shift midim be rast pas 4 bit IHL mipare onvar ham poshtesh 0 miad pas faghat version mimone
    version = version_internet_header_length >> 4

    #agar farz konim kole 8 bit version + IHL bashe 10101011 onvaght age ino ba adad 15 dar halat binary ke
    #dar system 8 biti mishe 00001111 and (&) konim faghat 4bit samt rast mimone ke mishe 00001011 ke mishe hamon IHL

    internet_header_length = (version_internet_header_length & 15) * 4
    ttl , proto , src , target =  struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version , internet_header_length , ttl , proto , ipv4(src) , ipv4(target) , data[internet_header_length:]

def icmp_packet(data):
    icmp_type , code , checksum = struct.unpack('! B B H' , data[:4])
    return icmp_type , code , checksum , data[4:]

def tcp_segment(data):
    src_port , dest_port , sequence , ack , offset_reserved_flags = struct.unpack('! H H L L H' , data[:14])
    offset  = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)

    return (src_port , dest_port , sequence , ack , flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin ,  data[offset:])

def udp_segment(data):
    src_port , dest_port , size = struct.unpack('! H H 2x H',data[:8])
    return src_port , dest_port , size , data[8:]

def formating_data_mutlilines(prefix , string, size=80):
    size = size - len(prefix)
    if isinstance(string , bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size = size - 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string , size)])
