from network_sniffing_methods import *

path = 'log.pcap'
pcap_file = open(path , 'a')
def main():
    #Create a always-on Socket for Tracking or Sniffing the packets
    conn = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3)) 

    while True:
        #recvfrom is a recv that returns a tuple of raw_data in bytes and addr
        raw_data , addr = conn.recvfrom(65536)
        dest_mac , src_mac , ethernet_protocol , data = ethernet_frame(raw_data)
        pcap_file.write('\n    Ethernet Frame Layer: \n')
        pcap_file.write(f'    Destination:  {dest_mac} / Source:  {src_mac} / Protocol:  {ethernet_protocol}\n')
        print('\n    Ethernet Frame Layer: ')
        print(f'    Destination:  {dest_mac} / Source:  {src_mac} / Protocol:  {ethernet_protocol}\n')
        

        if ethernet_protocol == 8:
            (version , header_length , ttl , proto , src , target , data) = ipv4_packet(data)
            pcap_file.write('\tIPV4 Packet: \n')
            pcap_file.write(f'\t\tVersion: {version} / Header Length : {header_length} / TTL : {ttl}\n')
            pcap_file.write(f'\t\tProtocol: {proto} / Source: {src} / Target: {target} \n')
            print('\tIPV4 Packet: ')
            print(f'\t\tVersion: {version} / Header Length : {header_length} / TTL : {ttl}')
            print(f'\t\tProtocol: {proto} / Source: {src} / Target: {target} ')
            
            #ICMP
            if proto == 1:
                icmp_type , code , checksum , data = icmp_packet(data)

                pcap_file.write('\tICMP Packet:\n')
                pcap_file.write(f'\t\tType: {icmp_type} / Code: {code} / Checksum: {checksum}\n')
                pcap_file.write('\t\tData:\n')
                pcap_file.write(formating_data_mutlilines('\t\t\t',data))

                print('\tICMP Packet:')
                print(f'\t\tType: {icmp_type} / Code: {code} / Checksum: {checksum}')
                print('\t\tData:')
                print(formating_data_mutlilines('\t\t\t',data))    
            
            #TCP
            elif proto == 6:
                (src_port , dest_port , sequence , ack , flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin , data) = tcp_segment(data)
                
                pcap_file.write('\tTCP Segment:\n')
                pcap_file.write(f'\t\tSource Port: {src_port} / Destination Port: {dest_port}\n')
                pcap_file.write(f'\t\tSequence: {sequence} / Ack: {ack}\n')
                pcap_file.write('\tFlags:\n')
                pcap_file.write(f'\t\t\tURG: {flag_urg} / ACK: {flag_ack} / PSH: {flag_psh} / RST: {flag_rst} / SYN: {flag_syn} / FIN: {flag_fin}\n')
                pcap_file.write(formating_data_mutlilines('\t\t\t',data))


                print('\tTCP Segment:')
                print(f'\t\tSource Port: {src_port} / Destination Port: {dest_port}')
                print(f'\t\tSequence: {sequence} / Ack: {ack}')
                print('\tFlags:')
                print(f'\t\t\tURG: {flag_urg} / ACK: {flag_ack} / PSH: {flag_psh} / RST: {flag_rst} / SYN: {flag_syn} / FIN: {flag_fin}')
                print(formating_data_mutlilines('\t\t\t',data))


            #UDP
            elif proto == 17:
                src_port , dest_port , length , data = udp_segment(data)
                
                pcap_file.write('\tUDP Segment:\n')
                pcap_file.write(f'\t\tSource Port: {src_port} / Destination Port: {dest_port} / Length: {length}\n')
                pcap_file.write('\t\tData:\n')
                pcap_file.write(formating_data_mutlilines('\t\t\t',data))   

                print('\tUDP Segment:')
                print(f'\t\tSource Port: {src_port} / Destination Port: {dest_port} / Length: {length}')
                print('\t\tData:')
                print(formating_data_mutlilines('\t\t\t',data))   
            #Other
            else:
                pcap_file.write('Data: \n')
                pcap_file.write(formating_data_mutlilines('\t\t\t',data))


                print('Data: ')
                print(formating_data_mutlilines('\t\t\t',data))



if __name__ == '__main__':
    main()