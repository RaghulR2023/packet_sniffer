#!/usr/bin/env python3

import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, conf, DNS, DNSQR, DNSRR, Raw, IPv6
import netifaces
from colorama import init, Fore, Style

# Initialize colorama
init()

# Set up logging
log_path = Path(__file__).parent / 'logs' / 'sniffer.log'
log_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self, interface=None, filter_string=None, packet_count=None, source_ip=None, domain=None):
        self.interface = interface or self._get_default_interface()
        self.filter_string = filter_string
        self.packet_count = packet_count
        self.source_ip = source_ip
        self.domain = domain
        self.packets_captured = 0
        self.source_packets = []
        
    def _get_default_interface(self):
        """Get the default network interface."""
        interfaces = conf.ifaces.data.values()
        for iface in interfaces:
            if iface.name != 'lo' and iface.ip:
                return iface.name
        return None

    def _list_interfaces(self):
        """List all available network interfaces."""
        print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
        for iface in conf.ifaces.data.values():
            if iface.ip:  # Only show interfaces with IP addresses
                print(f"{Fore.GREEN}Interface: {iface.name}{Style.RESET_ALL}")
                print(f"  IP: {iface.ip}")
                print(f"  MAC: {iface.mac}")
                print("---")

    def _get_protocol_name(self, packet):
        """Get the protocol name from the packet."""
        if IPv6 in packet:
            if TCP in packet:
                if packet[TCP].dport == 53 or packet[TCP].sport == 53:
                    return "DNS/TCP/IPv6"
                return "TCP/IPv6"
            elif UDP in packet:
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    return "DNS/UDP/IPv6"
                return "UDP/IPv6"
            elif ICMP in packet:
                return "ICMPv6"
            return "IPv6"
        elif IP in packet:
            if TCP in packet:
                if packet[TCP].dport == 53 or packet[TCP].sport == 53:
                    return "DNS/TCP"
                return "TCP"
            elif UDP in packet:
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    return "DNS/UDP"
                return "UDP"
            elif ICMP in packet:
                return "ICMP"
            return "IP"
        elif ARP in packet:
            return "ARP"
        return "Unknown"

    def _get_tcp_flags(self, packet):
        """Get TCP flags in a readable format."""
        if TCP in packet:
            flags = []
            if packet[TCP].flags & 0x01:  # FIN
                flags.append("FIN")
            if packet[TCP].flags & 0x02:  # SYN
                flags.append("SYN")
            if packet[TCP].flags & 0x04:  # RST
                flags.append("RST")
            if packet[TCP].flags & 0x08:  # PSH
                flags.append("PSH")
            if packet[TCP].flags & 0x10:  # ACK
                flags.append("ACK")
            if packet[TCP].flags & 0x20:  # URG
                flags.append("URG")
            return " ".join(flags)
        return None

    def _get_dns_info(self, packet):
        """Get detailed DNS information."""
        dns_info = {}
        
        # Try to get DNS layer from the packet
        dns_layer = None
        if DNS in packet:
            dns_layer = packet[DNS]
        elif Raw in packet:
            try:
                dns_layer = DNS(packet[Raw].load)
            except:
                pass
        
        if dns_layer:
            dns_info['type'] = 'Query' if dns_layer.qr == 0 else 'Response'
            dns_info['id'] = dns_layer.id
            
            # Get query information
            if hasattr(dns_layer, 'qd') and dns_layer.qd:
                qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                qtype = dns_layer.qd.qtype
                dns_info['query'] = {
                    'name': qname,
                    'type': self._get_dns_type_name(qtype)
                }
            
            # Get response information
            if dns_layer.qr == 1:  # Response packet
                answers = []
                if hasattr(dns_layer, 'an') and dns_layer.an:
                    for rr in dns_layer.an:
                        if hasattr(rr, 'rdata'):
                            answers.append({
                                'name': rr.rrname.decode('utf-8', errors='ignore'),
                                'type': self._get_dns_type_name(rr.type),
                                'data': str(rr.rdata)
                            })
                dns_info['answers'] = answers
                
        return dns_info

    def _get_dns_type_name(self, type_code):
        """Convert DNS type code to name."""
        dns_types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV'
        }
        return dns_types.get(type_code, f'Type{type_code}')

    def _get_protocol_info(self, packet):
        """Get detailed protocol information."""
        info = {}
        
        if IPv6 in packet:
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            info['ttl'] = packet[IPv6].hlim
            
            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = self._get_tcp_flags(packet)
                
                # Try to get DNS info from TCP payload
                if Raw in packet:
                    try:
                        dns_packet = DNS(packet[Raw].load)
                        if dns_packet:
                            dns_info = self._get_dns_info(dns_packet)
                            info.update(dns_info)
                    except:
                        pass
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                
                # DNS specific information
                if DNS in packet:
                    dns_info = self._get_dns_info(packet)
                    info.update(dns_info)
        elif IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['ttl'] = packet[IP].ttl
            
            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = self._get_tcp_flags(packet)
                
                # Try to get DNS info from TCP payload
                if Raw in packet:
                    try:
                        dns_packet = DNS(packet[Raw].load)
                        if dns_packet:
                            dns_info = self._get_dns_info(dns_packet)
                            info.update(dns_info)
                    except:
                        pass
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                
                # DNS specific information
                if DNS in packet:
                    dns_info = self._get_dns_info(packet)
                    info.update(dns_info)
            elif ICMP in packet:
                info['type'] = packet[ICMP].type
                info['code'] = packet[ICMP].code
                
        elif ARP in packet:
            info['src_mac'] = packet[ARP].hwsrc
            info['dst_mac'] = packet[ARP].hwdst
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            
        return info

    def _print_packet_info(self, packet):
        """Print formatted packet information."""
        protocol = self._get_protocol_name(packet)
        info = self._get_protocol_info(packet)
        
        # Print packet header
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Packet #{self.packets_captured}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Protocol: {protocol}{Style.RESET_ALL}")
        
        # Print packet details
        for key, value in info.items():
            if key == 'query':
                print(f"{Fore.WHITE}DNS Query: {value['name']} ({value['type']}){Style.RESET_ALL}")
            elif key == 'answers':
                print(f"{Fore.WHITE}DNS Answers:{Style.RESET_ALL}")
                for answer in value:
                    print(f"  {Fore.WHITE}{answer['name']} -> {answer['data']} ({answer['type']}){Style.RESET_ALL}")
            elif key == 'type' and 'DNS' in protocol:
                print(f"{Fore.WHITE}DNS Type: {value}{Style.RESET_ALL}")
            elif key == 'id' and 'DNS' in protocol:
                print(f"{Fore.WHITE}DNS ID: {value}{Style.RESET_ALL}")
            elif key == 'flags':
                print(f"{Fore.WHITE}TCP Flags: {value}{Style.RESET_ALL}")
            else:
                print(f"{Fore.WHITE}{key}: {value}{Style.RESET_ALL}")
            
        # Print packet summary
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

    def _print_source_ip_summary(self):
        """Print summary of packets from the specified source IP."""
        if not self.source_packets:
            print(f"\n{Fore.YELLOW}No packets found from source IP: {self.source_ip}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Summary of packets from {self.source_ip}:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # Count protocols
        protocols = {}
        for packet in self.source_packets:
            protocol = self._get_protocol_name(packet)
            protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Print protocol statistics
        print(f"\n{Fore.YELLOW}Protocol Distribution:{Style.RESET_ALL}")
        for protocol, count in protocols.items():
            print(f"{Fore.WHITE}{protocol}: {count} packets{Style.RESET_ALL}")
        
        # Print unique destination IPs
        destinations = set()
        for packet in self.source_packets:
            if IP in packet:
                destinations.add(packet[IP].dst)
            elif IPv6 in packet:
                destinations.add(packet[IPv6].dst)
        
        print(f"\n{Fore.YELLOW}Communicating with {len(destinations)} unique destinations:{Style.RESET_ALL}")
        for dst in destinations:
            print(f"{Fore.WHITE}{dst}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        try:
            # Check if packet matches domain filter
            if self.domain:
                dns_info = self._get_dns_info(packet)
                if not dns_info or 'query' not in dns_info:
                    return False
                if self.domain.lower() not in dns_info['query']['name'].lower():
                    return False
            
            self.packets_captured += 1
            
            # Check if packet is from the specified source IP
            if self.source_ip:
                if IP in packet and packet[IP].src == self.source_ip:
                    self.source_packets.append(packet)
                elif IPv6 in packet and packet[IPv6].src == self.source_ip:
                    self.source_packets.append(packet)
            
            self._print_packet_info(packet)
            
            # Stop if we've reached the packet count
            if self.packet_count and self.packets_captured >= self.packet_count:
                if self.source_ip:
                    self._print_source_ip_summary()
                return True
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            return False

    def start_capture(self):
        """Start capturing packets."""
        try:
            print(f"\n{Fore.GREEN}Starting packet capture on interface: {self.interface}{Style.RESET_ALL}")
            if self.source_ip:
                print(f"{Fore.YELLOW}Tracking packets from source IP: {self.source_ip}{Style.RESET_ALL}")
            if self.domain:
                print(f"{Fore.YELLOW}Filtering for domain: {self.domain}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Press Ctrl+C to stop{Style.RESET_ALL}\n")
            
            # Configure Scapy to use the specified interface
            conf.iface = self.interface
            
            # Print the filter being used
            print(f"{Fore.YELLOW}Using filter: {self.filter_string}{Style.RESET_ALL}\n")
            
            sniff(
                iface=self.interface,
                filter=self.filter_string,
                prn=self.packet_callback,
                count=self.packet_count,
                store=0,
                stop_filter=lambda x: self.packets_captured >= self.packet_count if self.packet_count else False
            )
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Packet capture stopped by user{Style.RESET_ALL}")
            if self.source_ip:
                self._print_source_ip_summary()
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            return 1
        
        return 0

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('--interface', '-i', help='Network interface to capture packets from')
    parser.add_argument('--filter', '-f', help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('--count', '-c', type=int, help='Number of packets to capture')
    parser.add_argument('--source', '-s', help='Track packets from specific source IP')
    parser.add_argument('--domain', '-d', help='Filter DNS packets for specific domain')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Create packet sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        filter_string=args.filter,
        packet_count=args.count,
        source_ip=args.source,
        domain=args.domain
    )
    
    # If no interface specified, show available interfaces
    if not args.interface:
        sniffer._list_interfaces()
        print(f"\n{Fore.YELLOW}Please specify an interface using --interface or -i{Style.RESET_ALL}")
        return 1
    
    return sniffer.start_capture()

if __name__ == '__main__':
    sys.exit(main()) 