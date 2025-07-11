#!/usr/bin/env python3

import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, conf, DNS, DNSQR, DNSRR, Raw, IPv6, sr1
import netifaces
from colorama import init, Fore, Style
import socket
import threading

# Initialize colorama
init()

# Set up logging
log_path = Path(__file__).parent / 'logs' / 'sniffer.log'
log_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PacketSniffer:
    def __init__(self, interface=None, filter_string=None, packet_count=None, source_ip=None, domain=None, timeout=None):
        self.interface = interface or self._get_default_interface()
        self.filter_string = filter_string
        self.packet_count = packet_count
        self.source_ip = source_ip
        self.domain = domain
        self.packets_captured = 0
        self.source_packets = []
        self.timeout = timeout
        self.domain_ips = set()
        self.ip_to_domain = {}  # Cache for IP to domain resolution
        
        # If domain is provided, resolve it
        if domain:
            try:
                # Get both IPv4 and IPv6 addresses
                for family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        for ip in socket.getaddrinfo(domain, None, family):
                            self.domain_ips.add(ip[4][0])
                    except socket.gaierror:
                        continue
                
                if self.domain_ips:
                    print(f"\n{Fore.GREEN}Resolved {domain} to IPs: {', '.join(self.domain_ips)}{Style.RESET_ALL}")
                    # Update filter string to include all IPs
                    ip_filter = ' or '.join(f'host {ip}' for ip in self.domain_ips)
                    if self.filter_string:
                        self.filter_string = f"({self.filter_string}) and ({ip_filter})"
                    else:
                        self.filter_string = ip_filter
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not resolve domain {domain}: {str(e)}{Style.RESET_ALL}")
        
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
            
            # Add description of common flag combinations
            flag_str = " ".join(flags)
            if "SYN" in flag_str and "ACK" in flag_str:
                flag_str += " (Connection established)"
            elif "FIN" in flag_str and "ACK" in flag_str:
                flag_str += " (Connection closing)"
            elif "RST" in flag_str:
                flag_str += " (Connection reset)"
            elif "PSH" in flag_str and "ACK" in flag_str:
                flag_str += " (Data transfer)"
            elif "ACK" in flag_str and len(flags) == 1:
                flag_str += " (Acknowledgement)"
            
            return flag_str
        return None

    def _get_dns_info(self, packet):
        """Get detailed DNS information."""
        dns_info = {}
        
        try:
            # Try to get DNS layer from the packet
            dns_layer = None
            if DNS in packet:
                logger.info("Found DNS layer in packet")
                dns_layer = packet[DNS]
            elif Raw in packet and (UDP in packet or TCP in packet):
                try:
                    if UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                        logger.info("Found DNS in UDP packet")
                        dns_layer = DNS(packet[Raw].load)
                    elif TCP in packet and (packet[TCP].sport == 53 or packet[TCP].dport == 53):
                        logger.info("Found DNS in TCP packet")
                        dns_layer = DNS(packet[Raw].load)
                except Exception as e:
                    logger.error(f"Error parsing DNS from raw payload: {str(e)}")
            
            if dns_layer:
                dns_info['type'] = 'Query' if dns_layer.qr == 0 else 'Response'
                dns_info['id'] = dns_layer.id
                logger.info(f"DNS packet type: {dns_info['type']}, ID: {dns_info['id']}")
                
                # Get query information
                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                    try:
                        qname = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                        qtype = dns_layer.qd.qtype
                        dns_info['query'] = {
                            'name': qname,
                            'type': self._get_dns_type_name(qtype)
                        }
                        logger.info(f"Processed DNS query: {qname} (Type: {self._get_dns_type_name(qtype)})")
                    except Exception as e:
                        logger.error(f"Error processing DNS query: {str(e)}")
                
                # Get response information
                if dns_layer.qr == 1:  # Response packet
                    answers = []
                    if hasattr(dns_layer, 'an') and dns_layer.an:
                        for rr in dns_layer.an:
                            try:
                                if hasattr(rr, 'rdata'):
                                    answer = {
                                        'name': rr.rrname.decode('utf-8', errors='ignore'),
                                        'type': self._get_dns_type_name(rr.type),
                                        'data': str(rr.rdata)
                                    }
                                    answers.append(answer)
                                    logger.info(f"Processed DNS answer: {answer['name']} -> {answer['data']} ({answer['type']})")
                            except Exception as e:
                                logger.error(f"Error processing DNS answer: {str(e)}")
                    dns_info['answers'] = answers
                    
                    # Get authority records
                    if hasattr(dns_layer, 'ns') and dns_layer.ns:
                        authorities = []
                        for rr in dns_layer.ns:
                            try:
                                if hasattr(rr, 'rdata'):
                                    authority = {
                                        'name': rr.rrname.decode('utf-8', errors='ignore'),
                                        'type': self._get_dns_type_name(rr.type),
                                        'data': str(rr.rdata)
                                    }
                                    authorities.append(authority)
                                    logger.info(f"Processed DNS authority: {authority['name']} -> {authority['data']} ({authority['type']})")
                            except Exception as e:
                                logger.error(f"Error processing DNS authority: {str(e)}")
                        dns_info['authorities'] = authorities
                    
                    # Get additional records
                    if hasattr(dns_layer, 'ar') and dns_layer.ar:
                        additionals = []
                        for rr in dns_layer.ar:
                            try:
                                if hasattr(rr, 'rdata'):
                                    additional = {
                                        'name': rr.rrname.decode('utf-8', errors='ignore'),
                                        'type': self._get_dns_type_name(rr.type),
                                        'data': str(rr.rdata)
                                    }
                                    additionals.append(additional)
                                    logger.info(f"Processed DNS additional: {additional['name']} -> {additional['data']} ({additional['type']})")
                            except Exception as e:
                                logger.error(f"Error processing DNS additional: {str(e)}")
                        dns_info['additionals'] = additionals
                    
        except Exception as e:
            logger.error(f"Error getting DNS info: {str(e)}")
        
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
            33: 'SRV',
            255: 'ANY',
            252: 'AXFR',
            251: 'IXFR',
            249: 'TKEY',
            250: 'TSIG',
            41: 'OPT',
            43: 'DS',
            44: 'SSHFP',
            45: 'IPSECKEY',
            46: 'RRSIG',
            47: 'NSEC',
            48: 'DNSKEY',
            49: 'DHCID',
            50: 'NSEC3',
            51: 'NSEC3PARAM',
            52: 'TLSA',
            53: 'SMIMEA',
            55: 'HIP',
            56: 'NINFO',
            57: 'RKEY',
            58: 'TALINK',
            59: 'CDS',
            60: 'CDNSKEY',
            61: 'OPENPGPKEY',
            62: 'CSYNC',
            63: 'ZONEMD',
            64: 'SVCB',
            65: 'HTTPS'
        }
        return dns_types.get(type_code, f'Type{type_code}')

    def _resolve_ip_to_domain(self, ip):
        """Resolve IP address to domain name."""
        if ip in self.ip_to_domain:
            return self.ip_to_domain[ip]
        
        try:
            # Try to get domain name from IP
            domain = socket.gethostbyaddr(ip)[0]
            self.ip_to_domain[ip] = domain
            return domain
        except:
            self.ip_to_domain[ip] = None
            return None

    def _get_http_info(self, payload):
        """Extract HTTP information from payload."""
        try:
            decoded = payload.decode('utf-8', errors='ignore')
            
            # Check for HTTP request
            if decoded.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                lines = decoded.split('\n')
                request_line = lines[0].strip()
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                return {
                    'type': 'request',
                    'method': request_line.split()[0],
                    'path': request_line.split()[1],
                    'headers': headers
                }
            
            # Check for HTTP response
            elif decoded.startswith('HTTP/'):
                lines = decoded.split('\n')
                status_line = lines[0].strip()
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                return {
                    'type': 'response',
                    'status': status_line,
                    'headers': headers
                }
            
            return None
        except:
            return None

    def _format_payload(self, payload):
        """Format packet payload data in a readable way."""
        try:
            # Try to decode as UTF-8
            decoded = payload.decode('utf-8', errors='ignore')
            
            # If the decoded string is empty or only whitespace, try other encodings
            if not decoded.strip():
                # Try other common encodings
                for encoding in ['ascii', 'latin1', 'cp1252']:
                    try:
                        decoded = payload.decode(encoding, errors='ignore')
                        if decoded.strip():
                            break
                    except:
                        continue
                
                # If still no readable content, return hex
                if not decoded.strip():
                    return f"[Binary/Encrypted Data]\nLength: {len(payload)} bytes\nHex: {payload.hex()}"
            
            # Clean the decoded string
            cleaned = ''.join(char for char in decoded if char.isprintable() or char in '\n\t\r')
            
            # If after cleaning we have no content, return hex
            if not cleaned.strip():
                return f"[Binary/Encrypted Data]\nLength: {len(payload)} bytes\nHex: {payload.hex()}"
            
            # Check for common protocols and formats
            if cleaned.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'HTTP/')):
                http_info = self._get_http_info(payload)
                if http_info:
                    if http_info['type'] == 'request':
                        return f"[HTTP Request]\n{http_info['method']} {http_info['path']}\nHeaders:\n" + \
                               '\n'.join(f"  {k}: {v}" for k, v in http_info['headers'].items())
                    else:
                        return f"[HTTP Response]\n{http_info['status']}\nHeaders:\n" + \
                               '\n'.join(f"  {k}: {v}" for k, v in http_info['headers'].items())
                return f"[HTTP Data]\n{cleaned}"
            
            if cleaned.strip().startswith('{') or cleaned.strip().startswith('['):
                return f"[JSON Data]\n{cleaned}"
            
            if '<html' in cleaned.lower() or '<!doctype' in cleaned.lower():
                return f"[HTML Data]\n{cleaned}"
            
            if cleaned.strip().startswith('<?xml') or cleaned.strip().startswith('<'):
                return f"[XML Data]\n{cleaned}"
            
            # If it's just text but not any of the above
            return f"[Text Data]\n{cleaned}"
            
        except Exception as e:
            # If all decoding attempts fail, return hex
            return f"[Binary/Encrypted Data]\nLength: {len(payload)} bytes\nHex: {payload.hex()}"

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
                info['seq'] = packet[TCP].seq
                info['ack'] = packet[TCP].ack
                info['window'] = packet[TCP].window
                
                # Get TCP payload data
                if Raw in packet:
                    payload = packet[Raw].load
                    info['payload'] = self._format_payload(payload)
                    
                    # Check for HTTP data
                    http_data = self._get_http_info(payload)
                    if http_data:
                        info['http_data'] = http_data
                    
                    # Check for BitTorrent
                    if payload.startswith(b'BitTorrent protocol'):
                        info['protocol'] = 'BitTorrent'
                    
                    try:
                        dns_packet = DNS(payload)
                        if dns_packet:
                            dns_info = self._get_dns_info(dns_packet)
                            info.update(dns_info)
                    except:
                        pass
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['length'] = packet[UDP].len
                
                # Get UDP payload data
                if Raw in packet:
                    payload = packet[Raw].load
                    info['payload'] = self._format_payload(payload)
                
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
                info['seq'] = packet[TCP].seq
                info['ack'] = packet[TCP].ack
                info['window'] = packet[TCP].window
                
                # Get TCP payload data
                if Raw in packet:
                    payload = packet[Raw].load
                    info['payload'] = self._format_payload(payload)
                    
                    # Check for HTTP data
                    http_data = self._get_http_info(payload)
                    if http_data:
                        info['http_data'] = http_data
                    
                    # Check for BitTorrent
                    if payload.startswith(b'BitTorrent protocol'):
                        info['protocol'] = 'BitTorrent'
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['length'] = packet[UDP].len
                
                # Get UDP payload data
                if Raw in packet:
                    payload = packet[Raw].load
                    info['payload'] = self._format_payload(payload)
                
                # DNS specific information
                if DNS in packet:
                    dns_info = self._get_dns_info(packet)
                    info.update(dns_info)
            elif ICMP in packet:
                info['type'] = packet[ICMP].type
                info['code'] = packet[ICMP].code
                if Raw in packet:
                    info['payload'] = self._format_payload(packet[Raw].load)
        elif ARP in packet:
            info['op'] = packet[ARP].op
            info['src_mac'] = packet[ARP].hwsrc
            info['dst_mac'] = packet[ARP].hwdst
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
        
        return info

    def _print_packet_info(self, packet):
        """Print detailed packet information."""
        protocol = self._get_protocol_name(packet)
        info = self._get_protocol_info(packet)
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Protocol: {protocol}{Style.RESET_ALL}")
        
        # Print source and destination information
        if 'src_ip' in info:
            src_domain = self._resolve_ip_to_domain(info['src_ip'])
            domain_info = f" ({src_domain})" if src_domain else ""
            print(f"{Fore.YELLOW}Source IP: {info['src_ip']}{domain_info}{Style.RESET_ALL}")
        if 'dst_ip' in info:
            dst_domain = self._resolve_ip_to_domain(info['dst_ip'])
            domain_info = f" ({dst_domain})" if dst_domain else ""
            print(f"{Fore.YELLOW}Destination IP: {info['dst_ip']}{domain_info}{Style.RESET_ALL}")
        if 'src_port' in info:
            print(f"{Fore.YELLOW}Source Port: {info['src_port']}{Style.RESET_ALL}")
        if 'dst_port' in info:
            print(f"{Fore.YELLOW}Destination Port: {info['dst_port']}{Style.RESET_ALL}")
        
        # Print protocol-specific information
        if 'flags' in info:
            print(f"{Fore.YELLOW}TCP Flags: {info['flags']}{Style.RESET_ALL}")
            if 'seq' in info:
                print(f"{Fore.YELLOW}Sequence Number: {info['seq']}{Style.RESET_ALL}")
            if 'ack' in info:
                print(f"{Fore.YELLOW}Acknowledgement Number: {info['ack']}{Style.RESET_ALL}")
            if 'window' in info:
                print(f"{Fore.YELLOW}Window Size: {info['window']}{Style.RESET_ALL}")
        if 'length' in info:
            print(f"{Fore.YELLOW}UDP Length: {info['length']}{Style.RESET_ALL}")
        if 'type' in info:
            print(f"{Fore.YELLOW}ICMP Type: {info['type']}{Style.RESET_ALL}")
        if 'code' in info:
            print(f"{Fore.YELLOW}ICMP Code: {info['code']}{Style.RESET_ALL}")
        if 'protocol' in info:
            print(f"{Fore.YELLOW}Application Protocol: {info['protocol']}{Style.RESET_ALL}")
        
        # Print DNS information if available
        if 'type' in info and info['type'] in ['Query', 'Response']:
            print(f"\n{Fore.MAGENTA}DNS Information:{Style.RESET_ALL}")
            print(f"Type: {info['type']}")
            if 'query' in info:
                print(f"Query: {info['query']['name']} ({info['query']['type']})")
            if 'answers' in info and info['answers']:
                print("Answers:")
                for answer in info['answers']:
                    print(f"  {answer['name']} -> {answer['data']} ({answer['type']})")
            else:
                print("No answers in response")
            if 'authorities' in info and info['authorities']:
                print("Authorities:")
                for authority in info['authorities']:
                    print(f"  {authority['name']} -> {authority['data']} ({authority['type']})")
            if 'additionals' in info and info['additionals']:
                print("Additional Records:")
                for additional in info['additionals']:
                    print(f"  {additional['name']} -> {additional['data']} ({additional['type']})")
        
        # Print HTTP information if available
        if 'http_data' in info:
            print(f"\n{Fore.MAGENTA}HTTP Information:{Style.RESET_ALL}")
            print(info['http_data'])
        
        # Print payload data if available
        if 'payload' in info:
            print(f"\n{Fore.MAGENTA}Payload Data:{Style.RESET_ALL}")
            print(f"{info['payload']}")
        
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

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
            # Check if packet matches our domain IPs
            if self.domain_ips:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    if src_ip in self.domain_ips or dst_ip in self.domain_ips:
                        logger.info(f"Found matching packet: {src_ip} -> {dst_ip}")
                        self._print_packet_info(packet)
                        self.packets_captured += 1
                elif IPv6 in packet:
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst
                    if src_ip in self.domain_ips or dst_ip in self.domain_ips:
                        logger.info(f"Found matching packet: {src_ip} -> {dst_ip}")
                        self._print_packet_info(packet)
                        self.packets_captured += 1
            else:
                self._print_packet_info(packet)
                self.packets_captured += 1
            
            # Check if we've reached the packet count
            if self.packet_count and self.packets_captured >= self.packet_count:
                return True
            
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            return None

    def start_capture(self, timeout=None):
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
            
            # If we have domain IPs, capture all web traffic
            if self.domain_ips:
                self.filter_string = "tcp port 80 or tcp port 443"
                print(f"{Fore.YELLOW}Capturing web traffic (ports 80 and 443){Style.RESET_ALL}\n")
                print(f"{Fore.YELLOW}Monitoring IPs:{Style.RESET_ALL}")
                for ip in self.domain_ips:
                    print(f"  {ip}")
            
            # Print the filter being used
            if self.filter_string:
                print(f"{Fore.YELLOW}Using filter: {self.filter_string}{Style.RESET_ALL}\n")
            
            # Set up sniffing parameters
            sniff_params = {
                'iface': self.interface,
                'filter': self.filter_string,
                'prn': self.packet_callback,
                'store': 0,
                'stop_filter': lambda p: self.packets_captured >= self.packet_count if self.packet_count else False
            }
            
            # Add timeout if specified
            if timeout is not None or self.timeout is not None:
                sniff_params['timeout'] = timeout or self.timeout
            
            # Start sniffing
            logger.info("Starting packet capture...")
            sniff(**sniff_params)
            logger.info("Packet capture completed")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Packet capture stopped by user{Style.RESET_ALL}")
            return 0
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            return 1
        
        return 0

    def scan_ports(self, target, ports=None):
        """Scan for open ports on the target."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
        
        print(f"\n{Fore.CYAN}Scanning ports on {target}...{Style.RESET_ALL}")
        open_ports = []
        
        # Common port descriptions
        port_descriptions = {
            21: "FTP",
            22: "SSH",
            23: "Telnet", 
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
        
        for port in ports:
            # Create SYN packet
            syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
            
            # Send packet and wait for response
            response = sr1(syn_packet, timeout=1, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                    sr1(rst_packet, timeout=1, verbose=0)
                    open_ports.append(port)
                    service = port_descriptions.get(port, "Unknown")
                    print(f"{Fore.GREEN}Port {port} ({service}) is open{Style.RESET_ALL}")
                elif response[TCP].flags == 0x14:  # RST-ACK
                    print(f"{Fore.RED}Port {port} is closed{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Port {port} is filtered/blocked{Style.RESET_ALL}")
        
        if open_ports:
            print(f"\n{Fore.GREEN}Open ports found: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Services detected:{Style.RESET_ALL}")
            for port in open_ports:
                service = port_descriptions.get(port, "Unknown")
                print(f"  {port}/tcp - {service}")
        else:
            print(f"\n{Fore.YELLOW}No open ports found{Style.RESET_ALL}")
        
        return open_ports

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('--interface', help='Network interface to capture packets from')
    parser.add_argument('--filter', help='BPF filter string')
    parser.add_argument('--count', type=int, help='Number of packets to capture')
    parser.add_argument('--source', help='Source IP address to track')
    parser.add_argument('--domain', help='Domain name to filter DNS packets')
    parser.add_argument('--timeout', type=int, help='Timeout in seconds for packet capture')
    parser.add_argument('--scan', help='Target to scan for open ports')
    return parser.parse_args()

def main():
    """Main function."""
    try:
        args = parse_arguments()
        
        # If scan argument is provided, perform port scan (doesn't need interface)
        if args.scan:
            # Create a minimal sniffer for scanning (interface not needed for scanning)
            sniffer = PacketSniffer()
            sniffer.scan_ports(args.scan)
            return 0
        
        # Create packet sniffer for capture operations
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
        
        return sniffer.start_capture(timeout=args.timeout)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by user{Style.RESET_ALL}")
        return 0
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program terminated by user{Style.RESET_ALL}")
        sys.exit(0) 