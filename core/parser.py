from scapy.all import IP, TCP, UDP, ICMP, ARP
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class PacketParser:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'ip_sources': {},
            'ip_destinations': {},
            'ports': {'src': {}, 'dst': {}}
        }
    
    def parse_packet(self, packet: Any) -> Dict[str, Any]:
        """
        Parse a captured packet and extract relevant information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing parsed packet information
        """
        self.stats['total_packets'] += 1
        parsed_data = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'protocol': None,
            'source': None,
            'destination': None,
            'info': {}
        }
        
        try:
            # Handle ARP packets
            if ARP in packet:
                parsed_data.update(self._parse_arp(packet))
                
            # Handle IP packets
            elif IP in packet:
                parsed_data.update(self._parse_ip(packet))
                
                # Handle transport layer protocols
                if TCP in packet:
                    parsed_data.update(self._parse_tcp(packet))
                elif UDP in packet:
                    parsed_data.update(self._parse_udp(packet))
                elif ICMP in packet:
                    parsed_data.update(self._parse_icmp(packet))
            
            # Update statistics
            self._update_stats(parsed_data)
            
        except Exception as e:
            logger.error(f"Error parsing packet: {str(e)}")
        
        return parsed_data
    
    def _parse_ip(self, packet) -> Dict[str, Any]:
        """Parse IP layer information."""
        return {
            'protocol': 'IP',
            'source': packet[IP].src,
            'destination': packet[IP].dst,
            'info': {
                'version': packet[IP].version,
                'ttl': packet[IP].ttl,
                'id': packet[IP].id
            }
        }
    
    def _parse_tcp(self, packet) -> Dict[str, Any]:
        """Parse TCP layer information."""
        return {
            'protocol': 'TCP',
            'source_port': packet[TCP].sport,
            'destination_port': packet[TCP].dport,
            'info': {
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack,
                'flags': packet[TCP].flags
            }
        }
    
    def _parse_udp(self, packet) -> Dict[str, Any]:
        """Parse UDP layer information."""
        return {
            'protocol': 'UDP',
            'source_port': packet[UDP].sport,
            'destination_port': packet[UDP].dport,
            'info': {
                'length': packet[UDP].len
            }
        }
    
    def _parse_icmp(self, packet) -> Dict[str, Any]:
        """Parse ICMP layer information."""
        return {
            'protocol': 'ICMP',
            'info': {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            }
        }
    
    def _parse_arp(self, packet) -> Dict[str, Any]:
        """Parse ARP layer information."""
        return {
            'protocol': 'ARP',
            'source': packet[ARP].psrc,
            'destination': packet[ARP].pdst,
            'info': {
                'op': packet[ARP].op,
                'hwsrc': packet[ARP].hwsrc,
                'hwdst': packet[ARP].hwdst
            }
        }
    
    def _update_stats(self, parsed_data: Dict[str, Any]) -> None:
        """Update packet statistics."""
        protocol = parsed_data.get('protocol')
        if protocol:
            self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
        
        source = parsed_data.get('source')
        if source:
            self.stats['ip_sources'][source] = self.stats['ip_sources'].get(source, 0) + 1
        
        destination = parsed_data.get('destination')
        if destination:
            self.stats['ip_destinations'][destination] = self.stats['ip_destinations'].get(destination, 0) + 1
        
        source_port = parsed_data.get('source_port')
        if source_port:
            self.stats['ports']['src'][source_port] = self.stats['ports']['src'].get(source_port, 0) + 1
        
        destination_port = parsed_data.get('destination_port')
        if destination_port:
            self.stats['ports']['dst'][destination_port] = self.stats['ports']['dst'].get(destination_port, 0) + 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current packet statistics."""
        return self.stats 