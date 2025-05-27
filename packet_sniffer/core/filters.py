from typing import Optional, List, Dict, Any
import re

class PacketFilter:
    """Class for creating and managing packet filters."""
    
    @staticmethod
    def create_bpf_filter(
        protocols: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        hosts: Optional[List[str]] = None,
        custom: Optional[str] = None
    ) -> str:
        """
        Create a Berkeley Packet Filter (BPF) string from filter parameters.
        
        Args:
            protocols: List of protocols (e.g., ['tcp', 'udp'])
            ports: List of ports to filter
            hosts: List of IP addresses or hostnames
            custom: Custom BPF filter string to append
            
        Returns:
            BPF filter string
        """
        filter_parts = []
        
        # Add protocol filters
        if protocols:
            protocols_str = ' or '.join(protocols)
            if len(protocols) > 1:
                protocols_str = f"({protocols_str})"
            filter_parts.append(protocols_str)
        
        # Add port filters
        if ports:
            ports_str = ' or '.join(f"port {port}" for port in ports)
            if len(ports) > 1:
                ports_str = f"({ports_str})"
            filter_parts.append(ports_str)
        
        # Add host filters
        if hosts:
            hosts_str = ' or '.join(f"host {host}" for host in hosts)
            if len(hosts) > 1:
                hosts_str = f"({hosts_str})"
            filter_parts.append(hosts_str)
        
        # Add custom filter
        if custom:
            filter_parts.append(f"({custom})")
        
        # Combine all parts with 'and'
        return ' and '.join(f"{part}" for part in filter_parts) if filter_parts else ""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format."""
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(ip_pattern.match(ip))
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        return 0 <= port <= 65535
    
    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """Validate protocol name."""
        valid_protocols = {'tcp', 'udp', 'icmp', 'arp', 'ip'}
        return protocol.lower() in valid_protocols
    
    @staticmethod
    def apply_post_capture_filter(
        packet_data: Dict[str, Any],
        filter_criteria: Dict[str, Any]
    ) -> bool:
        """
        Apply filtering after packet capture for more complex filtering.
        
        Args:
            packet_data: Parsed packet data dictionary
            filter_criteria: Dictionary of filtering criteria
            
        Returns:
            True if packet matches filter, False otherwise
        """
        # Check protocol
        if 'protocol' in filter_criteria:
            if packet_data.get('protocol') != filter_criteria['protocol']:
                return False
        
        # Check source
        if 'source' in filter_criteria:
            if packet_data.get('source') != filter_criteria['source']:
                return False
        
        # Check destination
        if 'destination' in filter_criteria:
            if packet_data.get('destination') != filter_criteria['destination']:
                return False
        
        # Check source port
        if 'source_port' in filter_criteria:
            if packet_data.get('source_port') != filter_criteria['source_port']:
                return False
        
        # Check destination port
        if 'destination_port' in filter_criteria:
            if packet_data.get('destination_port') != filter_criteria['destination_port']:
                return False
        
        # Check packet length range
        if 'min_length' in filter_criteria:
            if packet_data.get('length', 0) < filter_criteria['min_length']:
                return False
        
        if 'max_length' in filter_criteria:
            if packet_data.get('length', 0) > filter_criteria['max_length']:
                return False
        
        return True 