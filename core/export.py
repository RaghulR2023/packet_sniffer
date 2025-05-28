import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import csv
from datetime import datetime
import logging
from scapy.all import wrpcap

logger = logging.getLogger(__name__)

class PacketExporter:
    """Class for exporting captured packets in various formats."""
    
    @staticmethod
    def export_to_pcap(
        packets: List[Any],
        output_path: str,
        append: bool = False
    ) -> bool:
        """
        Export packets to PCAP format.
        
        Args:
            packets: List of Scapy packet objects
            output_path: Path to save the PCAP file
            append: Whether to append to existing file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            wrpcap(output_path, packets, append=append)
            logger.info(f"Exported {len(packets)} packets to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting to PCAP: {str(e)}")
            return False
    
    @staticmethod
    def export_to_json(
        packet_data: List[Dict[str, Any]],
        output_path: str,
        pretty: bool = True
    ) -> bool:
        """
        Export parsed packet data to JSON format.
        
        Args:
            packet_data: List of parsed packet dictionaries
            output_path: Path to save the JSON file
            pretty: Whether to format JSON with indentation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, 'w') as f:
                if pretty:
                    json.dump(packet_data, f, indent=2)
                else:
                    json.dump(packet_data, f)
            logger.info(f"Exported {len(packet_data)} packets to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            return False
    
    @staticmethod
    def export_to_csv(
        packet_data: List[Dict[str, Any]],
        output_path: str,
        fields: Optional[List[str]] = None
    ) -> bool:
        """
        Export parsed packet data to CSV format.
        
        Args:
            packet_data: List of parsed packet dictionaries
            output_path: Path to save the CSV file
            fields: List of fields to include (default: all)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not packet_data:
                logger.warning("No packets to export")
                return False
            
            # If fields not specified, use all fields from first packet
            if not fields:
                fields = list(packet_data[0].keys())
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(packet_data)
                
            logger.info(f"Exported {len(packet_data)} packets to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting to CSV: {str(e)}")
            return False
    
    @staticmethod
    def export_summary(
        packet_data: List[Dict[str, Any]],
        stats: Dict[str, Any],
        output_path: str
    ) -> bool:
        """
        Export a summary report of captured packets.
        
        Args:
            packet_data: List of parsed packet dictionaries
            stats: Dictionary containing packet statistics
            output_path: Path to save the summary file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_path, 'w') as f:
                f.write("Packet Capture Summary\n")
                f.write("=====================\n\n")
                
                # Write capture information
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"Total Packets: {stats['total_packets']}\n\n")
                
                # Protocol distribution
                f.write("Protocol Distribution\n")
                f.write("--------------------\n")
                for protocol, count in stats['protocols'].items():
                    f.write(f"{protocol}: {count}\n")
                f.write("\n")
                
                # Top source IPs
                f.write("Top Source IPs\n")
                f.write("-------------\n")
                for ip, count in sorted(stats['ip_sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"{ip}: {count}\n")
                f.write("\n")
                
                # Top destination IPs
                f.write("Top Destination IPs\n")
                f.write("------------------\n")
                for ip, count in sorted(stats['ip_destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"{ip}: {count}\n")
                f.write("\n")
                
                # Top ports
                f.write("Top Source Ports\n")
                f.write("---------------\n")
                for port, count in sorted(stats['ports']['src'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"{port}: {count}\n")
                f.write("\n")
                
                f.write("Top Destination Ports\n")
                f.write("--------------------\n")
                for port, count in sorted(stats['ports']['dst'].items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"{port}: {count}\n")
                
            logger.info(f"Exported summary to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting summary: {str(e)}")
            return False 