from scapy.all import sniff, wrpcap
import logging
from typing import Optional, Callable
import netifaces

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(
        self,
        interface: Optional[str] = None,
        filter_string: Optional[str] = None,
        packet_count: Optional[int] = None
    ):
        self.interface = interface or self._get_default_interface()
        self.filter_string = filter_string
        self.packet_count = packet_count
        self.packets = []
        
    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            # Skip loopback
            if iface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(iface):
                return iface
        return interfaces[0]  # Return first interface if no better option found
    
    def packet_callback(self, packet) -> None:
        """Default callback for packet processing."""
        self.packets.append(packet)
        logger.debug(f"Captured packet: {packet.summary()}")
    
    def start_capture(
        self,
        callback: Optional[Callable] = None,
        output_file: Optional[str] = None
    ) -> None:
        """
        Start capturing packets on the specified interface.
        
        Args:
            callback: Function to process each captured packet
            output_file: Path to save captured packets
        """
        logger.info(f"Starting capture on interface {self.interface}")
        
        try:
            # Use provided callback or default
            packet_handler = callback or self.packet_callback
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=self.filter_string,
                prn=packet_handler,
                count=self.packet_count,
                store=bool(output_file)  # Only store if we need to save
            )
            
            # Save captured packets if output file specified
            if output_file and self.packets:
                wrpcap(output_file, self.packets)
                logger.info(f"Saved {len(self.packets)} packets to {output_file}")
                
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            raise
        
    def stop_capture(self) -> None:
        """Stop the packet capture."""
        # Scapy's sniff() runs in the main thread, so we need to handle
        # stopping via keyboard interrupt or external signal
        logger.info("Stopping packet capture") 