from scapy.all import *
from pathlib import Path

class PacketReader:
    def __init__(self):
        self.captures_folder = Path(__file__).resolve().parent.parent / "captures"

    def read(self, source) -> PacketList:
        if source == "live":
            sniffer = AsyncSniffer(prn=self.handle_packet, store=False)
            sniffer.start()
        else:
            source_path = Path(source)
            if source_path.is_file():
                packets = rdpcap(source)
            elif (self.captures_folder / source).is_file():
                packets = rdpcap(str(self.captures_folder / source))
            else:
                raise FileNotFoundError
            return packets

    def handle_packet(self, packet):
        print(packet.summary())