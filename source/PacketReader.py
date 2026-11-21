from scapy.all import *
from pathlib import Path
from queue import Full, Empty
from errHandler import InterfaceNotFoundError, ReaderNotRunningError

class PacketReader:
    def __init__(self, packet_queue):
        self.captures_folder = Path(__file__).resolve().parent.parent / "captures"
        self.packet_queue = packet_queue
        self.dropped_packets = 0
        self.captured_packets = 0
        self.iface = None
        self.ifaces = get_working_ifaces()
        self.sniffer = None

    def read(self, source, type="live") -> PacketList:
        if type == "live":
            self.iface = self.identify_iface(source)

            # already running
            if self.has_live_thread():
                return

            self.drain_queue()

            # start a background sniffing thread
            self.sniffer = AsyncSniffer(prn=self.handle_packet, store=False, iface=self.iface)
            self.sniffer.start()

        else:
            source_path = Path(source)
            if source_path.is_file():
                packets = rdpcap(source)
            elif (self.captures_folder / source).is_file():
                packets = rdpcap(str(self.captures_folder / source))
            else:
                raise FileNotFoundError(f"File does not exist: {source_path}")
            
            return packets

    def identify_iface(self, iface_name):
        for iface in self.ifaces:
            if iface.name == iface_name:
                return iface

        else:
            raise InterfaceNotFoundError

    def drain_queue(self):
        while True:
            try:
                self.packet_queue.get_nowait()
            except Empty:
                return

    def handle_packet(self, packet):
        try:
            self.packet_queue.put_nowait(packet)
            self.captured_packets += 1
        except Full:
            self.dropped_packets += 1


    def get_ifaces(self):
        return self.ifaces

    def stop(self): 
        if not self.has_live_thread():
            return 
        try:
            self.sniffer.stop()
        except:
            raise ReaderNotRunningError

    def check_sniffer(self):
        if self.sniffer is None:
            return None

        return self.sniffer.exception

    def has_live_thread(self) -> bool:
        return (
            self.sniffer is not None
            and self.sniffer.thread is not None
            and self.sniffer.thread.is_alive()
        )