from PySide6.QtWidgets import QMainWindow, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QPushButton, QListWidget, QTableWidget, QTableWidgetItem
from PySide6.QtCore import Qt, Signal, QTimer
from queue import Empty
from errHandler import ReaderNotRunningError, InterfaceNotFoundError
from scapy.all import IP, TCP, UDP, IPv6

class MainWindow(QMainWindow):
    def __init__(self, packet_reader, packet_queue):
        super().__init__()

        self.packet_reader = packet_reader
        self.packet_queue = packet_queue
        self.timer = QTimer(self)

        self.setWindowTitle("IdevS")
        self.resize(1100, 700)
        self.setMinimumSize(800, 500)

        self.pages = QStackedWidget()
        self.setCentralWidget(self.pages)

        self.init_pages()
        self.init_connectors()

        self.pages.setCurrentWidget(self.home_page)

    def init_pages(self):
        self.home_page = HomePage(self.packet_reader.get_ifaces())
        self.capture_page = CapturePage(self.packet_reader)

        self.pages.addWidget(self.home_page)
        self.pages.addWidget(self.capture_page)

    def init_connectors(self):
        self.home_page.capture_request.connect(self.start_capture)
        self.timer.timeout.connect(self.retrieve_packets)
        self.capture_page.stop_capture_request.connect(self.stop)

    def start_capture(self, interface):
        self.pages.setCurrentWidget(self.capture_page)
        try:
            self.packet_reader.read(interface)
        except InterfaceNotFoundError:
            return 
        
        self.timer.start(50)
        

    def retrieve_packets(self):
        for _ in range(10):
            try:
                packet = self.packet_queue.get_nowait()
                self.capture_page.display_packet(packet)
            except Empty:
                return

    def stop(self):
        try:
            self.packet_reader.stop()
        except ReaderNotRunningError:
            return
        except PermissionError:
            return

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)

class HomePage(QWidget):
    capture_request = Signal(str)

    def __init__(self, ifaces):
        super().__init__()

        self.layout = QVBoxLayout(self)

        self.label = QLabel("Welcome. select your interface.")

        self.list = QListWidget()
        for iface in ifaces:
            self.list.addItem(iface.name)

        self.button = QPushButton("Select interface")
        self.button.clicked.connect(self.request_capture)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.list)
        self.layout.addWidget(self.button)

    def request_capture(self):
        self.interface = self.list.currentItem()

        if self.interface is not None:
            self.capture_request.emit(self.interface.text())

class CapturePage(QWidget):
    stop_capture_request = Signal()

    def __init__(self, packet_reader):
        super().__init__()
        
        self.layout = QVBoxLayout(self)
        self.packet_reader = packet_reader

        self.init_header()
        self.init_table()
        self.init_stats()

        self.layout.addWidget(self.header)
        self.layout.addWidget(self.packet_table)
        self.layout.addWidget(self.stats)

    def init_header(self):
        self.header = QWidget()
        self.header_layout = QHBoxLayout(self.header)

        self.iface_name = QLabel(f"{self.packet_reader.iface}")
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture_request.emit)

        self.header_layout.addWidget(self.iface_name)
        self.header_layout.addWidget(self.stop_button)

    def init_table(self):
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(["Number", "Source", "Destanation", "Protocl", "Length"])

    def init_stats(self):
        self.stats = QWidget()
        self.stats_layout = QHBoxLayout(self.stats)

        self.captured_label = QLabel(f"Captured: {self.packet_reader.captured_packets}")
        self.dropped_label = QLabel(f"dropped: {self.packet_reader.dropped_packets}")

        self.stats_layout.addWidget(self.captured_label)
        self.stats_layout.addWidget(self.dropped_label)

    def display_packet(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))

        src, dst = self.resolve_ips(packet)
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))

        protocl = self.identify_protocl(packet)
        self.packet_table.setItem(row, 3, QTableWidgetItem(protocl))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(len(packet))))

        self.iface_name.setText(f"{self.packet_reader.iface}")
        self.captured_label.setText(f"Captured: {self.packet_reader.captured_packets}")
        self.dropped_label.setText(f"dropped: {self.packet_reader.dropped_packets}")

    def resolve_ips(self, packet) -> tuple:
        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
        elif IPv6 in packet:
            source = packet[IPv6].src
            destination = packet[IPv6].dst
        else:
            source = destination = "—"

        return (source, destination)

    def identify_protocl(self, packet):
        if TCP in packet: return "TCP"
        elif UDP in packet: return "UDP"
        else: return "UnKnown"