from PySide6.QtWidgets import QMainWindow, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QPushButton, QToolButton, QListWidget, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt, Signal, QTimer, QSize
from PySide6.QtGui import QIcon
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
        self.home_page.capture_request.connect(self.begin_capture)
        self.timer.timeout.connect(self.retrieve_packets)
        self.capture_page.stop_capture_request.connect(self.stop_capture)
        self.capture_page.resume_capture_request.connect(self.resume_capture)

    def begin_capture(self, interface):
        self.curr_interface = interface
        self.pages.setCurrentWidget(self.capture_page)

        try:
            self.packet_reader.read(interface)
        except InterfaceNotFoundError:
            return 
        
        self.timer.start(50)

    def resume_capture(self):
        try:
            self.packet_reader.read(self.curr_interface)
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

    def stop_capture(self):
        try:
            self.packet_reader.stop()
        except ReaderNotRunningError:
            return
        except PermissionError:
            return

        self.timer.stop()

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)




class HomePage(QWidget):
    capture_request = Signal(str)

    def __init__(self, ifaces):
        super().__init__()

        self.layout = QVBoxLayout(self)

        self.welcome_label = QLabel("Welcome to IdevS :)")
        self.welcome_label.setObjectName("welcomeLabel")

        # initilialize the interface tree, style it, and populate it
        self.interface_tree = QTreeWidget()
        self.interface_tree.setObjectName("interfaceTree")
        self.interface_tree.setHeaderLabels(["Interface", "Address"])
        self.interface_tree.setColumnWidth(0, 200)
        self.interface_tree.setAlternatingRowColors(True)
        self.interface_tree.doubleClicked.connect(self.request_capture)
        self.populate_interfaces(ifaces)

        self.layout.addWidget(self.welcome_label)
        self.layout.addWidget(self.interface_tree)

    def populate_interfaces(self, ifaces):
        self.interface_tree.clear()

        for iface in ifaces:
            parent = QTreeWidgetItem(self.interface_tree, [iface.name or "Unknown", iface.ip or "-"])

            # preserve the actual Scapy interface object for later
            parent.setData(0, Qt.ItemDataRole.UserRole, iface.name)

            # information displayed when expanded
            details = {
                "Description": iface.description,
                "MAC Address": iface.mac,
                "IPv4 Addresses": ", ".join(iface.ips[4]),
                "IPv6 Addresses": ", ".join(iface.ips[6]),
                "Index": iface.index,
                "Network Name": iface.network_name,
            }

            # populate details in the parent
            for label, value in details.items():
                QTreeWidgetItem(parent, [label, str(value) if value else "N/A"])

            # do not show the details initally
            parent.setExpanded(False)


    def request_capture(self):
        self.interface = self.interface_tree.currentItem()

        if self.interface is not None:
            self.capture_request.emit(self.interface.data(0, Qt.ItemDataRole.UserRole))





class CapturePage(QWidget):
    stop_capture_request = Signal()
    resume_capture_request = Signal()

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
        # create the header widget, as a horizontal box 
        self.header = QWidget()
        self.header_layout = QHBoxLayout(self.header)

        # icons for the toggle cpature/stop button
        self.capturing_icon = QIcon("assets/icons/capturing-icon.svg")
        self.stopped_icon = QIcon("assets/icons/stopped-icon.svg")

        self.iface_name = QLabel(f"{self.packet_reader.iface}")
        self.iface_name.setObjectName("ifaceName")

        # capture stop button initialization
        self.capture_button = QToolButton()
        self.capture_button.setObjectName("captureButton")
        self.capture_button.setIcon(self.capturing_icon)
        self.capture_button.setCheckable(True)
        self.capture_button.setIconSize(QSize(24, 24))
        self.capture_button.toggled.connect(self.toggle_capture)

        # add the the qidgets to the layout
        self.header_layout.addWidget(self.iface_name)
        self.header_layout.addWidget(self.capture_button)

    def toggle_capture(self, checked):
        if checked:
            self.capture_button.setIcon(self.stopped_icon)
            self.stop_capture_request.emit()
        else:
            self.capture_button.setIcon(self.capturing_icon)
            self.resume_capture_request.emit()
        

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