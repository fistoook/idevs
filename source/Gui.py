from PySide6.QtWidgets import (QMainWindow, QLabel, QWidget, QVBoxLayout, QHBoxLayout, 
                               QGridLayout, QStackedWidget, QPushButton, QToolButton, 
                               QListWidget, QTableWidget, QTableWidgetItem, QTreeWidget, 
                               QTreeWidgetItem, QMessageBox, QHeaderView)
from PySide6.QtCore import Qt, Signal, QTimer, QSize, QPointF, QSignalBlocker
from PySide6.QtGui import QIcon, QPainter, QPen, QColor, QPolygonF
from queue import Empty
from errHandler import ReaderNotRunningError, InterfaceNotFoundError
from scapy.all import IP, TCP, UDP, IPv6
from InterfaceActivityMonitor import InterfaceActivityMonitor
from collections import deque


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
        self.capture_page.back_to_homepage.connect(self.back_to_homepage)

    def begin_capture(self, interface):
        self.curr_interface = interface
        self.capture_page.iface_name.setText(interface)
        self.pages.setCurrentWidget(self.capture_page)
        self.capture_page.set_capture_state(True)
        self.capture_page.packet_table.setRowCount(0)
        self.capture_page.packet_count = 0

        try:
            self.packet_reader.read(interface)

        except InterfaceNotFoundError:
            return 
        
        self.timer.start(50)

    def resume_capture(self):
        try:
            self.packet_reader.read(self.curr_interface)
            self.capture_page.set_capture_state(True)

        except InterfaceNotFoundError:
            return 
        
        self.timer.start(50)

    def retrieve_packets(self):
        for _ in range(10):
            try:
                error = self.packet_reader.check_sniffer()

                if error is not None:
                    self.timer.stop()
                    self.capture_page.capture_button.setEnabled(False)
                    self.pages.setCurrentWidget(self.home_page)
                    self.home_page.timer.start()
                    QMessageBox.warning(self, "Capture failed", str(error))
                    return

                self.capture_page.capture_button.setEnabled(True)
                packet = self.packet_queue.get_nowait()
                self.capture_page.display_packet(packet)

            except Empty:
                return

    def stop_capture(self) -> bool:
        try:
            self.capture_page.capture_button.setEnabled(False)
            self.packet_reader.stop()
            self.capture_page.set_capture_state(False)
        except (ReaderNotRunningError, PermissionError):
            self.capture_page.capture_button.setEnabled(False)
            self.home_page.timer.start()
            QMessageBox.warning(self, "Capture failed", str("stopping failed"))
            return False
        
        self.capture_page.capture_button.setEnabled(True)
        self.timer.stop()

        return True

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)

    def back_to_homepage(self):
        if self.stop_capture():
            self.pages.setCurrentWidget(self.home_page)
            self.home_page.timer.start()





class HomePage(QWidget):
    capture_request = Signal(str)

    def __init__(self, ifaces):
        super().__init__()

        # initlize interface activity monitor and timer for the graph view
        self.interface_activity_monitor = InterfaceActivityMonitor()
        self.interface_graphs = {}
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_activity)
        self.timer.setInterval(1000)

        # vertical box layout
        self.layout = QVBoxLayout(self)

        # initialize welcome label
        self.welcome_label = QLabel("Welcome to IdevS :)")
        self.welcome_label.setObjectName("welcomeLabel")

        # initilialize the interface tree, style it, and populate it
        self.interface_tree = QTreeWidget()
        self.interface_tree.setObjectName("interfaceTree")
        self.interface_tree.setHeaderLabels(["Interface", "Address", "Activity"])
        header = self.interface_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.interface_tree.setAlternatingRowColors(True)
        self.interface_tree.doubleClicked.connect(self.request_capture)
        self.populate_interfaces(ifaces)

        # add the widgets to layout
        self.layout.addWidget(self.welcome_label)
        self.layout.addWidget(self.interface_tree)

    def update_activity(self):
        sample = self.interface_activity_monitor.get_activity()

        for name, graph in self.interface_graphs.items():
            if name in sample:
                graph.handle_sample(sample[name])

    def populate_interfaces(self, ifaces):
        self.interface_tree.clear()

        for iface in ifaces:
            graph = ActivityGraph()
            self.interface_graphs[iface.name] = graph

            parent = QTreeWidgetItem(self.interface_tree, [iface.name or "Unknown", iface.ip or "-", ""])

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

            # resize 
            parent.setSizeHint(2, QSize(140, 30))

            # add it to the interface tree
            self.interface_tree.setItemWidget(parent, 2, graph)

        # start the graoh activity timer    
        self.timer.start()

    def request_capture(self):
        item = self.interface_tree.currentItem()

        if item is None: return

        interface_name = item.data(0, Qt.ItemDataRole.UserRole)
        if not interface_name: return

        self.timer.stop()
        self.capture_request.emit(interface_name)





class CapturePage(QWidget):
    stop_capture_request = Signal()
    resume_capture_request = Signal()
    back_to_homepage  = Signal()

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

        # back to home page button
        self.back_button = QPushButton(text="back")
        self.back_button.setObjectName("backButton")
        self.back_button.clicked.connect(self.handle_back)

        # interface name label
        self.iface_name = QLabel()
        self.iface_name.setObjectName("ifaceName")

        # icons for the toggle cpature/stop button
        self.capturing_icon = QIcon("assets/icons/capturing-icon.svg")
        self.stopped_icon = QIcon("assets/icons/stopped-icon.svg")

        # capture stop button initialization
        self.capture_button = QToolButton()
        self.capture_button.setObjectName("captureButton")
        self.capture_button.setIcon(self.capturing_icon)
        self.capture_button.setCheckable(True)
        self.capture_button.setEnabled(True)
        self.capture_button.setIconSize(QSize(24, 24))
        self.capture_button.toggled.connect(self.toggle_capture)

        # add the the qidgets to the layout
        self.header_layout.addWidget(self.back_button)
        self.header_layout.addWidget(self.iface_name)
        self.header_layout.addWidget(self.capture_button)

    def handle_back(self):
        self.back_to_homepage.emit()

    def toggle_capture(self, checked):
        if checked:
            self.stop_capture_request.emit()
        else:
            self.resume_capture_request.emit()

    def init_table(self):
        self.packet_table = QTableWidget(0, 5)
        self.packet_table.setHorizontalHeaderLabels(["Number", "Source", "Destanation", "Protocl", "Length"])
        self.packet_table.verticalHeader().setVisible(False)
        self.scroll_bar = self.packet_table.verticalScrollBar()
        self.max_rows = 5000
        self.packet_count = 0

    def init_stats(self):
        self.stats = QWidget()
        self.stats_layout = QHBoxLayout(self.stats)

        self.captured_label = QLabel(f"Captured: {self.packet_reader.captured_packets}")
        self.dropped_label = QLabel(f"dropped: {self.packet_reader.dropped_packets}")

        self.stats_layout.addWidget(self.captured_label)
        self.stats_layout.addWidget(self.dropped_label)

    def display_packet(self, packet):
        # check for too much rows
        if self.packet_table.rowCount() >= self.max_rows:
            self.packet_table.removeRow(0)

        self.packet_count += 1

        at_bottom = (self.scroll_bar.value() == self.scroll_bar.maximum()) # check if user scrolled up
        row = self.packet_table.rowCount()

        self.packet_table.insertRow(row)

        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))

        src, dst = self.resolve_ips(packet)
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))

        protocl = self.identify_protocl(packet)
        self.packet_table.setItem(row, 3, QTableWidgetItem(protocl))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(len(packet))))

        if at_bottom:
            self.packet_table.scrollToBottom()

        self.captured_label.setText(f"Captured: {self.packet_reader.captured_packets}")
        self.dropped_label.setText(f"dropped: {self.packet_reader.dropped_packets}")

    def set_capture_state(self, running):
        # temprorialy stop the button from emitting more signals
        with QSignalBlocker(self.capture_button):
            self.capture_button.setChecked(not running)

        icon = self.capturing_icon if running else self.stopped_icon
        self.capture_button.setIcon(icon)

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







class ActivityGraph(QWidget):
    def __init__(self):
        super().__init__()

        self.history = deque([0] * 40, maxlen=40)

        self.set_options()

    def set_options(self):
        self.setFixedSize(130, 22)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAutoFillBackground(True)

    def handle_sample(self, sample):
        self.history.append(sample)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = max(1, self.width() - 8)
        height = max(1, self.height() - 8)

        maximum = max(max(self.history), 1)

        points = QPolygonF()

        for i, value in enumerate(self.history):
            x = 4 + i * width / (len(self.history) - 1)
            y = 4 + height - (value / maximum) * height

            points.append(QPointF(x, y))

        painter.setPen(QPen(QColor("#A9D59C"), 1))
        painter.drawPolyline(points)