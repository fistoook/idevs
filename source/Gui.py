from PySide6.QtWidgets import QMainWindow, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget, QPushButton, QListWidget
from PySide6.QtCore import Qt, Signal

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("IdevS")

        self.pages = QStackedWidget()
        self.setCentralWidget(self.pages)

        self.init_pages()
        self.init_connectors()

        self.pages.setCurrentWidget(self.home_page)

    def init_pages(self):
        self.home_page = HomePage()
        self.capture_page = CapturePage()

        self.pages.addWidget(self.home_page)
        self.pages.addWidget(self.capture_page)

    def init_connectors(self):
        self.home_page.capture_request.connect(self.start_capture)

    def start_capture(self, interface):
        self.pages.setCurrentWidget(self.capture_page)
        print(interface)

class HomePage(QWidget):
    capture_request = Signal(str)

    def __init__(self):
        super().__init__()
        
        self.layout = QVBoxLayout(self)

        self.label = QLabel("Welcome. select your interface.")

        self.list = QListWidget()
        self.list.addItems(["interface 1", "interface 2", "interface 3"])

        self.button = QPushButton("press me")
        self.button.clicked.connect(self.request_capture)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.list)
        self.layout.addWidget(self.button)

    def request_capture(self):
        interface = self.list.currentItem()

        if interface is not None:
            self.capture_request.emit(interface.text())

class CapturePage(QWidget):
    def __init__(self):
        super().__init__()
        
        layout = QGridLayout(self)

        label1 = QLabel("Number")
        label2 = QLabel("Source")
        label3 = QLabel("Destanation")
        label4 = QLabel("Protocol")

        label1.setAlignment(Qt.AlignCenter)
        label2.setAlignment(Qt.AlignCenter)
        label3.setAlignment(Qt.AlignCenter)
        label4.setAlignment(Qt.AlignCenter)

        layout.addWidget(label1, 0, 0)
        layout.addWidget(label2, 0, 1)
        layout.addWidget(label3, 0, 2)
        layout.addWidget(label4, 0, 3)