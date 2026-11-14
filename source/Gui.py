import sys
from PySide6.QtWidgets import QMainWindow, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QStackedWidget
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.pages = QStackedWidget()

        home_window = HomeWindow()
        capture_window = CaptureWindow()

        self.setCentralWidget(self.pages)

        self.pages.addWidget(home_window)
        self.pages.addWidget(capture_window)

        self.pages.setCurrentWidget(capture_window)

class HomeWindow(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        label1 = QLabel("Interface 1")
        label2 = QLabel("Interface 2")
        label3 = QLabel("Interface 3")
        label4 = QLabel("Interface 4")

        label1.setAlignment(Qt.AlignCenter)
        label2.setAlignment(Qt.AlignCenter)
        label3.setAlignment(Qt.AlignCenter)
        label4.setAlignment(Qt.AlignCenter)

        layout.addWidget(label1)
        layout.addWidget(label2)
        layout.addWidget(label3)
        layout.addWidget(label4)

class CaptureWindow(QWidget):
    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout(self)

        label1 = QLabel("Packet 1")
        label2 = QLabel("Packet 2")
        label3 = QLabel("Packet 3")
        label4 = QLabel("Packet 4")

        label1.setAlignment(Qt.AlignCenter)
        label2.setAlignment(Qt.AlignCenter)
        label3.setAlignment(Qt.AlignCenter)
        label4.setAlignment(Qt.AlignCenter)

        layout.addWidget(label1)
        layout.addWidget(label2)
        layout.addWidget(label3)
        layout.addWidget(label4)

