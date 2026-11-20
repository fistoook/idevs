from PySide6.QtWidgets import QApplication
from Gui import MainWindow
from PacketReader import PacketReader
from queue import Queue

def main():
    packet_queue = Queue(maxsize=10000)

    packet_reader = PacketReader(packet_queue)
    app = QApplication()
    window = MainWindow(packet_reader, packet_queue)

    window.show()
    app.exec()



if __name__ == "__main__":
    main()