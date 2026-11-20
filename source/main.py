from PySide6.QtWidgets import QApplication
from Gui import MainWindow
from PacketReader import PacketReader
from queue import Queue
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
STYLES_DIR = ROOT_DIR / "assets" / "styles"
STYLE_FILES = ["global.qss", "home_page.qss", "capture_page.qss"]

def main():
    packet_queue = Queue(maxsize=10000)
    packet_reader = PacketReader(packet_queue)

    app = QApplication()

    apply_styles(app)

    window = MainWindow(packet_reader, packet_queue)

    window.show()
    app.exec()

def apply_styles(app):
    try:
        styles = "\n".join(
            (STYLES_DIR / name).read_text(encoding="utf-8")
            for name in STYLE_FILES
        )

        app.setStyleSheet(styles)

    except FileNotFoundError:
        print("Unable to load styles sorry")


if __name__ == "__main__":
    main()