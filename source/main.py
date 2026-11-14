from Tui import Tui
from PySide6.QtWidgets import QApplication
from Gui import MainWindow

def main():
    app = QApplication()
    window = MainWindow()

    window.show()
    app.exec()



if __name__ == "__main__":
    main()