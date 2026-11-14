from PacketReader import PacketReader
from errHandler import errHandler

WELCOME_MSG = "Welcome to idevs!"

class tui:
    def __init__(self):
        self.packet_reader = PacketReader()
        self.err_handler = errHandler()

    def run(self):
        print(WELCOME_MSG)

        while True:
            try:
                command = input("> ").strip().lower().split()
                match len(command):
                    case 0:
                        continue
                    case 1:
                        match command[0]:
                            case "help": self.print_help()
                            case _: self.err_handler.errInvalidCommand()
                    case 2:
                        match command[0]:
                            case "read": self.packet_reader.read(command[1])
                            case _: self.err_handler.errInvalidCommand()
                    case _:
                        self.err_handler.errTooManyArgs()

            except KeyboardInterrupt:
                break
            except FileNotFoundError:
                print("invalid argument: not a file")

    def print_help(self):
        pass