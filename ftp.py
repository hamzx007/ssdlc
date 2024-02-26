import signal
import sys
import os
import logging
import json
import time
import datetime
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor, protocol
from scapy.all import sniff
from scapy.packet import Raw 
from scapy.layers.inet import TCP, IP

class FlushHandler(logging.FileHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            log_entry = json.loads(msg)
            with open(self.baseFilename, "a", encoding=self.encoding) as f:
                f.write(json.dumps(log_entry) + self.terminator)
                f.flush()
        except Exception:
            self.handleError(record)

def start_sniffing():
    try:
        sniff(prn=packet_sniffer, filter="tcp", store=False)
    except Exception as e:
        logging.error("An error occurred in start_sniffing: %s", str(e))

# Set up logging configuration
log_file = 'FTP_logs.json'
logging.basicConfig(level=logging.INFO, format='%(message)s')
file_handler = FlushHandler(filename=log_file)
logging.getLogger().handlers = [file_handler]

# Define specific usernames and passwords
USERNAMES_PASSWORDS = {
    "admin": "admin@321",
    "root": "root@321"
}

class HoneypotFTPProtocol(LineOnlyReceiver):
    def __init__(self):
        self.username = None
        self.is_authenticated = False
        self.current_directory = "/tmp/ftpserver/"  # change it to your desired path

    def connectionMade(self):
        # Log the connection establishment as a scan
        self.log_activity("ConnectionRequest", "")
        self.sendLine("220 Welcome to the Gene6 ftpd 3.10.0 server".encode())

    def lineReceived(self, line):
        # Log the received command
        command = line.decode().strip()
        self.log_activity(command, "")
        command = command.split(" ")

        try:
            if not self.is_authenticated and command[0] not in ["USER", "PASS"]:
                self.sendLine("530 Not logged in".encode())
            elif command[0] == "USER":
                self.handle_user_command(command)
            elif command[0] == "PASS":
                self.handle_pass_command(command)
            elif command[0] == "LIST":
                self.handle_list_command()
            elif command[0] == "RETR":
                self.handle_retr_command(command)
            else:
                self.log_activity(command[0], "500 Unknown command")
                self.sendLine("500 Unknown command".encode())
        except Exception as e:
            logging.error("An error occurred: %s", str(e))
            self.sendLine("500 Internal Server Error".encode())

    def log_activity(self, command, response):
        timest = int(time.time())
        converted_time = datetime.datetime.fromtimestamp(timest).strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            "timestamp": converted_time,
            "source_ip": self.transport.getPeer().host,
            "command": command,
            "response": response,
            "username": self.username
        }
        logging.info(json.dumps(log_entry))

    def handle_user_command(self, command):
        if len(command) < 2 or command[1] not in USERNAMES_PASSWORDS:
            self.sendLine("530 Invalid username".encode())
        else:
            self.username = command[1]
            self.sendLine("331 User name okay, need password".encode())

    def handle_pass_command(self, command):
        if len(command) < 2 or self.username is None or command[1] != USERNAMES_PASSWORDS.get(self.username, ""):
            self.sendLine("530 Incorrect password".encode())
        else:
            self.is_authenticated = True
            self.sendLine("230 User logged in".encode())

    def handle_list_command(self):
        listing = "\n".join(os.listdir(self.current_directory))
        self.sendLine(("150 Here comes the directory listing.\n" + listing + "\n226 Directory send OK.").encode())

    def handle_retr_command(self, command):
        if len(command) < 2:
            self.sendLine("501 Syntax error in parameters or arguments".encode())
            return

        filename = command[1]
        filepath = os.path.join(self.current_directory, filename)

        if not os.path.isfile(filepath):
            self.sendLine(f"550 Failed to open file: {filename}".encode())
            return

        with open(filepath, 'r') as file:
            content = file.read()
            self.sendLine(f"150 Opening BINARY mode data connection for {filename}\n{content}\n226 Transfer complete.".encode())

    def connectionLost(self, reason):
        # Log the connection loss
        self.log_activity("CONNECTION_LOST", "")
        self.transport.loseConnection()

class HoneypotFTPFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return HoneypotFTPProtocol()

def packet_sniffer(packet):
    try:
        source_ip = packet[IP].src if packet.haslayer(IP) else ""

        if packet.haslayer(TCP):
            
            if packet[TCP].flags == "S" and packet[TCP].dport == 21:
                timest = int(time.time())
                converted_time = datetime.datetime.fromtimestamp(timest).strftime('%Y-%m-%d %H:%M:%S')
                log_entry = {
                    "timestamp": converted_time,
                    "source_ip": source_ip,
                    "command": "SCAN",
                    "response": "",
                    "username": ""
                }
                logging.info(json.dumps(log_entry))

            if packet[TCP].flags == "A" and packet[TCP].dport == 21:
                if Raw in packet:
                    command = packet[Raw].load.decode().strip()
                    if command:
                        timest = int(time.time())
                        converted_time = datetime.datetime.fromtimestamp(timest).strftime('%Y-%m-%d %H:%M:%S')
                        log_entry = {
                            "timestamp": converted_time,
                            "source_ip": source_ip,
                            "command": command,
                            "response": "",
                            "username": ""
                        }
                        logging.info(json.dumps(log_entry))
    except Exception as e:
        logging.error("An error occurred in packet_sniffer: %s", str(e))

def sigint_handler(signal, frame):
    print("Received interruption signal. Exiting gracefully...")
    reactor.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Register the signal handlers
    signal.signal(signal.SIGINT, sigint_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, sigint_handler)  # Termination signal

    # Rest of your existing code
    reactor.listenTCP(23, HoneypotFTPFactory())
    reactor.callInThread(start_sniffing)
    reactor.run()
    