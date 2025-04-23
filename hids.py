import socket
import struct
import json
import datetime
import os
import signal
import sys

# Define log directory and file
LOG_DIR = "/var/log/ids"
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def log_alert(alert_data):
    """Log the alert to a JSON file."""
    with open(LOG_FILE, "a") as log_file:
        json.dump(alert_data, log_file)
        log_file.write("\n")

def parse_packet(packet):
    """Extract source IP, destination IP, and TCP flags."""
    ip_header = packet[0:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    
    # Check if it's TCP (protocol 6)
    if protocol == 6:
        tcp_header = packet[20:40]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        src_port = tcph[0]
        dst_port = tcph[1]
        flags = tcph[5]
        return src_ip, dst_ip, src_port, dst_port, flags
    return None

def detect_syn_flood():
    """Detect SYN flood attack using raw sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as err:
        print(f"Socket creation failed: {err}")
        return

    def handle_exit(signum, frame):
        """Handle Ctrl+C for graceful exit."""
        print("\n[INFO] IDS shutting down...")
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)  # Capture Ctrl+C

    print("[INFO] IDS started. Monitoring for SYN floods...")
    while True:
        packet, _ = sock.recvfrom(65565)
        parsed = parse_packet(packet)
        if parsed:
            src_ip, dst_ip, src_port, dst_port, flags = parsed
            # Check for SYN flag (0x02) without ACK (0x10)
            if flags & 0x02 and not (flags & 0x10):
                alert = {
                    "timestamp": str(datetime.datetime.now()),
                    "alert_type": "Possible SYN Flood",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port
                }
                print(f"[ALERT] {alert}")
                log_alert(alert)

if __name__ == "__main__":
    detect_syn_flood()
