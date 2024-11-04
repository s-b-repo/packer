from scapy.all import *
import random
import time

class ProPacketFuzzer:
    def __init__(self, target_ip, target_port, delay=0.1, log_file="fuzzer_log.txt"):
        """
        Initialize the fuzzer with target details and configuration options.
        
        Args:
            target_ip (str): The target IP address.
            target_port (int): The target port number.
            delay (float): Delay between packet transmissions in seconds.
            log_file (str): File path for logging packet details and responses.
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.delay = delay
        self.log_file = log_file

        # Open log file
        with open(self.log_file, 'w') as f:
            f.write("Fuzzing Log\n")
            f.write("="*20 + "\n")

    def generate_packet(self):
        """Generate a packet with random combinations and malformed fields."""
        # Randomly select base protocol
        protocol_choice = random.choice(["TCP", "UDP", "ICMP"])
        
        if protocol_choice == "TCP":
            packet = IP(dst=self.target_ip) / TCP(dport=self.target_port)
            packet[TCP].seq = random.randint(0, 0xFFFFFFFF)
            packet[TCP].ack = random.randint(0, 0xFFFFFFFF)
            packet[TCP].window = random.randint(0, 0xFFFF)
            packet[TCP].flags = random.choice(["S", "A", "R", "F", "P", ""])
        
        elif protocol_choice == "UDP":
            packet = IP(dst=self.target_ip) / UDP(dport=self.target_port)
            packet[UDP].len = random.randint(1, 65535)
        
        elif protocol_choice == "ICMP":
            packet = IP(dst=self.target_ip) / ICMP()
            packet[ICMP].type = random.choice(range(0, 256))
            packet[ICMP].code = random.choice(range(0, 256))
        
        # Add random payload or combine with another protocol
        if random.choice([True, False]):
            payload_size = random.randint(20, 100)
            packet = packet / Raw(RandString(size=payload_size))
        
        # Combine with another layer to create unpredictable packets
        if random.choice([True, False]):
            extra_protocol = random.choice(["TCP", "UDP", "ICMP"])
            if extra_protocol == "TCP" and "TCP" not in packet:
                packet = packet / TCP(dport=random.randint(1, 65535), flags="S")
            elif extra_protocol == "UDP" and "UDP" not in packet:
                packet = packet / UDP(dport=random.randint(1, 65535))
            elif extra_protocol == "ICMP" and "ICMP" not in packet:
                packet = packet / ICMP(type=random.randint(0, 15), code=random.randint(0, 15))

        return packet

    def log_packet(self, packet, response):
        """Log packet and response information."""
        with open(self.log_file, 'a') as f:
            f.write(f"Packet Sent: {packet.summary()}\n")
            if response:
                f.write(f"Response Received: {response.summary()}\n")
            f.write("-" * 20 + "\n")

    def start_fuzzing(self):
        """Continuously send packets with random configurations, logging each result."""
        print("Starting continuous fuzzing process...")
        
        while True:
            packet = self.generate_packet()
            response = sr1(packet, timeout=1, verbose=False)  # Send packet and wait for one response
            self.log_packet(packet, response)
            print(f"Packet sent: {packet.summary()}")
            if response:
                print(f"Response: {response.summary()}")

            time.sleep(self.delay)

# Usage Example
target_ip = "192.168.1.100"  # Replace with actual target IP
target_port = 80             # Replace with actual target port
fuzzer = ProPacketFuzzer(
    target_ip=target_ip, 
    target_port=target_port, 
    delay=0.1,
    log_file="fuzzer_log.txt"
)
fuzzer.start_fuzzing()  # Continuous fuzzing, no packet count limit
