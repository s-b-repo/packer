from scapy.all import *
import random
import time
import argparse
import logging
from pathlib import Path

class PacketFuzzer:
    def __init__(self, target_ip, output_file="packets.fuzz"):
        self.target_ip = target_ip
        self.output_file = Path(output_file)
        self.logger = self._setup_logger()
        
    def _setup_logger(self):
        logger = logging.getLogger("PacketFuzzer")
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File handler
        fh = logging.FileHandler('fuzzer.log')
        fh.setFormatter(formatter)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        return logger

    def _random_bytes(self, length=10):
        return bytes(random.getrandbits(8) for _ in range(length))

    def _generate_base_packet(self):
        """Create packet with random layer combination"""
        layers = [
            IP(dst=self.target_ip)/TCP(),
            IP(dst=self.target_ip)/UDP(),
            IP(dst=self.target_ip)/ICMP(),
            IP(dst=self.target_ip)/Raw(load=self._random_bytes(20))
        ]
        return random.choice(layers)

    def _malform_ip(self, packet):
        """Randomize IP header fields"""
        ip = packet[IP]
        ip.version = random.randint(0, 15)
        ip.ihl = random.randint(0, 15)
        ip.len = random.randint(0, 20)
        ip.ttl = random.randint(0, 1)
        ip.id = random.randint(0, 65535)
        ip.flags = random.randint(0, 7)
        return packet

    def generate_malformed_packet(self):
        """Generate one malformed packet with random anomalies"""
        packet = self._generate_base_packet()
        packet = self._malform_ip(packet)
        
        if TCP in packet:
            packet[TCP].flags = random.randint(0, 255)
            packet[TCP].sport = random.randint(0, 65535)
            packet[TCP].dport = random.randint(0, 65535)
            
        elif UDP in packet:
            packet[UDP].len = random.randint(0, 5)
            packet[UDP].sport = random.randint(0, 65535)
            packet[UDP].dport = random.randint(0, 65535)
            
        elif ICMP in packet:
            packet[ICMP].type = random.randint(0, 255)
            packet[ICMP].code = random.randint(0, 255)
            
        return packet

    def generate_fragmented_packets(self):
        """Generate multiple fragmented packets"""
        payload = self._random_bytes(1400)
        packet = IP(dst=self.target_ip)/UDP()/payload
        return fragment(packet)

    def save_packets(self, packets, mode='a'):
        """Save packets to file in hex format"""
        with self.output_file.open(mode) as f:
            for p in packets:
                try:
                    f.write(p.hex() + '\n')
                except Exception as e:
                    self.logger.error(f"Error saving packet: {e}")

    def generate_continuous(self, interval=0.1, max_packets=1000):
        """Continuous packet generation mode"""
        self.logger.info(f"Starting packet generation to {self.target_ip}")
        try:
            for _ in range(max_packets):
                if random.random() < 0.2:  # 20% chance for fragmented packets
                    fragments = self.generate_fragmented_packets()
                    self.save_packets(fragments)
                else:
                    packet = self.generate_malformed_packet()
                    self.save_packets([packet])
                
                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Packet generation stopped by user")

    def test_saved_packets(self, test_target, delay=0.1):
        """Replay saved packets against a target"""
        self.logger.info(f"Testing saved packets against {test_target}")
        try:
            with self.output_file.open('r') as f:
                for line in f:
                    try:
                        packet = bytes.fromhex(line.strip())
                        send(IP(packet), verbose=0)
                        self.logger.info(f"Sent packet to {test_target}")
                        time.sleep(delay)
                    except Exception as e:
                        self.logger.error(f"Failed to send packet: {e}")
        except FileNotFoundError:
            self.logger.error("No packet file found. Generate packets first.")

def main():
    parser = argparse.ArgumentParser(description="Network Fuzzing Tool")
    parser.add_argument('mode', choices=['generate', 'test'], 
                      help="'generate' to create packets, 'test' to replay them")
    parser.add_argument('-t', '--target', required=True,
                      help="Target IP address for generation/testing")
    parser.add_argument('-f', '--file', default="packets.fuzz",
                      help="Packet storage file")
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                      help="Delay between packets (seconds)")
    parser.add_argument('-m', '--max', type=int, default=1000,
                      help="Maximum packets to generate")

    args = parser.parse_args()

    fuzzer = PacketFuzzer(args.target, args.file)
    
    if args.mode == 'generate':
        fuzzer.generate_continuous(args.delay, args.max)
    elif args.mode == 'test':
        fuzzer.test_saved_packets(args.target, args.delay)

if __name__ == "__main__":
    main()
