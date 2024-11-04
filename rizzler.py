from scapy.all import *
import random
import time

def random_bytes(length=10):
    """Generate random bytes of a specified length."""
    return bytes(random.getrandbits(8) for _ in range(length))

def generate_random_packet(destination_ip):
    """
    Generate a random packet with various layer combinations and malformed fields.
    """
    ip = IP(dst=destination_ip)
    tcp = TCP()
    udp = UDP()
    icmp = ICMP()
    raw = Raw(load=random_bytes(20))
    
    # Randomly choose a packet type
    packet_options = [
        ip/tcp,  # IP + TCP
        ip/udp,  # IP + UDP
        ip/icmp, # IP + ICMP
        ip/raw   # IP + Raw Data
    ]
    packet = random.choice(packet_options)
    
    # Randomize IP fields
    packet[IP].version = random.randint(0, 15)      # Invalid IP version
    packet[IP].ihl = random.randint(0, 15)          # Invalid header length
    packet[IP].len = random.randint(0, 20)          # Too short packet length
    packet[IP].ttl = random.randint(0, 1)           # Very low TTL
    packet[IP].id = random.randint(0, 65535)        # Random identification
    packet[IP].flags = random.randint(0, 7)         # Random flags

    # Malform TCP layer if present
    if TCP in packet:
        packet[TCP].flags = random.randint(0, 255)    # Random TCP flags
        packet[TCP].seq = random.randint(0, 1 << 32)  # Random sequence number
        packet[TCP].sport = random.randint(0, 65535)  # Random source port
        packet[TCP].dport = random.randint(0, 65535)  # Random destination port

    # Malform UDP layer if present
    if UDP in packet:
        packet[UDP].len = random.randint(0, 5)        # Invalid UDP length
        packet[UDP].sport = random.randint(0, 65535)  # Random source port
        packet[UDP].dport = random.randint(0, 65535)  # Random destination port

    # Malform ICMP layer if present
    if ICMP in packet:
        packet[ICMP].type = random.randint(0, 255)    # Random ICMP type
        packet[ICMP].code = random.randint(0, 255)    # Random ICMP code

    return bytes(packet)

def generate_fragmented_packet(destination_ip):
    """
    Generate a fragmented IP packet with unusual parameters.
    """
    ip = IP(dst=destination_ip)
    udp = UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))
    payload = random_bytes(1400)  # Large payload to ensure fragmentation
    fragments = fragment(ip/udp/payload)
    for fragment in fragments:
        fragment[IP].flags = "MF"  # More fragments flag
        fragment[IP].frag = random.randint(0, 8191)  # Random fragment offset
    return [bytes(fragment) for fragment in fragments]

def generate_flag_manipulated_packet(destination_ip):
    """
    Generate a packet with unusual TCP flag combinations.
    """
    ip = IP(dst=destination_ip)
    tcp = TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535), flags=random.choice(['S', 'F', 'R', 'FA', 'SA']))
    return bytes(ip/tcp)

def generate_protocol_layer_mix_packet(destination_ip):
    """
    Generate a packet with both TCP and UDP headers, or mixed protocols.
    """
    ip = IP(dst=destination_ip)
    tcp = TCP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))
    udp = UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535))
    packet = ip/tcp/udp/Raw(load=random_bytes(20))
    return bytes(packet)

def fuzz_packet_structure(destination_ip):
    """
    Randomly modify a packet structure to create undefined behavior.
    """
    ip = IP(dst=destination_ip, version=random.randint(0, 15), ihl=random.randint(0, 15), ttl=random.randint(0, 1))
    udp = UDP(sport=random.randint(1024, 65535), dport=random.randint(1024, 65535), len=random.randint(0, 5))
    return bytes(ip/udp/Raw(load=random_bytes(50)))

def generate_malformed_packet(destination_ip):
    """
    Select a method at random to generate a malformed packet.
    """
    methods = [
        generate_random_packet,
        generate_fragmented_packet,
        generate_flag_manipulated_packet,
        fuzz_packet_structure,
        generate_protocol_layer_mix_packet,
    ]
    selected_method = random.choice(methods)
    
    result = selected_method(destination_ip)
    if isinstance(result, list):  # Handle fragmented packets
        return b'\n'.join(result)
    return result

def write_packets_to_file(filename="malformed_packets.txt", delay=0.5):
    """
    Continuously generates malformed packets and writes each to a file in hex format.
    :param filename: Name of the file to save packets.
    :param delay: Delay between generating each packet.
    """
    destination_ip = input("Enter the destination IP address: ")  # Get IP from user
    with open(filename, "a") as file:
        while True:
            malformed_packet = generate_malformed_packet(destination_ip)
            hex_packet = malformed_packet.hex()  # Convert to hex string
            file.write(hex_packet + "\n")
            file.flush()  # Ensure immediate writing
            time.sleep(delay)

if __name__ == "__main__":
    try:
        write_packets_to_file(delay=0.1)
        print("Generating malformed packets continuously. Check malformed_packets.txt for output.")
    except KeyboardInterrupt:
        print("Packet generation stopped by user.")
