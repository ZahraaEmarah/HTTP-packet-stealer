import socket
import binascii


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    return socket.inet_ntoa(raw_ip_addr)


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    src_port = int(binascii.hexlify(ip_packet_payload[0:2]), 16)
    dst_port = int(binascii.hexlify(ip_packet_payload[2:4]), 16)

    data_offset = ip_packet_payload[12:13]
    bit_arr = convert_to_bits(data_offset)
    data_offset = bit_arr[0:4]
    data_offset = int(data_offset, 2)
    start = int((data_offset * 32) / 8)
    data = ip_packet_payload[start:len(ip_packet_payload)]

    if validate(data):
        print(data.decode("utf-8"))

    return TcpPacket(src_port, dst_port, data_offset, data)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    source_address = parse_raw_ip_addr(ip_packet[12:16])
    destination_address = parse_raw_ip_addr(ip_packet[16:20])

    bits_arr = convert_to_bits(ip_packet)
    ihl = int(bits_arr[4:8], 2)
    protocol = int(bits_arr[73:80], 2)

    start = int((ihl * 32) / 8)
    payload = ip_packet[start:len(ip_packet)]
    parse_application_layer_packet(payload)

    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def convert_to_bits(packet: bytes):
    bit_arr = ""
    for bit in range(len(packet)):
        bit_arr = bit_arr + '{0:08b}'.format(packet[bit])
    return bit_arr


def validate(data):
    data = iter(data)
    ones = 8
    for y in data:
        # count the number of the leftmost consecutive ones
        for x in range(8):
            constant = 0b11111111 >> (7 - x)  # get the n left most bits
            constant = constant & (constant - 1)  # Flip the last bit
            if y >> (7 - x) == constant:
                ones = x

        if ones == 2 or ones == 3 or ones == 4 or ones == 5 or ones == 6:
            for i in range(ones - 1):  # Get the following bytes
                nxt_byte = next(data, -1)
                if nxt_byte != -1:
                    if nxt_byte >> 6 != 0b10:
                        return False
                else:
                    return False
        else:
            if ones != 0:
                return False

    return True


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    TCP = 6
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)
    while True:
        # Receive packets and do processing here
        packet, adrs = stealer.recvfrom(4096)
        parse_network_layer_packet(packet)
        pass
    pass


if __name__ == "__main__":
    main()
