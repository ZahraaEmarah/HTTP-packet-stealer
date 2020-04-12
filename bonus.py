import socket


class UdpPacket(object):
    def __init__(self, src_port, dst_port, length, checksum, data):
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.checksum = checksum
        self.data = data

    def to_byte_string(self):
        byte_str = self.src_port + self.dst_port + self.length + self.checksum + self.data
        return byte_str


def craft_packet(data, src_port, dst_port, src_ip_bytes, dst_ip_bytes) -> UdpPacket:
    length = 8 + len(data)  # length in bytes (8 bytes for header + each character is 1 byte in ascii)
    data_bytes = data.encode(encoding='UTF-8', errors='strict')
    src_port_bytes = src_port.to_bytes(2, byteorder='big')
    dst_port_bytes = dst_port.to_bytes(2, byteorder='big')
    checksum = calculate_checksum(src_ip_bytes, dst_ip_bytes, length.to_bytes(2, byteorder='big'),
                                  src_port_bytes, dst_port_bytes, data_bytes)
    packet = UdpPacket(src_port_bytes, dst_port_bytes, length.to_bytes(2, byteorder='big'),
                       checksum.to_bytes(2, byteorder='big'), data_bytes)
    return packet


def calculate_checksum(src_ip_bytes, dst_ip_bytes, length,
                       src_port_bytes, dst_port_bytes, data_bytes):
    reserved_protocol = 0x0011
    # Convert to hex str then hex numbers
    src_ip_hex_1 = int(src_ip_bytes.hex()[0:4], 16)
    src_ip_hex_2 = int(src_ip_bytes.hex()[5:8], 16)
    dst_ip_hex_1 = int(dst_ip_bytes.hex()[0:4], 16)
    dst_ip_hex_2 = int(dst_ip_bytes.hex()[5:8], 16)
    length_hex = int(length.hex(), 16)
    src_port_hex = int(src_port_bytes.hex(), 16)
    dst_port_hex = int(dst_port_bytes.hex(), 16)
    list_data = list(data_bytes)
    even_flag = -1
    data_hex = 0x00
    # Split and add each two bytes of the data bytes
    lower = 0x00
    for i in list_data:
        even_flag = even_flag * (-1)
        if even_flag == 1:
            lower = i
        else:
            data_hex += (i + lower*0x100)

    temp = reserved_protocol + src_ip_hex_1 + src_ip_hex_2 + dst_ip_hex_1 + dst_ip_hex_2 + length_hex + \
        length_hex + src_port_hex + dst_port_hex + data_hex

    temp_binary = temp.to_bytes(4, byteorder='big')
    list_checksum = list(temp_binary)
    even_flag = -1
    checksum = 0x00
    # Split and add each two bytes of the data bytes
    for i in list_checksum:
        even_flag = even_flag * (-1)
        if even_flag == 1:
            lower = i
        else:
            checksum += (i + lower * 0x100)
    # One's complement
    checksum = checksum ^ 0xFFFF
    return checksum


def setup_socket(byte_str, host, port, dst_host, dst_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 17)
    except IndexError as e:
        print(e)
        return None
    sock.bind((host, port))
    sock.sendto(byte_str, (dst_host, dst_port))


def main():
    print("\n\n")
    print("*" * 30)
    print(f"Packet Stealer: Hacker Edition")
    print("*" * 30)
    print("\n")

    data = "Hello!!!"
    src_port = 18888
    dst_port = 44444
    src_ip = '127.0.0.1'
    dst_ip = '127.0.0.1'

    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))

    udp_packet = craft_packet(data, src_port, dst_port, src_ip_bytes, dst_ip_bytes)
    byte_str = udp_packet.to_byte_string()
    print("Byte string: ", byte_str)
    setup_socket(byte_str, src_ip, src_port, dst_ip, dst_port)


if __name__ == "__main__":
    main()
