import struct
import socket
import logging
import sys
import os
from Crypto.Cipher import XOR

MAX_ITER = 20


def parse_input():
    try:
        file_name = sys.argv[sys.argv.index('-f') + 1]
        address = sys.argv[sys.argv.index('-adr') + 1]
        crypt = '-cr' in sys.argv
        return file_name, address, crypt
    except ValueError:
        print('Format: {} [-f <file_name>] [-adr <address>] [-cr]'.format(sys.argv[0]))
        exit(0)
    except IndexError:
        print('Format: {} [-f <file_name>] [-adr <address>] [-cr]'.format(sys.argv[0]))
        exit(0)


def set_logger():
    logging.basicConfig(format='%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG,
                        filename='client.log')


def check_sum(inf_string):
    hash_sum = 0
    count_to = (len(inf_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = ord(inf_string[count + 1]) * 256 + ord(inf_string[count])
        hash_sum += this_val
        hash_sum &= 0xffffffff
        count += 2
    if count_to < len(inf_string):
        hash_sum += ord(inf_string[count_to])
        hash_sum &= 0xffffffff
    hash_sum = (hash_sum >> 16) + hash_sum & 0xffff
    hash_sum += hash_sum >> 16
    answer = ~hash_sum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xffff)
    return answer


def create_packet(id, num, message):
    header = struct.pack('bbHHh', 8, 0, 0, id, num)
    packet = header + message
    check = check_sum(str(packet))
    header = struct.pack('bbHHh', 8, 0, check, id, num)
    return header + message


def send_packet(sock, packet, expected_response, addr):
    code = 0
    i = 0
    while True:
        try:
            if i == MAX_ITER:
                return False
            if code == 0:
                sock.sendto(packet, (addr, 1))
                code = 1
            data, address = sock.recvfrom(1508)
            if struct.unpack('b', data[20:21])[0] != 0:
                continue
            answer = (data[28:len(data)]).decode()
            if answer == expected_response or answer == 'again':
                return True
            code = 0
        except socket.timeout:
            if len(packet) == 8:
                print('lol')
            code = 0
            i += 1
            continue


def send_file(file_name, addr, crypt):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(0.5)

    id = 4
    num = 0
    message = file_name
    cipher = XOR.new((open('key.txt', 'r')).readline())
    if crypt:
        message += ' true'
    else:
        message += ' false'

    packet = create_packet(id, num, message.encode())

    logging.info('Sending filename to server')

    if send_packet(s, packet, 'opened', addr):
        logging.info('Filename was sent to server')
    else:
        logging.error('Server is not available')
        return
    num += 1

    logging.info('Sending of file started')

    file_size = os.path.getsize(file_name)
    f = open(file_name, 'rb')
    message = f.read(1472)
    all_len = 0

    progress = 0
    num_data_sent = 0
    while message:
        all_len += len(message)
        logging.debug('Sending packet {}'.format(num))
        if crypt:
            message = cipher.encrypt(message)
        packet = create_packet(id, num, message)

        if send_packet(s, packet, 'correct', addr):
            logging.debug('Packet {} was sent successful'.format(num))
        else:
            logging.error('Server is not available')
            return
        num_data_sent += len(message)
        message = f.read(1472)

        if int((num_data_sent / file_size) * 100) > progress:
            progress = int(num_data_sent / file_size * 100)
            print(str(progress) + '%')

        if num + 1 < 0xffff:
            num += 1
        else:
            num = 0

    logging.debug('Sending last packet')

    packet = create_packet(id, num, b'')
    if send_packet(s, packet, '', addr):
        logging.info('File was sent to server successfully')
    else:
        logging.error('Server is not available')
        return


set_logger()
filename, address, crypt_status = parse_input()
send_file(filename, address, crypt_status)
