import socket
import struct
import logging
import datetime
import os
from Crypto.Cipher import XOR


def set_logger():
    logging.basicConfig(format='%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG,
                        filename='server.log')


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


def check_correct(packet):
    type, code, expected_sum, id, num = struct.unpack('bbHHh', packet[20:28])
    message = packet[28:len(packet)]
    header = struct.pack('bbHHh', type, code, 0, id, num)
    real_sum = check_sum(str(header + message))
    return real_sum == expected_sum


def create_packet(id, num, message):
    header = struct.pack('bbHHh', 0, 0, 0, id, num)
    packet = header + message
    check = check_sum(str(packet))
    header = struct.pack('bbHHh', 0, 0, check, id, num)
    return header + message


def give_unique_name(file_name):
    if os.path.exists(file_name):
        i = 1
        while True:
            if os.path.exists(str(i) + '_' + file_name):
                i += 1
            else:
                break
        return str(i) + '_' + file_name
    else:
        return file_name


def listen():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', 14900))
    info = open('work_history.txt', 'a')
    cipher = XOR.new((open('key.txt', 'r')).readline())
    places = {}
    while True:
        data, address = s.recvfrom(1508)
        if struct.unpack('b', data[20:21])[0] != 8:
            continue

        logging.info('Received packet from {} '.format(address[0]))

        packet_num = struct.unpack('H', data[26:28])[0]

        if not check_correct(data):
            logging.debug('Corrupted data in packet')
            print('Data corrupted')
            s.sendto(create_packet(0, packet_num, 'corrupted'.encode()), address)
            continue

        if address[0] not in places.keys():
            if len(data) == 28:
                s.sendto(create_packet(0, packet_num, b''), address)
                continue

            file_name, crypt = (data[28:len(data)]).decode().split(' ')
            uniq_name = give_unique_name(file_name)
            about_file = '\nFile: {}\nSaved as: {}\nReceived from: {}\nTime: {}\n'.format(
                file_name, uniq_name, address[0], datetime.datetime.now()
            )
            logging.info('New client. Opening new file {} for acceptance'.format(uniq_name))
            places[address[0]] = [open(uniq_name, 'wb'), 0, about_file, crypt]
            s.sendto(create_packet(0, packet_num, 'opened'.encode()), address)

        elif packet_num == places[address[0]][1] + 1 or places[address[0]][1] + 1 == 0xffff and packet_num == 0:
            if len(data) == 28:
                logging.info('Received end of file. Closing file')
                s.sendto(create_packet(0, packet_num, b''), address)
                item = places.pop(address[0])
                item[0].close()
                info.write(item[2])
            else:
                logging.debug('Correct data in packet')
                places[address[0]][1] = packet_num
                message = data[28:len(data)]
                if places[address[0]][3] == 'true':
                    message = cipher.decrypt(message)
                places[address[0]][0].write(message)
                s.sendto(create_packet(0, packet_num, 'correct'.encode()), address)

        elif packet_num == places[address[0]][1]:
            logging.debug('again')
            s.sendto(create_packet(0, packet_num, 'again'.encode()), address)


set_logger()
listen()
