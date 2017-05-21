import socket
import struct
import logging
import datetime
import os
from Crypto.Cipher import XOR


def set_logger(log_file_name):
    """
    Установка нужных настроек логирования
    :param log_file_name: имя файла-лога
    :return: -
    """
    logging.basicConfig(format='%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG,
                        filename=log_file_name)


def check_sum(inf_string):
    """
    Подсчет контрольной суммы для icmp пакета
    :param inf_string: пакет в виде байт-строки
    :return: полученная контрольная сумма
    """
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
    """
    Проверка корректности доставленного пакета через пересчет контрольной суммы
    :param packet: доставленный пакет
    :return: True, если пакет корректен, иначе False
    """
    type, code, expected_sum, id, num = struct.unpack('bbHHh', packet[20:28])
    message = packet[28:len(packet)]
    header = struct.pack('bbHHh', type, code, 0, id, num)
    real_sum = check_sum(str(header + message))
    return real_sum == expected_sum


def create_packet(id, num, message):
    """
    Создание icmp пакета
    :param id: идентификатор из заголовка пакета
    :param num: номер пакета
    :param message: поле данных пакета
    :return: полученный пакет
    """
    header = struct.pack('bbHHh', 0, 0, 0, id, num)
    packet = header + message
    check = check_sum(str(packet))
    header = struct.pack('bbHHh', 0, 0, check, id, num)
    return header + message


def give_unique_name(file_name):
    """
    Создание уникального имени файла для исходного имени файла.
    Функция создана для корректности работы сервера в случае получения двух разных файлов с одинаковыми именами.
    "Уникальность" обеспечивается добавлением числа в начало имени файла.
    Соответственно, предполагается, что совпадения имен файлов, получаемых сервером, будут происходить редко.
    :param file_name: исходное имя файла
    :return: уникальное имя файла, полученное на основе исходного
    """
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


def listen(key):
    """
    Функция, в которой сервер проводит все время работы, в ней происходит обмен пакетами с клиентами
    :param key: ключ для XOR-шифрования
    :return: -
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', 14900))

    # Открывается файл, в который будет вноситься вся информация о полученных файлах
    # connects - словарь вида
    # {адрес : (открытый файл, номер текущего пакета, информация о посылке, статус шифрования)}
    info = open('work_history.txt', 'a')
    cipher = XOR.new(key)
    connects = {}

    while True:
        data, address = s.recvfrom(1508)

        # Сервер обрабатывает только запросы
        if struct.unpack('b', data[20:21])[0] != 8:
            continue

        logging.info('Received packet from {} '.format(address[0]))

        packet_num = struct.unpack('H', data[26:28])[0]

        # Проверка корректности данных, оповещение клиента в случае некорректности
        if not check_correct(data):
            logging.debug('Corrupted data in packet')
            print('Data corrupted')
            s.sendto(create_packet(0, packet_num, 'corrupted'.encode()), address)
            continue

        # Если нет такого IP-адреса в словаре, значит не было приема данных от этого клиента
        if address[0] not in connects.keys():

            # Пустой пакет клиент присылает последним сообщением, если при этом его не оказалось в текущих
            # коннектах, значит он отправлял этот пакет не один раз, выждав таймаут или получив некорректный ответ
            if len(data) == 28:
                s.sendto(create_packet(0, packet_num, b''), address)
                continue

            # Иначе создается новый файл под новое соединение, генерируется имя для этого файла
            # В about_file пишется информация о новом клиенте, чтобы в случае успешного сеанса записать в файл отчета
            file_name, crypt = (data[28:len(data)]).decode().split(' ')
            uniq_name = give_unique_name(file_name)
            about_file = '\nFile: {}\nSaved as: {}\nReceived from: {}\nTime: {}\n'.format(
                file_name, uniq_name, address[0], datetime.datetime.now()
            )
            logging.info('New client. Opening new file {} for acceptance'.format(uniq_name))
            connects[address[0]] = [open(uniq_name, 'wb'), 0, about_file, crypt]
            s.sendto(create_packet(0, packet_num, 'opened'.encode()), address)

        # Ловится всегда следующий пакет
        elif packet_num == connects[address[0]][1] + 1 or connects[address[0]][1] + 1 == 0xffff and packet_num == 0:

            # Пустой пакет от клиента означает завершение передачи. Связи обрываются, информация пишется в файл отчета.
            if len(data) == 28:
                logging.info('Received end of file. Closing file')
                s.sendto(create_packet(0, packet_num, b''), address)
                item = connects.pop(address[0])
                item[0].close()
                info.write(item[2])

            # Иначе просто обновляется счетчик пакетов, дописывается принимаемый файл
            else:
                logging.debug('Correct data in packet')
                connects[address[0]][1] = packet_num
                message = data[28:len(data)]
                if connects[address[0]][3] == 'true':
                    message = cipher.decrypt(message)
                connects[address[0]][0].write(message)
                s.sendto(create_packet(0, packet_num, 'correct'.encode()), address)

        # Клиент может прислать один и тот же пакет несколько раз, если до него не дошел или дошел некорректно
        # ответ сервера о получении пакета, в таком случае отправляется сообщение "again"
        elif packet_num == connects[address[0]][1]:
            logging.debug('again')
            s.sendto(create_packet(0, packet_num, 'again'.encode()), address)

conf = open('config.txt', 'r')
try:
    set_logger(conf.readline())
    listen(conf.readline())
except EOFError:
    logging.error('Wrong format of config file')
