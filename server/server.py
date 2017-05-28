import socket
import struct
import logging
import datetime
import os
import signal
from Crypto.Cipher import XOR

ECHO_REPLY = 0
ECHO_REQUEST = 8
PORT = 14900


def set_logger(log_file_name):
    """
    Установка нужных настроек логирования
    :param log_file_name: имя файла-лога
    :return: -
    """
    logging.basicConfig(format='%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG,
                        filename=log_file_name)


def handle_sigint(signal, frame):
    """
    Обработка SigInt (Crtl + C)
    """
    logging.info('Work was stopped')
    print('\nInterrupting. Server was stopped')
    exit(0)


def check_sum(inf_string):
    """
    Подсчет контрольной суммы для icmp пакета по алгоритму RFC1071
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
    packet_type, code, expected_sum, client_id, num = struct.unpack('bbHHH', packet[20:28])
    message = packet[28:len(packet)]
    header = struct.pack('bbHHH', packet_type, code, 0, client_id, num)
    real_sum = check_sum(str(header + message))
    return real_sum == expected_sum


def create_packet(server_id, num, message):
    """
    Создание icmp пакета
    :param server_id: идентификатор из заголовка пакета
    :param num: номер пакета
    :param message: поле данных пакета
    :return: полученный пакет
    """
    header = struct.pack('bbHHH', ECHO_REPLY, 0, 0, server_id, num)
    packet = header + message
    check = check_sum(str(packet))
    header = struct.pack('bbHHH', ECHO_REPLY, 0, check, server_id, num)
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
    s.bind(('', PORT))

    logging.info('Start working')

    cipher = XOR.new(key)

    # Открывается файл, в который будет вноситься вся информация о полученных файлах
    # connects - словарь вида
    # {адрес : (открытый файл, номер текущего пакета, информация о посылке, статус шифрования)}
    info = open('work_history.txt', 'a')
    connects = {}

    while True:
        data, address = s.recvfrom(192)

        # Сервер обрабатывает только запросы
        if struct.unpack('b', data[20:21])[0] != ECHO_REQUEST:
            continue

        address = (socket.gethostbyname(address[0]), PORT)

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
            crypt = int(crypt)
            uniq_name = give_unique_name(file_name)
            about_file = '\nFile: {}\nSaved as: {}\nReceived from: {}\nTime: {}\n'.format(
                file_name, uniq_name, address[0], datetime.datetime.now()
            )
            logging.info('New client. Opening new file {} for acceptance'.format(uniq_name))
            connects[address[0]] = [open(uniq_name, 'wb'), 0, about_file, crypt]

            # Даем права доступа другим пользователям к получаемому файлу
            os.chmod(uniq_name, 0o777)
            s.sendto(create_packet(0, packet_num, 'opened'.encode()), address)

        # Ловится всегда следующий пакет
        elif packet_num == connects[address[0]][1] + 1 or connects[address[0]][1] + 1 == 0xffff and packet_num == 0:

            # Пустой пакет от клиента означает завершение передачи. Связи обрываются, информация пишется в файл отчета.
            if len(data) == 28:
                logging.info('Received end of file. Closing file')
                s.sendto(create_packet(0, packet_num, b''), address)
                item = connects.pop(address[0])
                item[0].close()
                print('\nNew file received.\nInformation, that will be written in work_history.txt:{}'.
                      format(item[2]))
                info.write(item[2])

            # Иначе просто обновляется счетчик пакетов, дописывается принимаемый файл
            else:
                logging.debug('Correct data in packet')
                connects[address[0]][1] = packet_num
                message = data[28:len(data)]
                if connects[address[0]][3]:
                    message = cipher.decrypt(message)
                connects[address[0]][0].write(message)
                packet = create_packet(0, packet_num, 'correct'.encode())
                s.sendto(packet, address)

        # Клиент может прислать один и тот же пакет несколько раз, если до него не дошел или дошел некорректно
        # ответ сервера о получении пакета, в таком случае отправляется сообщение "again"
        elif packet_num == connects[address[0]][1]:
            logging.debug('again')
            s.sendto(create_packet(0, packet_num, 'again'.encode()), address)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_sigint)
    conf = open('config.txt', 'r')
    try:
        set_logger(conf.readline()[:-1])
        listen(conf.read(32))
    except EOFError:
        logging.error('Wrong format of config file')
