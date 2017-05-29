import struct
import socket
import logging
import sys
import os
import signal
from Crypto.Cipher import XOR


MAX_ITER = 20
PORT = 14900
ECHO_REQUEST = 8
ECHO_REPLY = 0
SIZE = 1000


def parse_input():
    """
    Парсер аргументов программы
    :return: кортеж (имя файла, адрес, статус шифрования)
    """
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


def set_logger(log_file_name):
    """
    Установка нужных настроек логирования
    :return: -
    :param log_file_name: имя лог-файла
    """
    logging.basicConfig(format='%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s] %(message)s',
                        level=logging.DEBUG,
                        filename=log_file_name)


def handle_sigint(signal, frame):
    """
    Обработка SigInt (Crtl + C)
    """
    logging.info('Work was stopped')
    print('\nInterrupting. Client was stopped')
    exit(0)


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


def create_packet(client_id, num, message):
    """
    Создание icmp пакета
    :param client_id: идентификатор из заголовка пакета
    :param num: номер пакета
    :param message: поле данных пакета
    :return: полученный пакет
    """
    header = struct.pack('bbHHH', ECHO_REQUEST, 0, 0, client_id, num)
    packet = header + message
    check = check_sum(str(packet))
    header = struct.pack('bbHHH', ECHO_REQUEST, 0, check, client_id, num)
    return header + message


def send_packet(sock, packet, expected_response, addr):
    """
    Отправка пакета по заданному адресу до получения заданого ответа или некоторого количества таймаутов
    :param sock: сокет
    :param packet: пакет
    :param expected_response: ожидаемый ответ при успешном получении
    :param addr: адрес
    :return: True при успешном отправлении, False, если сервер недоступен
    """
    code = 0
    addr = socket.gethostbyname(addr)
    # Подсчет таймаутов
    i = 0
    while True:
        try:
            if i == MAX_ITER:
                return False
            if code == 0:
                sock.sendto(packet, (addr, PORT))
                code = 1
            data, reply_addr = sock.recvfrom(1500)

            # Принимает только эхо-ответы от сервера, которому отправил пакет
            if struct.unpack('b', data[20:21])[0] != ECHO_REPLY or reply_addr[0] != addr:
                continue

            answer = (data[28:len(data)]).decode()

            # Если получен ожидаемый ответ, все прошло успешно. Если получен ответ "again", значит, сервер уже получил
            # пакет, но его оповещение об этом не дошло до данного клиента или дошло в некорректной форме, поэтому
            # было пропущенно.
            if answer == expected_response or answer == 'again':
                return True
            code = 0
        except socket.timeout:
            code = 0
            i += 1
            continue
        except UnicodeDecodeError:
            continue


def send_file(file_name, addr, crypt, key):
    """
    Основная функция клиента, отправка некоего файла на сервер
    :param file_name: имя отправляемого файла
    :param addr: адрес сервера
    :param crypt: статус шифрования
    :param key: ключ для XOR-шифрования
    :return: 
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(0.5)

    cipher = XOR.new(key)

    client_id = 1
    num = 0
    message = file_name.encode()

    if crypt:
        message += ' 1'.encode()
    else:
        message += ' 0'.encode()

    # Первый отправляемый пакет содержит имя файла и статус использования шифрования
    packet = create_packet(client_id, num, message)

    logging.info('Sending filename to server')

    if send_packet(s, packet, 'opened', addr):
        logging.info('Filename was sent to server')
    else:
        logging.error('Server is not available')
        print('Server is not available')
        return
    num += 1

    logging.info('Sending of file started')

    # Получение размера файла для отображения прогресса отправления
    file_size = os.path.getsize(file_name)

    f = open(file_name, 'rb')
    message = f.read(SIZE - 28)
    all_len = 0

    num_data_sent = 0

    # В цикле файл читается и отправляется пакетами, попутно выводится прогресс отправки файла
    while message:
        all_len += len(message)
        logging.debug('Sending packet {}'.format(num))
        if crypt:
            message = cipher.encrypt(message)
        packet = create_packet(client_id, num, message)

        if send_packet(s, packet, 'correct', addr):
            logging.debug('Packet {} was sent successful'.format(num))
        else:
            logging.error('Server is not available')
            print('Server is not available')
            return
        num_data_sent += len(message)
        message = f.read(SIZE)

        progress = num_data_sent / file_size * 100
        print('Sending progress: ' + "%.2f" % progress + '%')

        # Так как поле номера пакета 16-битное, а приложение может взаимодействовать с файлами, размер которых
        # превышает 10ГБ, номер пакета обнуляется, когда доходит до максимально-возможного 16-битного числа
        if num + 1 < 0xffff:
            num += 1
        else:
            num = 0

    # В конце отправляется пустой пакет, сигнализирующий о завершении передачи
    logging.debug('Sending last packet')

    packet = create_packet(client_id, num, b'')
    if send_packet(s, packet, '', addr):
        logging.info('File was sent to server successfully')
    else:
        logging.error('Server is not available')
        print('Server is not available')
        return


if __name__ == '__main__':
    signal.signal(signal.SIGINT, handle_sigint)
    conf = open('config.txt', 'r')
    try:
        set_logger(conf.readline()[:-1])
        filename, address, crypt_status = parse_input()
        send_file(filename, address, crypt_status, conf.read(32))
    except EOFError:
        logging.error('Wrong format of config file')
